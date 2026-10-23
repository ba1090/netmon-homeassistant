"""Ping senza processi esterni: pacchetti ICMP inviati direttamente dal programma.

Su un Raspberry Pi Zero avviare il comando `ping` per ogni dispositivo costa più di tutto il
resto della sonda. Qui un solo thread invia i pacchetti a tutti i dispositivi, distanziati di
pochi centesimi di secondo, e raccoglie le risposte da un unico socket.

Socket usati, nell'ordine:
- ICMP "datagramma" (nessun privilegio, se net.ipv4.ping_group_range lo consente);
- ICMP "raw" (serve CAP_NET_RAW: il servizio netmon-probe lo concede solo a questo scopo).
Se nessuno dei due è disponibile, ping_many() restituisce None e la sonda usa il comando ping.
"""
__version__ = "1.1.20261023-210326"
import ipaddress
import os
import socket
import struct
import time
import select

ECHO4, REPLY4 = 8, 0
ECHO6, REPLY6 = 128, 129
SO_TIMESTAMPNS = getattr(socket, "SO_TIMESTAMPNS", 35)   # ora di arrivo misurata dal kernel
PACKET_GAP = 1.0            # secondi tra due pacchetti allo stesso dispositivo (come ping)
DNS_TTL, DNS_FAIL_TTL = 300, 60

_dns = {}                   # host -> (scadenza, famiglia, indirizzo di destinazione)
_kind = {}                  # famiglia -> SOCK_DGRAM / SOCK_RAW / None (non disponibile)
_seq = [0]


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _open(family):
    """Socket ICMP per la famiglia (IPv4/IPv6), oppure None. Il tipo che funziona viene ricordato."""
    proto = socket.IPPROTO_ICMP if family == socket.AF_INET else socket.IPPROTO_ICMPV6
    kinds = [_kind[family]] if family in _kind else [socket.SOCK_DGRAM, socket.SOCK_RAW]
    for kind in kinds:
        if kind is None:
            return None, None
        try:
            s = socket.socket(family, kind, proto)
        except OSError:
            continue
        s.setblocking(False)
        try:
            s.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
        except OSError:
            pass
        _kind[family] = kind
        return s, kind
    _kind[family] = None
    return None, None


def available() -> bool:
    s, _ = _open(socket.AF_INET)
    if s is None:
        return False
    s.close()
    return True


def mode() -> str:
    k = _kind.get(socket.AF_INET)
    return {socket.SOCK_DGRAM: "icmp", socket.SOCK_RAW: "icmp-raw"}.get(k, "comando ping")


def _resolve(host, now):
    """(famiglia, sockaddr) con cache; None se il nome non si risolve."""
    hit = _dns.get(host)
    if hit and hit[0] > now:
        return hit[1]
    result = None
    try:
        ip = ipaddress.ip_address(host.split("%")[0])
        if ip.version == 4:
            result = (socket.AF_INET, (host, 0))
    except ValueError:
        pass
    if result is None:
        try:
            infos = socket.getaddrinfo(host, None, 0, socket.SOCK_DGRAM)
            infos.sort(key=lambda i: i[0] != socket.AF_INET)          # IPv4 per primo
            fam, _, _, _, addr = infos[0]
            result = (fam, addr)
        except (OSError, IndexError):
            result = None
    _dns[host] = (now + (DNS_TTL if result else DNS_FAIL_TTL), result)
    return result


def _arrival_ns(ancdata):
    for level, typ, data in ancdata:
        if level == socket.SOL_SOCKET and typ == SO_TIMESTAMPNS:
            if len(data) >= 16:
                sec, nsec = struct.unpack("qq", data[:16])
            elif len(data) >= 8:
                sec, nsec = struct.unpack("ii", data[:8])          # sistemi a 32 bit
            else:
                continue
            return sec * 1_000_000_000 + nsec
    return time.time_ns()


def ping_many(targets, count=2, timeout=1.0, gap=0.1):
    """Pinga tutti i dispositivi. targets: lista di (nome, host) nell'ordine di partenza.
    Restituisce {nome: (risponde, rtt medio ms o None)} oppure None se i socket ICMP non si
    possono usare. Basta una risposta su `count` perché il dispositivo risulti raggiungibile."""
    now = time.monotonic()
    count, timeout = max(1, int(count)), max(0.2, float(timeout))
    socks, results, plan = {}, {}, []
    for i, (name, host) in enumerate(targets):
        results[name] = []
        dest = _resolve(str(host), now)
        if dest is None:
            continue
        fam, addr = dest
        if fam not in socks:
            s, kind = _open(fam)
            if s is None:
                if fam == socket.AF_INET:
                    for sk, _ in socks.values():
                        sk.close()
                    return None                      # niente ICMP: userà il comando ping
                continue
            socks[fam] = (s, kind)
        for k in range(count):
            plan.append((now + i * gap + k * PACKET_GAP, name, fam, addr))
    if not plan:
        return {n: (False, None) for n in results}

    plan.sort(key=lambda x: x[0])
    cookie = os.urandom(4)                           # scarta risposte tardive di cicli precedenti
    ident = (os.getpid() ^ int.from_bytes(os.urandom(2), "big")) & 0xFFFF
    sent = {}                                        # seq -> (nome, inviato ns, famiglia)
    deadline = plan[-1][0] + timeout
    fd_map = {s.fileno(): (fam, s, kind) for fam, (s, kind) in socks.items()}
    idx = 0
    try:
        while True:
            mono = time.monotonic()
            while idx < len(plan) and plan[idx][0] <= mono:
                _, name, fam, addr = plan[idx]
                idx += 1
                _seq[0] = (_seq[0] + 1) & 0xFFFF
                seq = _seq[0]
                typ = ECHO4 if fam == socket.AF_INET else ECHO6
                payload = cookie + struct.pack("!I", seq) + b"netmon.."
                header = struct.pack("!BBHHH", typ, 0, 0, ident, seq)
                csum = _checksum(header + payload) if fam == socket.AF_INET else 0   # IPv6: la calcola il kernel
                packet = struct.pack("!BBHHH", typ, 0, csum, ident, seq) + payload
                s = socks[fam][0]
                t0 = time.time_ns()              # prima dell'invio: su loopback la risposta arriva subito
                try:
                    s.sendto(packet, addr)
                    sent[seq] = (name, t0, fam)
                except OSError:
                    pass                             # rete irraggiungibile: conta come perso
            if idx >= len(plan) and time.monotonic() >= deadline:
                break
            wait = (plan[idx][0] if idx < len(plan) else deadline) - time.monotonic()
            ready, _, _ = select.select(list(fd_map), [], [], max(0.0, wait))
            for fd in ready:
                fam, s, kind = fd_map[fd]
                while True:
                    try:
                        data, anc, _, src = s.recvmsg(1500, 256)
                    except (BlockingIOError, InterruptedError):
                        break
                    except OSError:
                        break
                    arrived = _arrival_ns(anc)
                    if fam == socket.AF_INET and kind == socket.SOCK_RAW:
                        data = data[(data[0] & 0x0F) * 4:]          # salta l'intestazione IP
                    if len(data) < 16:
                        continue
                    typ, _, _, rid, rseq = struct.unpack("!BBHHH", data[:8])
                    if typ != (REPLY4 if fam == socket.AF_INET else REPLY6) or data[8:12] != cookie:
                        continue
                    if kind == socket.SOCK_RAW and rid != ident:
                        continue                                    # risposta a un altro programma
                    hit = sent.pop(rseq, None)
                    if hit is None:
                        continue
                    name, t0, _ = hit
                    rtt = max(0.0, (arrived - t0) / 1e6)
                    if rtt <= timeout * 1000:
                        results[name].append(rtt)
    finally:
        for s, _ in socks.values():
            s.close()
    return {n: (bool(r), round(sum(r) / len(r), 2) if r else None) for n, r in results.items()}
