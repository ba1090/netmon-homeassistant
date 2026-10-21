#!/usr/bin/env python3
"""Sonda di rete (per esempio un Raspberry Pi): pinga i dispositivi locali e invia i risultati al server.

Pensata per consumare poco anche su un Raspberry Pi Zero: ping senza processi esterni (pinger.py),
un client HTTP minimo con connessione persistente, una sola connessione al FRITZ!Box condivisa e
con cache, buffer letto e scritto a pezzi.

Dipendenze (Debian, Raspberry Pi OS e simili): sudo apt install python3-yaml
(fritzconnection, facoltativa, solo per il FRITZ!Box)
"""
__version__ = "1.1.20261021-140329"
import http.client
import fcntl
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import termios
import threading
import time
from collections import deque
from urllib.parse import urlencode, urlsplit

import yaml

import pinger
import sysops

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("probe")

CONFIG_PATH = os.getenv("PROBE_CONFIG", "/etc/netprobe/config.yaml")
# Misure raccolte mentre il server non risponde: inviate appena torna raggiungibile
BUFFER_PATH = os.getenv("PROBE_BUFFER", "/var/lib/netprobe/buffer.jsonl")
BUFFER_MAX = int(os.getenv("PROBE_BUFFER_MAX", "5000"))   # report conservati al massimo
BUFFER_BATCH = 200                                        # report per invio
MAX_RESPONSE = 4 * 1024 * 1024                            # risposte del server lette al massimo fino a qui


class HttpError(OSError):
    """Risposta di errore del server o problema di connessione."""


class ProbeMoved(HttpError):
    """Il server dice che la sonda ora appartiene a un'altra VM (utente spostato): nuovo indirizzo."""
    def __init__(self, url):
        super().__init__(f"sonda spostata su {url}")
        self.url = url


class Http:
    """Client HTTP(S) minimo con connessione persistente (keep-alive): una sola connessione TLS
    riutilizzata per report, configurazione e buffer. Molto più leggero della libreria requests."""

    def __init__(self):
        self._conn, self._key, self._ctx = None, None, None

    def close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
        self._conn = None

    def _connection(self, scheme, host, port, timeout):
        key = (scheme, host, port)
        if self._conn is None or self._key != key:
            self.close()
            if scheme == "https":
                if self._ctx is None:
                    self._ctx = ssl.create_default_context()
                self._conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=self._ctx)
            else:
                self._conn = http.client.HTTPConnection(host, port, timeout=timeout)
            self._key = key
        self._conn.timeout = timeout
        if self._conn.sock is not None:
            self._conn.sock.settimeout(timeout)
        return self._conn

    def request(self, method, url, token=None, body=None, params=None, timeout=15):
        u = urlsplit(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise HttpError(f"indirizzo non valido: {url}")
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        if params:
            path += ("&" if "?" in path else "?") + urlencode(params)
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {"Accept": "application/json", "User-Agent": "netmon-probe"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        for attempt in (1, 2):
            conn = self._connection(u.scheme, u.hostname, u.port, timeout)
            reused = conn.sock is not None
            try:
                conn.request(method, path, body=data, headers=headers)
                resp = conn.getresponse()
                raw = resp.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    self.close()
                    raise HttpError("risposta del server troppo grande")
            except (http.client.RemoteDisconnected, BrokenPipeError, ConnectionResetError) as exc:
                self.close()
                if reused and attempt == 1:
                    continue                     # il server aveva chiuso la connessione inattiva
                raise HttpError(str(exc) or type(exc).__name__) from exc
            except (OSError, http.client.HTTPException) as exc:
                self.close()
                raise HttpError(str(exc) or type(exc).__name__) from exc
            if resp.will_close:
                self.close()
            if resp.status == 410:
                try:
                    moved = (json.loads(raw) or {}).get("moved")
                except (ValueError, AttributeError):
                    moved = None
                if isinstance(moved, str):
                    raise ProbeMoved(moved)
            if resp.status >= 400:
                raise HttpError(f"{resp.status} {resp.reason}: {raw[:200].decode(errors='replace')}")
            return json.loads(raw or b"null")
        raise HttpError("nessuna risposta")


def load_config():
    with open(CONFIG_PATH, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    cfg.setdefault("interval", 60)
    cfg.setdefault("ping_count", 2)
    cfg.setdefault("ping_timeout", 1)
    cfg.setdefault("fail_threshold", 3)
    cfg.setdefault("alert_mode", "proporzionale")
    cfg.setdefault("stale_factor", 1.5)
    cfg.setdefault("offline_factor", 3)
    cfg.setdefault("stale_seconds", 90)
    cfg.setdefault("offline_seconds", 180)
    cfg.setdefault("config_rev", 0)
    cfg.setdefault("config_poll", 60)   # ogni quanto chiedere al server se ci sono modifiche
    cfg.setdefault("fritz_enabled", False)
    cfg.setdefault("fritz_host", "")
    cfg.setdefault("fritz_user", "")
    cfg.setdefault("fritz_password", "")
    cfg.setdefault("fritz_more", [])         # altri FRITZ!Box (ripetitori, altri posti): vedi fritz_boxes()
    cfg.setdefault("fritz_max", 4)           # quanti oltre al primo (lo decide l'amministratore)
    cfg.setdefault("devices_max", 30)        # dispositivi controllabili (lo decide l'amministratore)
    cfg.setdefault("traffic_interval", 30)
    cfg.setdefault("ping_parallel", 2)       # ping contemporanei (1 = uno alla volta)   # secondi tra due campioni di traffico (0 = disattivato)
    if not cfg.get("devices"):
        raise ValueError("nessun dispositivo in config.yaml")
    return cfg


# Campi gestibili anche dalla pagina del server (server_url, token e probe_name restano locali)
SHARED = ("devices", "interval", "ping_count", "ping_timeout", "fail_threshold",
          "alert_mode", "stale_factor", "offline_factor", "stale_seconds", "offline_seconds",
          "traffic_interval", "ping_parallel", "probe_name", "fritz_max", "devices_max")


def shared_config(cfg):
    return {k: cfg[k] for k in SHARED}


def valid_host(h):
    try:
        ipaddress.ip_address(str(h))
        return "%" not in str(h)             # niente zona IPv6 (fe80::1%eth0): testo libero
    except ValueError:
        return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$", str(h)))


NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,39}$")
MAX_DEVICES = 200
# Valori della configurazione che può cambiare il server: tipo e limiti (gli stessi della pagina
# locale e del server). Un valore fuori limite o del tipo sbagliato non viene applicato.
REMOTE_LIMITS = {"interval": (int, 10, 3600), "ping_count": (int, 1, 10), "ping_timeout": (int, 1, 10),
                 "fail_threshold": (int, 1, 20), "stale_factor": (float, 1, 20),
                 "offline_factor": (float, 1, 20), "stale_seconds": (int, 10, 86400),
                 "offline_seconds": (int, 10, 86400), "ping_parallel": (int, 1, 16),
                 "fritz_max": (int, 0, 8), "devices_max": (int, 1, MAX_DEVICES)}


def clean_remote(cfg, new):
    """Configurazione arrivata dal server, controllata campo per campo. Un campo non valido
    mantiene il valore attuale; dispositivi non validi = configurazione rifiutata."""
    devices = new.get("devices")
    if not isinstance(devices, dict) or not devices or len(devices) > MAX_DEVICES:
        raise ValueError("configurazione remota non valida (dispositivi)")
    for name, host in devices.items():
        if not isinstance(name, str) or not NAME_RE.match(name) or not isinstance(host, str) or not valid_host(host):
            raise ValueError("configurazione remota non valida (dispositivi)")
    out = {"devices": dict(devices)}
    for k, (cast, lo, hi) in REMOTE_LIMITS.items():
        if k not in new:
            continue
        v = new[k]
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
            log.warning("Configurazione dal server: valore non valido per %s, mantengo %s", k, cfg.get(k))
            continue
        out[k] = cast(v)
    t = new.get("traffic_interval")
    if isinstance(t, int) and not isinstance(t, bool) and (t == 0 or 2 <= t <= 300):
        out["traffic_interval"] = t
    if new.get("alert_mode") in ("proporzionale", "fisso"):
        out["alert_mode"] = new["alert_mode"]
    if isinstance(new.get("probe_name"), str) and NAME_RE.match(new["probe_name"]):
        out["probe_name"] = new["probe_name"]
    return out


def apply_remote_config(cfg, new, rev):
    """Applica la configurazione arrivata dal server e la scrive su config.yaml."""
    if not isinstance(new, dict):
        raise ValueError("configurazione remota non valida")
    new = clean_remote(cfg, new)
    merged = {**cfg, **{k: new[k] for k in SHARED if k in new}, "config_rev": int(rev)}
    text = ("# Aggiornato dalla pagina del server\n"
            + yaml.safe_dump(merged, allow_unicode=True, sort_keys=False))
    folder = os.path.dirname(CONFIG_PATH) or "."
    tmp = os.path.join(folder, ".config-remote.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, 0o640)
    os.replace(tmp, CONFIG_PATH)
    return merged


_buffered = [None]          # report nel buffer, contati una volta sola e poi tenuti in memoria


def buffer_count():
    """Numero di report in attesa (il file si legge solo la prima volta)."""
    if _buffered[0] is None:
        try:
            with open(BUFFER_PATH, "rb") as f:
                _buffered[0] = sum(1 for _ in f)
        except FileNotFoundError:
            _buffered[0] = 0
    return _buffered[0]


def buffer_trim():
    """Tiene solo gli ultimi BUFFER_MAX report (righe grezze, senza decodificarle)."""
    with open(BUFFER_PATH, encoding="utf-8") as f:
        last = deque(f, maxlen=BUFFER_MAX)
    tmp = BUFFER_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.writelines(last)
    os.replace(tmp, BUFFER_PATH)
    _buffered[0] = len(last)


def buffer_append(record):
    """Aggiunge una riga in fondo al file: nessuna riscrittura a ogni ciclo."""
    count = buffer_count()
    os.makedirs(os.path.dirname(BUFFER_PATH) or ".", exist_ok=True)
    with open(BUFFER_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")
    _buffered[0] = count + 1
    # Taglio solo quando si supera il limite del 10%: una riscrittura ogni ~500 cicli
    if _buffered[0] > BUFFER_MAX * 1.1:
        buffer_trim()
        log.warning("Buffer pieno: conservati gli ultimi %d report, i più vecchi sono stati scartati",
                    BUFFER_MAX)
    log.warning("Misure messe da parte: %d in attesa di invio", _buffered[0])


def backfill_url(cfg):
    return cfg["server_url"].rsplit("/api/report", 1)[0] + "/api/backfill"


def flush_buffer(client, cfg):
    """Invia le misure in attesa a blocchi, leggendo il file un blocco alla volta (poca memoria
    anche con migliaia di report). Il file viene eliminato solo a invio completato; se l'invio
    si interrompe restano solo i report non ancora accettati dal server."""
    if not buffer_count() or not os.path.exists(BUFFER_PATH):
        _buffered[0] = 0
        return
    log.info("Invio al server %d misure bufferizzate", _buffered[0])
    done_at, sent = 0, 0
    try:
        with open(BUFFER_PATH, encoding="utf-8") as f:
            while True:
                batch, lines = [], 0
                while True:
                    line = f.readline()
                    if not line:
                        break
                    lines += 1
                    try:
                        batch.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass                               # riga danneggiata: la salto
                    if lines >= BUFFER_BATCH:
                        break
                if not lines:
                    break
                if batch:
                    client.request("POST", backfill_url(cfg), cfg["token"],
                                   {"probe": cfg["probe_name"], "reports": batch}, timeout=30)
                done_at, sent = f.tell(), sent + lines
    finally:
        if sent and sent >= _buffered[0]:
            os.remove(BUFFER_PATH)
            _buffered[0] = 0
            log.info("Buffer svuotato")
        elif sent:
            tmp = BUFFER_PATH + ".tmp"
            with open(BUFFER_PATH, encoding="utf-8") as src, open(tmp, "w", encoding="utf-8") as dst:
                src.seek(done_at)
                shutil.copyfileobj(src, dst)
            os.replace(tmp, BUFFER_PATH)
            _buffered[0] -= sent


# Suffissi dei nomi locali (come nella pagina locale, config_web.LOCAL_SUFFIXES)
LOCAL_SUFFIXES = (".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain", ".fritz.box")


def is_local_host(host):
    """Indirizzo della rete locale (IP privato, localhost o nome locale)."""
    host = (host or "").strip("[]").lower()
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return host == "localhost" or host.endswith(LOCAL_SUFFIXES)


def follow_move(cfg, url):
    """Scrive in config.yaml il nuovo indirizzo del server (utente spostato su un'altra VM). Il token
    resta lo stesso; la configurazione si ricarica al giro successivo. Solo un indirizzo dei report
    diverso da quello attuale, con la stessa regola della pagina locale: https:// sempre, http://
    solo verso la rete locale (altrimenti il token viaggerebbe in chiaro su Internet)."""
    u = urlsplit(url)
    if (u.scheme not in ("http", "https") or not u.hostname or not u.path.endswith("/api/report") or u.query
            or (u.scheme == "http" and not is_local_host(u.hostname))):
        log.error("Indirizzo di spostamento non valido ricevuto dal server: %r", url[:200])
        return
    if url == cfg.get("server_url"):
        return
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        data["server_url"] = url
        folder = os.path.dirname(CONFIG_PATH) or "."
        tmp = os.path.join(folder, ".config-move.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("# Indirizzo del server cambiato dal server (account spostato su un'altra VM)\n"
                    + yaml.safe_dump(data, allow_unicode=True, sort_keys=False))
        os.chmod(tmp, 0o640)
        os.replace(tmp, CONFIG_PATH)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        log.error("Nuovo indirizzo del server (%s) non salvato: %s", url, exc)
        return
    log.warning("Il server ha spostato questa sonda: ora scrive a %s", url)


def config_url(cfg):
    return cfg["server_url"].rsplit("/api/report", 1)[0] + "/api/probe-config"


# ---------------------------------------------------------------- comandi dal server
# Riavvio e aggiornamento richiesti dalla pagina di stato. Lo stato del comando è salvato su disco
# prima di eseguirlo: dopo un riavvio la sonda riconosce il comando e non lo ripete.
COMMAND_FILE = os.path.join(sysops.STATE_DIR, "command.json")


def load_command():
    try:
        with open(COMMAND_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save_command(cmd):
    os.makedirs(os.path.dirname(COMMAND_FILE), exist_ok=True)
    tmp = COMMAND_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cmd, f)
    os.replace(tmp, COMMAND_FILE)


REBOOT_GAP = 600      # secondi minimi tra due riavvii chiesti dal server


def handle_command(requested, cfg=None):
    """Esegue un comando arrivato dal server, una sola volta per identificativo."""
    if not isinstance(requested, dict) or requested.get("cmd") not in ("reboot", "upgrade", "update", "wifi"):
        return
    current = load_command()
    if current and current.get("id") == requested.get("id"):
        return                                         # già eseguito (o in corso)
    if (requested["cmd"] == "reboot" and current and current.get("cmd") == "reboot"
            and time.time() - float(current.get("started") or 0) < REBOOT_GAP):
        log.warning("Riavvio dal server ignorato: l'ultimo è di meno di %d minuti fa", REBOOT_GAP // 60)
        return
    cmd = {"id": str(requested.get("id"))[:40], "cmd": requested["cmd"], "state": "running",
           "started": time.time(), "output": "", "acked": False}
    if requested["cmd"] == "reboot":
        ok, message = sysops.reboot(delay=3)
        cmd.update(state="done" if ok else "error", output=message, finished=time.time())
        save_command(cmd)                              # salvato PRIMA che il sistema si riavvii
        log.warning("Comando dal server: riavvio · %s", message)
    elif requested["cmd"] == "wifi":
        # rete Wi-Fi: la password va solo allo script di root, non in command.json né nel registro
        w = requested.get("wifi") if isinstance(requested.get("wifi"), dict) else {}
        cmd.update(action=str(w.get("action") or "")[:10], ssid=str(w.get("ssid") or "")[:64])
        save_command(cmd)
        host, port = server_endpoint(cfg.get("server_url", "") if cfg else "")
        ok, message = sysops.start_wifi({"action": w.get("action"), "ssid": w.get("ssid"), "psk": w.get("psk") or "",
                                         "hidden": bool(w.get("hidden")), "server_host": host, "server_port": port})
        if not ok:
            cmd.update(state="error", output=message, finished=time.time())
        save_command(cmd)
        log.warning("Comando dal server: rete Wi-Fi (%s) · %s", cmd["action"], message)
    elif requested["cmd"] == "update":
        cmd["mode"] = "zip" if sysops.can_zipupdate() and os.path.exists(sysops.UPDATE_KEY) else "py"
        save_command(cmd)                              # salvato PRIMA che la sonda si riavvii
        if cfg is None:
            ok, message = False, "configurazione non disponibile"
        else:
            ok, message, cmd["mode"] = sysops.update_from_server(cfg.get("server_url", ""), cfg.get("token", ""))
        cmd["output"] = message
        if not ok:
            cmd.update(state="error", finished=time.time())
        elif cmd["mode"] == "same":                    # già alla versione del server: fatto, senza riavvio
            cmd.update(state="done", finished=time.time(), version=NETMON_VERSION)
        save_command(cmd)
        log.warning("Comando dal server: aggiornamento di netmon · %s", message)
    else:
        ok, message = sysops.start_upgrade()
        if not ok:
            cmd.update(state="error", output=message, finished=time.time())
        save_command(cmd)
        log.warning("Comando dal server: aggiornamento · %s", message)


def command_status():
    """Esito del comando da comunicare al server, finché il server non l'ha confermato."""
    cmd = load_command()
    if not cmd or cmd.get("acked"):
        return None
    if cmd["cmd"] == "wifi" and cmd.get("state") == "running":
        st = sysops.wifi_status()
        fresh = (st.get("started") or 0) >= cmd["started"] - 5
        if fresh and st.get("state") in ("ok", "error"):
            cmd.update(state="done" if st["state"] == "ok" else "error",
                       finished=st.get("finished") or time.time(), output=st.get("message") or "")
            _wifi_cache.clear()                        # elenco delle reti cambiato: rileggerlo subito
        elif not fresh and time.time() - cmd["started"] > 120:
            cmd.update(state="error", finished=time.time(), output="L'operazione non è partita.")
        save_command(cmd)
    if cmd["cmd"] in ("upgrade", "update") and cmd.get("state") == "running":
        is_update = cmd["cmd"] == "update"
        is_zip = is_update and cmd.get("mode") == "zip"         # aggiornamento completo (pacchetto)
        st = (sysops.zipupdate_status() if is_zip else sysops.selfupdate_status() if is_update
              else sysops.upgrade_status())
        # Conta solo un esito dell'aggiornamento partito con QUESTO comando, non di uno precedente
        fresh = (st.get("started") or 0) >= cmd["started"] - 5
        if fresh and st.get("state") in ("ok", "error"):
            cmd.update(state="done" if st["state"] == "ok" else "error",
                       finished=st.get("finished") or time.time(),
                       reboot_required=st.get("reboot_required", False))
            if is_update:
                cmd["version"] = st.get("version") or NETMON_VERSION
        elif not fresh and time.time() - cmd["started"] > 180:
            cmd.update(state="error", finished=time.time(), output="L'aggiornamento non è partito.")
        if fresh:
            cmd["output"] = (sysops.zipupdate_log if is_zip else sysops.selfupdate_log if is_update
                             else sysops.upgrade_log)(3000)
        save_command(cmd)
    return {k: cmd.get(k) for k in ("id", "cmd", "state", "started", "finished", "output", "reboot_required", "version")}


def command_acked(ack_id):
    cmd = load_command()
    if cmd and ack_id and cmd.get("id") == ack_id and cmd.get("state") != "running":
        cmd["acked"] = True
        save_command(cmd)


def poll_config(client, cfg):
    """Chiede al server se ha una configurazione più recente e la applica."""
    reply = client.request("GET", config_url(cfg), cfg["token"], timeout=10,
                           params={"probe": cfg["probe_name"], "rev": int(cfg["config_rev"])}) or {}
    handle_command(reply.get("command"), cfg)
    speedtest_requested(reply.get("speedtest"))
    scan_requested(reply.get("scan"))
    server_rev = int(reply.get("config_rev") or 0)
    if reply.get("config") and server_rev > int(cfg["config_rev"]):
        cfg = apply_remote_config(cfg, reply["config"], server_rev)
        log.info("Configurazione aggiornata dal server (rev %d): %d dispositivi, ogni %ss",
                 server_rev, len(cfg["devices"]), cfg["interval"])
        return cfg, True
    return cfg, False


# ---------------------------------------------------------------- FRITZ!Box (TR-064)
# Credenziali solo locali: non vengono mai inviate al server, solo il riepilogo.
# Una sola connessione, condivisa tra riepilogo e traffico (la creazione legge e analizza le
# descrizioni dei servizi: sul Raspberry Pi Zero è l'operazione più pesante, e con la cache su
# disco si fa una volta sola). I dati che cambiano di rado si rileggono ogni 10 minuti.
SLOW_EVERY = 600
GUEST_EVERY = 300         # elenco ospiti: riletto se cambia il numero di client, altrimenti ogni 5 minuti
SUMMARY_BUDGET = 15       # secondi: oltre, le parti facoltative del riepilogo usano gli ultimi valori letti
REBUILD_AFTER = 3         # errori di rete di fila prima di ricreare la connessione da capo
TRUE = ("1", "true", "True", True, 1)


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:  # noqa: BLE001 — un singolo dato mancante non deve bloccare il resto
        return default


def _soft(fn, default=None):
    """Come _safe, ma un errore di rete (timeout, router irraggiungibile) interrompe il riepilogo:
    inutile aspettare il timeout di ogni chiamata successiva. Gli errori di requests sono OSError."""
    try:
        return fn()
    except OSError:
        raise
    except Exception:  # noqa: BLE001 — azione non supportata da questo FRITZ!OS
        return default


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# --- rete mesh: mappa del FRITZ!Box principale (Hosts1 → X_AVM-DE_GetMeshListPath, un JSON)
MESH_EVERY = 300          # secondi tra due letture della mappa mesh e dello stato della fibra
MESH_NODES = 10           # nodi della mesh (FRITZ!Box e repeater) inviati al server
MESH_CLIENTS = 60         # dispositivi per nodo
WEAK_DBM = -75            # segnale Wi-Fi debole (dBm)
WEAK_KBIT = 30_000        # senza misura del segnale: velocità del collegamento sotto i 30 Mbit/s


def _band(iface):
    """Banda di un'interfaccia della mappa mesh: dal nome (AP:2G:0, AP:5G:1, AP:6G:0…) o dal canale."""
    if str(iface.get("type", "")).upper() == "LAN":
        return "cavo"
    name = str(iface.get("name", "")).upper()
    for tag, band in (("2G", "2,4 GHz"), ("2.4", "2,4 GHz"), ("5G", "5 GHz"), ("6G", "6 GHz")):
        if tag in name:
            return band
    ch = _int(iface.get("current_channel")) or 0
    return "2,4 GHz" if 0 < ch <= 14 else "5 GHz" if ch else "Wi-Fi"


def _dbm(link):
    """Segnale del collegamento in dBm, dall'RCPI di 802.11k (0–220; 255 = non misurato)."""
    for k in ("rx_rcpi", "tx_rcpi"):
        v = _int(link.get(k))
        if v is not None and 0 < v <= 220:
            return round(v / 2 - 110)
    return None


def parse_mesh(topo):
    """Riassunto della mappa mesh del FRITZ!Box: i nodi (FRITZ!Box principale e repeater) con il
    collegamento verso il nodo da cui dipendono e i dispositivi agganciati a ciascuno.
    Velocità in kbit/s (come nel FRITZ!OS), segnale in dBm se il FRITZ lo misura.
    Ogni campo è facoltativo: un FRITZ!OS diverso non deve far fallire il resto."""
    nodes = {n.get("uid"): n for n in (topo or {}).get("nodes") or [] if isinstance(n, dict) and n.get("uid")}
    iface_of = {}                                         # uid interfaccia -> (uid nodo, interfaccia)
    for uid, n in nodes.items():
        for i in n.get("node_interfaces") or []:
            if isinstance(i, dict) and i.get("uid"):
                iface_of[i["uid"]] = (uid, i)
    links, seen = [], set()
    for uid, n in nodes.items():
        for i in n.get("node_interfaces") or []:
            for l in (i.get("node_links") or []) if isinstance(i, dict) else []:
                if not isinstance(l, dict):
                    continue
                lid = l.get("uid") or (l.get("node_interface_1_uid"), l.get("node_interface_2_uid"))
                if lid in seen or str(l.get("state", "CONNECTED")).upper() != "CONNECTED":
                    continue
                seen.add(lid)
                a, b = iface_of.get(l.get("node_interface_1_uid")), iface_of.get(l.get("node_interface_2_uid"))
                if a and b and a[0] != b[0]:
                    links.append((a, b, l))
    meshed = {uid for uid, n in nodes.items()
              if n.get("is_meshed") in TRUE or str(n.get("mesh_role", "")).lower() in ("master", "slave")}
    master = next((uid for uid in meshed if str(nodes[uid].get("mesh_role", "")).lower() == "master"), None)
    if master is None:
        return None

    def rate(l, key):
        vals = [_int(l.get(f"{key}_rx")), _int(l.get(f"{key}_tx"))]
        vals = [v for v in vals if v is not None and v >= 0]
        return max(vals) if vals else None

    # albero della mesh: dal principale, ogni repeater sotto il nodo da cui riceve il collegamento
    parent, uplink, todo = {master: None}, {}, [master]
    while todo:
        cur = todo.pop(0)
        for a, b, l in links:
            for me, other in ((a, b), (b, a)):
                if me[0] == cur and other[0] in meshed and other[0] not in parent:
                    parent[other[0]] = cur
                    uplink[other[0]] = {"type": _band(me[1]) if me[1].get("type") != "LAN" else _band(other[1]),
                                        "rate": rate(l, "cur_data_rate"), "max": rate(l, "max_data_rate"),
                                        "signal": _dbm(l)}
                    todo.append(other[0])
    clients = {uid: [] for uid in parent}
    for uid, n in nodes.items():
        if uid in meshed:
            continue
        best = None
        for a, b, l in links:
            for me, other in ((a, b), (b, a)):
                if me[0] == uid and other[0] in parent:
                    wifi = str(l.get("type", "")).upper() == "WLAN" or other[1].get("type") == "WLAN"
                    if best is None or (wifi and not best[3]):
                        best = (other[0], other[1], l, wifi)
        if best is None:
            continue
        node_uid, iface, l, wifi = best
        band = _band(iface) if wifi else "cavo"
        sig, cur = _dbm(l), rate(l, "cur_data_rate")
        clients[node_uid].append({
            "name": str(n.get("device_name") or n.get("device_mac_address") or "?")[:40],
            "band": band, "rate": cur, "signal": sig,
            "weak": bool(wifi and ((sig is not None and sig <= WEAK_DBM)
                                   or (sig is None and cur is not None and 0 < cur < WEAK_KBIT)))})
    order = [master] + [u for u in parent if u != master]
    out = []
    for uid in order[:MESH_NODES]:
        n = nodes[uid]
        cl = sorted(clients[uid], key=lambda c: (c["band"] != "cavo", c["name"].lower()))
        out.append({"name": str(n.get("device_name") or "FRITZ!")[:40], "model": str(n.get("device_model") or "")[:40],
                    "master": uid == master, "up": uplink.get(uid),
                    "parent": str(nodes[parent[uid]].get("device_name") or "")[:40] if parent.get(uid) else "",
                    "clients": cl[:MESH_CLIENTS], "more": max(0, len(cl) - MESH_CLIENTS)})
    return {"nodes": out, "clients": sum(len(clients[u]) for u in parent)}


def fiber_active(values):
    """La linea in fibra è in uso? Un FRITZ!Box in fibra collegato a Internet in altro modo (cavo,
    DSL, LTE) risponde lo stesso, ma con tutti i valori a 0 o «Unknown»: in quel caso non si invia."""
    for v in (values or {}).values():
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)) and v != 0:
            return True
        if isinstance(v, str) and v.strip().lower() not in ("", "0", "unknown", "none", "n/a", "-", "disabled"):
            return True
    return False


def fiber_key(k):
    """Nome di un valore della fibra senza i prefissi di TR-064 (NewX_AVM-DE_RxPower → RxPower)."""
    k = re.sub(r"^New", "", str(k))
    return re.sub(r"^X_AVM[-_]DE_", "", k)[:40]


class Fritz:
    def __init__(self):
        self.lock = threading.RLock()       # una richiesta alla volta sulla sessione HTTP condivisa
        self.fc, self.key, self.fails = None, None, 0
        self.names = {}                     # MAC -> nome, chiesto una sola volta
        self._reset_cache()

    def _reset_cache(self):
        self.static, self.static_at = {}, None
        self.wlan_services, self.wlan_info, self.wlan_at, self.wlans = None, {}, None, None
        self.hosts, self.hosts_at = {}, None
        self.guests, self.guests_count, self.guests_at = None, None, None
        self.addon, self.addon_at = None, None
        self.ext_ip, self.ext_ip_at, self.last_uptime, self.last_connected = None, None, None, None
        self.mesh_at, self.fiber_at = None, None        # ultime letture (mappa mesh, stato della fibra)
        self.lan_prev = None                            # ultimi contatori della porta LAN (repeater)

    def failed(self):
        """Errore: chiude solo le connessioni HTTP (si riaprono da sole alla richiesta dopo). Solo dopo
        REBUILD_AFTER errori di fila ricrea la connessione da capo, che rilegge le descrizioni dei
        servizi: sul Pi Zero è l'operazione più pesante, inutile ripeterla per un timeout isolato."""
        with self.lock:
            self.fails += 1
            if self.fails >= REBUILD_AFTER:
                self.fc, self.fails = None, 0
            elif self.fc is not None:
                session = getattr(self.fc, "session", None)   # fritzconnection precedenti: senza sessione
                if session is not None:
                    _safe(session.close)

    def call(self, fc, service, action):
        with self.lock:
            return fc.call_action(service, action)

    def connection(self, cfg):
        key = (cfg["fritz_host"], cfg.get("fritz_user"), cfg.get("fritz_password"))
        with self.lock:
            if self.fc is None or self.key != key:
                from fritzconnection import FritzConnection   # import pigro: la libreria è facoltativa
                kw = dict(address=key[0], user=key[1] or None, password=key[2] or None, timeout=8)
                try:
                    os.makedirs(sysops.STATE_DIR, exist_ok=True)
                    self.fc = FritzConnection(**kw, use_cache=True, cache_directory=sysops.STATE_DIR)
                except TypeError:                             # fritzconnection precedente alla 1.10
                    self.fc = FritzConnection(**kw)
                if self.key != key:                           # altro router o altre credenziali
                    self._reset_cache()
                self.key = key
            return self.fc

    # --- traffico: una sola chiamata per campione (contatori e velocità insieme)
    def addon_infos(self, cfg):
        with self.lock:
            fc = self.connection(cfg)
            info = fc.call_action("WANCommonIFC1", "GetAddonInfos")
            sent = _int(info.get("NewX_AVM_DE_TotalBytesSent64"))
            recv = _int(info.get("NewX_AVM_DE_TotalBytesReceived64"))
            if sent is None or recv is None:              # FRITZ!OS vecchi: contatori a 32 bit
                sent = _int(fc.call_action("WANCommonIFC1", "GetTotalBytesSent").get("NewTotalBytesSent"))
                recv = _int(fc.call_action("WANCommonIFC1", "GetTotalBytesReceived").get("NewTotalBytesReceived"))
            self.addon, self.addon_at, self.fails = info, time.monotonic(), 0
            return time.time(), sent, recv, _int(info.get("NewByteSendRate")), _int(info.get("NewByteReceiveRate"))

    # --- riepilogo allegato a ogni report
    def summary(self, cfg):
        if not cfg.get("fritz_enabled") or not cfg.get("fritz_host"):
            return None
        try:
            data = self._summary(cfg)
            self.fails = 0
            return data
        except ImportError:
            return {"ok": False, "error": "Libreria fritzconnection non installata sulla sonda"}
        except Exception as exc:  # noqa: BLE001
            self.failed()                                 # al prossimo giro riprovo
            log.error("FRITZ!Box %s non raggiungibile: %s", cfg.get("fritz_host"), exc)
            return {"ok": False, "error": str(exc)[:200]}

    def _summary_wifi(self, fc, mono):
        """FRITZ!Box «solo Wi-Fi» (ripetitore o secondo FRITZ nella stessa casa): Internet, traffico,
        ospiti e dispositivi li conosce il principale; qui contano i client collegati alle sue reti.
        La prima chiamata di rete è quella dei client: se il FRITZ non risponde, ci si ferma lì."""
        wlans = self._wlans(fc, mono)
        if self.static_at is None or mono - self.static_at > SLOW_EVERY:
            dev = _soft(lambda: self.call(fc, "DeviceInfo1", "GetInfo"), {}) or {}
            self.static = {"model": _safe(lambda: fc.modelname), "firmware": _safe(lambda: fc.system_version),
                           "device_uptime": _int(dev.get("NewUpTime"))}
            self.static_at = mono
        st = self.static
        data = {"ok": True, "model": st.get("model"), "firmware": st.get("firmware"), "wlans": wlans,
                "device_uptime": None if st.get("device_uptime") is None
                else st["device_uptime"] + int(mono - self.static_at)}
        data.update(_soft(lambda: self._lan_rates(fc, mono), None) or {})
        return data

    def _lan_rates(self, fc, mono):
        """Traffico della porta LAN del repeater (bit/s, media dall'ultimo riepilogo), dai contatori
        di LANEthernetInterfaceConfig1. Il server decide come mostrarlo: con il repeater collegato
        alla mesh via cavo è tutto il suo traffico (ricevuto = download dei suoi dispositivi)."""
        if "LANEthernetInterfaceConfig1" not in (fc.services or {}):
            return None
        st = self.call(fc, "LANEthernetInterfaceConfig1", "GetStatistics")
        rx, tx = _int(st.get("NewBytesReceived")), _int(st.get("NewBytesSent"))
        if rx is None or tx is None:
            return None
        prev, self.lan_prev = self.lan_prev, (mono, rx, tx)
        if prev is None or mono - prev[0] < 5:
            return None
        dt = mono - prev[0]

        def rate(now, before):
            d = now - before
            if d < 0:                                     # contatore a 32 bit ripartito da zero
                d += 2 ** 32 if before < 2 ** 32 else 0
            return int(d * 8 / dt) if d >= 0 else None
        return {"lan_rx_rate": rate(rx, prev[1]), "lan_tx_rate": rate(tx, prev[2]), "lan_dt": round(dt, 1)}

    def _summary(self, cfg):
        """Riepilogo del router. Le chiamate prendono il lock una alla volta, così il campionatore
        del traffico non resta fermo per tutto il riepilogo. Al primo errore di rete si smette; se il
        router è lento, oltre SUMMARY_BUDGET secondi le parti facoltative usano gli ultimi valori."""
        fc = self.connection(cfg)
        mono = time.monotonic()
        if cfg.get("role") == "wifi":
            return self._summary_wifi(fc, mono)

        def late():
            return time.monotonic() - mono > SUMMARY_BUDGET

        # prima chiamata: se il router non risponde, si capisce subito
        status = _soft(lambda: self.call(fc, "WANIPConn1", "GetStatusInfo"), None)
        if self.static_at is None or mono - self.static_at > SLOW_EVERY:
            dev = _soft(lambda: self.call(fc, "DeviceInfo1", "GetInfo"), {}) or {}
            link = _soft(lambda: self.call(fc, "WANCommonIFC1", "GetCommonLinkProperties"), {}) or {}
            self.static = {"model": _safe(lambda: fc.modelname), "firmware": _safe(lambda: fc.system_version),
                           "device_uptime": _int(dev.get("NewUpTime")),
                           "max_up": _int(link.get("NewLayer1UpstreamMaxBitRate")),
                           "max_down": _int(link.get("NewLayer1DownstreamMaxBitRate"))}
            self.static_at = mono
        st = self.static
        data = {"ok": True, "model": st["model"], "firmware": st["firmware"],
                "max_up": st["max_up"], "max_down": st["max_down"],
                "device_uptime": None if st["device_uptime"] is None
                else st["device_uptime"] + int(mono - self.static_at)}

        connected = status.get("NewConnectionStatus") == "Connected" if status else None
        uptime = _int(status.get("NewUptime")) if status else None
        reconnected = uptime is not None and self.last_uptime is not None and uptime < self.last_uptime
        if (self.ext_ip_at is None or reconnected or connected != self.last_connected
                or mono - self.ext_ip_at > SLOW_EVERY):
            self.ext_ip = _soft(lambda: self.call(fc, "WANIPConn1", "GetExternalIPAddress")
                                .get("NewExternalIPAddress"))
            self.ext_ip_at = mono
        self.last_uptime, self.last_connected = uptime, connected
        data.update(connected=connected, connection_uptime=uptime, external_ip=self.ext_ip)

        # velocità istantanea: riuso l'ultima lettura del traffico se recente
        info = self.addon if self.addon_at and mono - self.addon_at < 45 else \
            _soft(lambda: self.call(fc, "WANCommonIFC1", "GetAddonInfos"), None)
        up, down = (_int(info.get("NewByteSendRate")), _int(info.get("NewByteReceiveRate"))) if info else (None, None)
        data["rate_up"] = up * 8 if up is not None else None          # bit/s
        data["rate_down"] = down * 8 if down is not None else None

        if (self.hosts_at is None or mono - self.hosts_at > SLOW_EVERY) and not late():
            hosts = _soft(lambda: self._hosts(fc), None)
            if hosts is not None:
                self.hosts, self.hosts_at = hosts, mono
        data["hosts_active"] = self.hosts.get("active")
        data["hosts_known"] = self.hosts.get("known")
        data["lan_active"] = self.hosts.get("lan")
        try:
            data["wlans"] = self.wlans if late() and self.wlans is not None else self._wlans(fc, mono)
        except OSError:
            raise
        except Exception as exc:  # noqa: BLE001
            data["wlans_error"] = str(exc)[:200]
        try:
            data["guests"] = self.guests if late() and self.guests is not None \
                else self._guests(fc, data.get("wlans"), mono)
        except OSError:
            raise
        except Exception as exc:  # noqa: BLE001 — rete ospiti assente o non leggibile
            data["guests_error"] = str(exc)[:200]
        # Mappa mesh e fibra: ogni MESH_EVERY secondi, e solo allora nel report (il server tiene
        # l'ultima ricevuta): la mappa pesa qualche kB, inutile rimandarla a ogni controllo.
        if (self.mesh_at is None or mono - self.mesh_at > MESH_EVERY) and not late():
            self.mesh_at = mono
            try:
                mesh = self._mesh(fc)
                if mesh:
                    data["mesh"] = mesh
            except OSError:
                raise
            except Exception as exc:  # noqa: BLE001 — FRITZ!OS senza mesh o formato diverso
                log.info("Mappa mesh del FRITZ!Box non disponibile: %s", exc)
        if (self.fiber_at is None or mono - self.fiber_at > MESH_EVERY) and not late():
            self.fiber_at = mono
            fiber = _soft(lambda: self._fiber(fc), None)
            if fiber:
                data["fiber"] = fiber
        return data

    def _mesh(self, fc):
        """Mappa mesh (JSON) letta dal FRITZ!Box e riassunta da parse_mesh."""
        from fritzconnection.lib.fritzhosts import FritzHosts
        with self.lock:
            hosts = FritzHosts(fc)
            if hasattr(hosts, "get_mesh_topology"):
                topo = hosts.get_mesh_topology()
            else:                                         # fritzconnection precedenti
                path = fc.call_action("Hosts1", "X_AVM-DE_GetMeshListPath")["NewX_AVM-DE_MeshListPath"]
                topo = fc.session.get(f"{fc.address}:{fc.port}{path}", timeout=8).json()
        return parse_mesh(topo)

    def _fiber(self, fc):
        """Stato della linea in fibra (X_AVM-DE_WANFiber1): tutte le azioni Get* senza argomenti.
        I nomi dei valori cambiano tra modelli e FRITZ!OS: si inviano così come sono, solo i
        valori semplici, e la pagina li traduce quando li riconosce."""
        svc = (fc.services or {}).get("X_AVM-DE_WANFiber1")
        if svc is None:
            return None
        out = {}
        for name, action in sorted((getattr(svc, "actions", None) or {}).items()):
            args = getattr(action, "arguments", None) or {}
            if not name.startswith("Get") or any(getattr(a, "direction", "out") == "in" for a in args.values()):
                continue
            res = _soft(lambda: self.call(fc, "X_AVM-DE_WANFiber1", name), None) or {}
            for k, v in res.items():
                if isinstance(v, (bool, int, float)) or (isinstance(v, str) and len(v) <= 100):
                    out.setdefault(fiber_key(k), v)
                if len(out) >= 30:
                    break
        return out if fiber_active(out) else None

    def _hosts(self, fc):
        """Dispositivi noti e attivi: una sola richiesta (elenco completo del FRITZ!Box)."""
        from fritzconnection.lib.fritzhosts import FritzHosts
        try:
            with self.lock:
                attrs = FritzHosts(fc).get_hosts_attributes()
            active = [h for h in attrs if h.get("Active") in TRUE]
            return {"known": len(attrs), "active": len(active),
                    "lan": sum(1 for h in active if str(h.get("InterfaceType", "")).lower() == "ethernet")}
        except OSError:
            raise
        except Exception:  # noqa: BLE001 — FRITZ!OS vecchi: una richiesta per dispositivo
            with self.lock:
                hosts = FritzHosts(fc).get_hosts_info()
            return {"known": len(hosts), "active": sum(1 for h in hosts if h.get("status")),
                    "lan": sum(1 for h in hosts if h.get("status")
                               and str(h.get("interface_type", "")).lower() == "ethernet")}

    def _wlans(self, fc, mono):
        """Client collegati ora a ciascuna rete Wi-Fi attiva. L'ultima rete è quella ospiti,
        come nel FRITZ!OS e in fritzconnection. Nome e banda si rileggono ogni 10 minuti."""
        if self.wlan_services is None:
            self.wlan_services = sorted((x for x in fc.services if x.startswith("WLANConfiguration")),
                                        key=lambda x: int(x[len("WLANConfiguration"):] or 0))
        services = self.wlan_services
        if self.wlan_at is None or mono - self.wlan_at > SLOW_EVERY:
            self.wlan_info = {svc: self.call(fc, svc, "GetInfo") for svc in services}
            self.wlan_at = mono
        out = []
        for i, svc in enumerate(services):
            info = self.wlan_info.get(svc) or {}
            if info.get("NewEnable") not in TRUE:
                continue
            clients = self.call(fc, svc, "GetTotalAssociations").get("NewTotalAssociations")
            freq = str(info.get("NewX_AVM-DE_FrequencyBand") or "")
            channel = _safe(lambda: int(info.get("NewChannel") or 0), 0)
            band = ("2,4 GHz" if freq.startswith("24") else "5 GHz" if freq.startswith("5")
                    else "6 GHz" if freq.startswith("6")
                    else "2,4 GHz" if 0 < channel <= 14 else "5 GHz" if channel else "")
            out.append({"ssid": info.get("NewSSID") or "", "band": band, "clients": int(clients or 0),
                        "guest": len(services) > 1 and i == len(services) - 1})
        self.wlans = out
        return out

    def _guests(self, fc, wlans, mono):
        """Dispositivi collegati ora alla rete ospiti Wi-Fi: lista di {mac, ip, name, signal}.
        Se la rete ospiti è attiva ma vuota non serve nessuna richiesta. L'elenco (una richiesta per
        ospite) si rilegge solo se cambia il numero di client della rete ospiti, che si legge comunque
        a ogni giro, o dopo GUEST_EVERY secondi."""
        from fritzconnection.lib.fritzhosts import FritzHosts
        guest_wlan = next((w for w in wlans or [] if w.get("guest")), None)
        count = guest_wlan["clients"] if guest_wlan is not None else None
        if count == 0:
            self.guests, self.guests_count, self.guests_at = [], 0, mono
            return []
        if (self.guests is not None and count is not None and count == self.guests_count
                and mono - self.guests_at < GUEST_EVERY):
            return self.guests
        guests = None
        try:
            from fritzconnection.lib.fritzwlan import FritzGuestWLAN
            with self.lock:
                infos = FritzGuestWLAN(fc).get_hosts_info()
            guests = [{"mac": str(h.get("mac", "")).upper(), "ip": h.get("ip"), "signal": h.get("signal")}
                      for h in infos if h.get("mac") and h.get("status", True) in TRUE]
        except OSError:
            raise
        except Exception:  # noqa: BLE001 — versione della libreria o del FRITZ!OS diversa
            guests = None
        if guests is None:
            with self.lock:
                attrs = FritzHosts(fc).get_hosts_attributes()
            guests = [{"mac": str(h.get("MACAddress", "")).upper(), "ip": h.get("IPAddress"),
                       "name": h.get("HostName"), "signal": None}
                      for h in attrs
                      if h.get("X_AVM-DE_Guest") in TRUE and h.get("Active") in TRUE and h.get("MACAddress")]
        names = self.names
        for g in guests:
            if g.get("name"):
                names[g["mac"]] = g["name"]
            elif g["mac"] not in names:
                names[g["mac"]] = _soft(
                    lambda: self._host_name(fc, g["mac"]), None)
            g["name"] = names.get(g["mac"]) or ""
        if len(names) > 500:                              # non cresce all'infinito
            names.clear()
        self.guests, self.guests_count, self.guests_at = guests[:50], count, mono
        return self.guests

    def _host_name(self, fc, mac):
        from fritzconnection.lib.fritzhosts import FritzHosts
        with self.lock:
            return FritzHosts(fc).get_specific_host_entry(mac).get("NewHostName")


FRITZ_MAX = 4                                 # FRITZ!Box oltre al primo
FRITZ_ID_RE = re.compile(r"^[a-z0-9]{1,16}$")


def fritz_boxes(cfg):
    """FRITZ!Box da leggere, ognuno nella forma che Fritz si aspetta (campi fritz_*).

    Il primo è quello di sempre (fritz_enabled, fritz_host…), con id «main»: è il principale e il
    suo riepilogo e il suo traffico viaggiano nei campi di sempre del report, così un server non
    aggiornato continua a mostrarlo. Gli altri stanno in fritz_more, ognuno con un id fisso scelto
    dalla pagina locale, e un ruolo:
      main  principale: Internet, traffico, ospiti, dispositivi (per esempio un FRITZ in un altro
            posto raggiungibile dalla sonda, con la VPN tra i due FRITZ!Box)
      wifi  solo Wi-Fi: ripetitore o secondo FRITZ nella stessa casa, solo i client delle sue reti"""
    out = []
    if cfg.get("fritz_enabled") and cfg.get("fritz_host"):
        out.append({"id": "main", "name": "", "role": "main", "fritz_enabled": True,
                    "fritz_host": str(cfg["fritz_host"]), "fritz_user": cfg.get("fritz_user") or "",
                    "fritz_password": cfg.get("fritz_password") or ""})
    # Quante FRITZ!Box oltre al primo: lo decide l'amministratore (fritz_max), default FRITZ_MAX
    try:
        # 0 è un valore vero (nessun FRITZ!Box oltre al primo), non «mancante»
        raw = cfg.get("fritz_max")
        lim = max(0, min(8, int(FRITZ_MAX if raw in (None, "") else raw)))
    except (TypeError, ValueError):
        lim = FRITZ_MAX
    for b in (cfg.get("fritz_more") or [])[:lim]:
        if not isinstance(b, dict) or not b.get("host") or not FRITZ_ID_RE.match(str(b.get("id", ""))) \
                or b["id"] == "main":
            continue
        out.append({"id": b["id"], "name": str(b.get("name") or "")[:40],
                    "role": "wifi" if b.get("role") == "wifi" else "main", "fritz_enabled": True,
                    "fritz_host": str(b["host"]), "fritz_user": str(b.get("user") or ""),
                    "fritz_password": str(b.get("password") or "")})
    return out


FRITZES = {}                 # id -> Fritz: una connessione e una cache per ogni FRITZ!Box
_fritz_jobs = {}             # id -> riepilogo in corso


def fritz_for(box_id):
    if box_id not in FRITZES:
        FRITZES[box_id] = Fritz()
    return FRITZES[box_id]


def fritz_summaries(cfg, wait=50):
    """Riepilogo di tutti i FRITZ!Box, letti in parallelo: (principale, [altri]).

    Ognuno ha il suo filo: un FRITZ lento o spento non fa aspettare gli altri. Se il riepilogo
    precedente di un FRITZ è ancora in corso non se ne avvia un secondo: si aspetta quello."""
    boxes = fritz_boxes(cfg)
    ids = {b["id"] for b in boxes}
    for gone in [k for k in FRITZES if k not in ids]:          # FRITZ!Box tolto dalla configurazione
        FRITZES.pop(gone, None)
        _fritz_jobs.pop(gone, None)
    jobs = []
    for box in boxes:
        job = _fritz_jobs.get(box["id"])
        if job is None or not job.is_alive():
            job = _fritz_jobs[box["id"]] = Background(fritz_for(box["id"]).summary, box)
        jobs.append((box, job))
    deadline = time.monotonic() + wait
    main, others = None, []
    for box, job in jobs:
        try:
            s = job.result(timeout=max(0.1, deadline - time.monotonic()))
        except Exception as exc:  # noqa: BLE001
            s = {"ok": False, "error": str(exc)[:200]}
        if box["id"] == "main":
            main = s
        else:
            others.append({**(s or {}), "id": box["id"], "name": box["name"], "role": box["role"]})
    return main, others


class TrafficSampler(threading.Thread):
    """Legge il traffico Internet dei FRITZ!Box principali ogni `traffic_interval` secondi, in un
    thread separato dai ping. I campioni [ts, up bit/s, down bit/s, durata s] restano in memoria,
    divisi per FRITZ!Box, fino al report successivo (al massimo TRAFFIC_MAX per FRITZ, poi i più
    vecchi vengono scartati). I FRITZ «solo Wi-Fi» non hanno traffico Internet: non si leggono."""

    TRAFFIC_MAX = 5000
    RETRY_AFTER = 60          # secondi: un FRITZ che non risponde si riprova solo dopo, senza rallentare gli altri

    def __init__(self):
        super().__init__(daemon=True, name="traffico")
        self.cfg = None
        self._lock = threading.Lock()
        self._samples = {}                 # id -> deque di campioni
        self._prev, self._down_until, self._last_error = {}, {}, {}

    def take(self):
        """Campioni raccolti dall'ultimo report: {id del FRITZ: [campioni]}."""
        with self._lock:
            out = {k: list(v) for k, v in self._samples.items() if v}
            for v in self._samples.values():
                v.clear()
        return out

    def _sample(self, box, every):
        bid = box["id"]
        try:
            now, sent, recv, r_up, r_down = fritz_for(bid).addon_infos(box)
        except Exception as exc:  # noqa: BLE001
            fritz_for(bid).failed()
            self._prev.pop(bid, None)
            self._down_until[bid] = time.monotonic() + self.RETRY_AFTER
            if time.time() - self._last_error.get(bid, 0) > 300:      # un messaggio ogni 5 minuti al massimo
                self._last_error[bid] = time.time()
                log.error("Lettura del traffico dal FRITZ!Box %s non riuscita: %s", box["name"] or box["fritz_host"], exc)
            return
        prev = self._prev.get(bid)
        if prev and sent is not None and recv is not None \
                and sent >= prev[1] and recv >= prev[2] and now > prev[0]:
            # Media reale sull'intervallo, dai contatori di byte: coglie anche i picchi brevi
            dt = now - prev[0]
            up, down = (sent - prev[1]) * 8 / dt, (recv - prev[2]) * 8 / dt
        else:
            # Primo campione o contatori azzerati: uso la velocità istantanea del router
            dt, up, down = every, (r_up or 0) * 8, (r_down or 0) * 8
        if sent is not None and recv is not None:
            self._prev[bid] = (now, sent, recv)
        else:
            self._prev.pop(bid, None)
        with self._lock:
            self._samples.setdefault(bid, deque(maxlen=self.TRAFFIC_MAX)).append(
                [round(now, 1), round(up), round(down), round(dt, 1)])

    def run(self):
        while True:
            cfg = self.cfg
            every = int((cfg or {}).get("traffic_interval") or 0)
            boxes = [b for b in fritz_boxes(cfg or {}) if b["role"] == "main"]
            if not boxes or every <= 0:
                self._prev.clear()
                time.sleep(30)                 # FRITZ!Box non usato: controllo raro
                continue
            every = max(2, every)
            started = time.time()
            ids = {b["id"] for b in boxes}
            with self._lock:
                for gone in [k for k in self._samples if k not in ids]:
                    self._samples.pop(gone, None)
            for box in boxes:
                if time.monotonic() >= self._down_until.get(box["id"], 0):
                    self._sample(box, every)
            time.sleep(max(0.5, every - (time.time() - started)))


PING_GAP = 0.2     # secondi tra l'avvio di due ping con il comando esterno (solo come ripiego)


def run_pings(devices, cfg, cycle):
    """Pinga i dispositivi. L'ordine di partenza ruota a ogni ciclo, così nessun dispositivo è
    sempre l'ultimo. Di norma i pacchetti partono dal programma stesso (pinger), distanziati di
    0,2 s diviso i "ping contemporanei"; se il sistema non lo consente usa il comando ping."""
    names = list(devices)
    if not names:
        return {}
    parallel = max(1, min(16, int(cfg.get("ping_parallel") or 2)))
    shift = cycle % len(names)
    rotated = names[shift:] + names[:shift]
    results = pinger.ping_many([(n, devices[n]) for n in rotated], cfg["ping_count"],
                               cfg["ping_timeout"], gap=PING_GAP / parallel)
    if results is None:
        results = run_pings_exec(devices, rotated, cfg, parallel)
    return {n: results.get(n, (False, None)) for n in names}   # nell'ordine della configurazione


def run_pings_exec(devices, rotated, cfg, parallel):
    """Ripiego: comando ping, con un numero limitato di ping contemporanei avviati scaglionati."""
    slots = threading.Semaphore(parallel)
    start_lock = threading.Lock()
    next_start = [time.monotonic()]

    def job(name):
        with slots:
            with start_lock:                       # distanzia gli avvii
                wait = next_start[0] - time.monotonic()
                next_start[0] = max(next_start[0], time.monotonic()) + PING_GAP
            if wait > 0:
                time.sleep(wait)
            return ping(devices[name], cfg["ping_count"], cfg["ping_timeout"])

    from concurrent.futures import ThreadPoolExecutor   # solo nel ripiego
    with ThreadPoolExecutor(max_workers=parallel) as pool:
        futures = {n: pool.submit(job, n) for n in rotated}
        return {n: f.result() for n, f in futures.items()}


# ---------------------------------------------------------------- stato della sonda
NETMON_VERSION = __version__
PROBE_STARTED = time.time()

# Bit di `vcgencmd get_throttled`: (bit, descrizione, adesso?)
THROTTLE_BITS = [(0, "sottotensione", True), (1, "frequenza limitata", True), (2, "rallentato", True),
                 (3, "limite di temperatura", True), (16, "sottotensione", False),
                 (17, "frequenza limitata", False), (18, "rallentato", False),
                 (19, "limite di temperatura", False)]


def _read(path, default=None):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return default


def _run(cmd, timeout=4):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _default_iface():
    """Interfaccia della rotta predefinita, da /proc/net/route."""
    for line in (_read("/proc/net/route", "") or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) > 3 and parts[1] == "00000000" and int(parts[3], 16) & 2:
            return parts[0]
    return None


def _local_ip(target):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
            sk.connect((target, 80))          # UDP: nessun pacchetto inviato, serve solo a scegliere l'IP
            return sk.getsockname()[0]
    except OSError:
        return None


def _wifi_info(iface):
    iw = static_info()["iw"]
    out = _run([iw, "dev", iface, "link"]) if iw else ""
    info = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("SSID:"):
            info["ssid"] = line[5:].strip()
        elif line.startswith("freq:"):
            info["freq_mhz"] = _safe(lambda: int(float(line[5:].strip())))
        elif line.startswith("signal:"):
            info["signal_dbm"] = _safe(lambda: int(line.split()[1]))
        elif line.startswith("tx bitrate:"):
            info["bitrate_mbit"] = _safe(lambda: float(line.split()[2]))
    if "signal_dbm" not in info:                # alternativa senza il comando iw
        for line in (_read("/proc/net/wireless", "") or "").splitlines()[2:]:
            if line.strip().startswith(iface + ":"):
                info["signal_dbm"] = _safe(lambda: int(float(line.split()[3])))
    return info


_static = {}
_full_cache = {}
_wifi_cache = {}


_remote_cache = {}


def remote_ops_ok():
    """La sonda può chiedere a root riavvio e aggiornamenti (sudo installato e permessi presenti)?
    Senza, misura e invia lo stesso: mancano solo le operazioni da remoto. Ricontrollato ogni 10 minuti."""
    now = time.monotonic()
    if now - _remote_cache.get("at", -1e9) > 600:
        ok = _safe(lambda: bool(shutil.which("sudo")) and sysops.can_sudo(sysops.REBOOT_CMD), False)
        _remote_cache.update(ok=bool(ok), at=now)
    return _remote_cache["ok"]


def full_update_ok():
    """La sonda sa installare il pacchetto completo dal server (script, verificatore, chiave, sudo)?
    Un "no" si ricontrolla ogni 10 minuti; un "si'" resta valido finche' la sonda gira."""
    now = time.monotonic()
    if not _full_cache.get("ok") and now - _full_cache.get("at", -1e9) > 600:
        ok = _safe(lambda: sysops.can_zipupdate() and os.path.exists(sysops.UPDATE_KEY), False)
        _full_cache.update(ok=bool(ok), at=now)
    return _full_cache["ok"]
WIFI_EVERY = 300          # secondi: l'elenco delle reti salvate cambia di rado (e subito dopo un comando)


def wifi_state():
    """Reti Wi-Fi salvate e possibilita' di gestirle dal server, rilette ogni WIFI_EVERY secondi."""
    if not _wifi_cache or time.monotonic() - _wifi_cache["at"] > WIFI_EVERY:
        nets = _safe(sysops.wifi_networks, None) or {"nm": False, "known": []}
        cmd = bool(nets["nm"] and _safe(sysops.can_wifi, False))
        _wifi_cache.update(at=time.monotonic(), nm=nets["nm"], known=nets["known"], cmd=cmd,
                           why="" if cmd else "nm" if not nets["nm"] else sysops._wifi_cap.get("problem") or "")
    return _wifi_cache


def static_info():
    """Dati che non cambiano mentre la sonda è in funzione: letti una volta sola."""
    if not _static:
        _static.update({
            "version": NETMON_VERSION,
            "model": (_read("/proc/device-tree/model", "") or "").replace("\x00", "").strip() or None,
            "os": next((l.split("=", 1)[1].strip('"') for l in (_read("/etc/os-release", "") or "").splitlines()
                        if l.startswith("PRETTY_NAME=")), None),
            "kernel": platform.release(),
            "python": platform.python_version(),
            "cpus": os.cpu_count(),
        })
        _static["vcgencmd"] = shutil.which("vcgencmd")   # solo Raspberry Pi: altrove nessun processo
        _static["iw"] = shutil.which("iw")
    return _static


def collect_system(cfg):
    """Stato della sonda: sistema, salute, rete e processo. Tutto opzionale: su hardware diverso
    dal Raspberry Pi alcuni dati (per esempio l'alimentazione) semplicemente mancano."""
    st = static_info()
    info = {k: st[k] for k in ("version", "model", "os", "kernel", "python", "cpus")}
    info.update({"hostname": socket.gethostname(),
                 "ping_mode": pinger.mode(),
                 "uptime": _safe(lambda: float(_read("/proc/uptime").split()[0])),
                 "probe_uptime": time.time() - PROBE_STARTED})

    t = _read("/sys/class/thermal/thermal_zone0/temp")
    info["temp_c"] = _safe(lambda: round(int(t) / 1000, 1)) if t else None

    thr = _run([st["vcgencmd"], "get_throttled"]) if st["vcgencmd"] else ""
    if "=" in thr:
        value = _safe(lambda: int(thr.split("=")[1].strip(), 16))
        if value is not None:
            info["throttled_raw"] = hex(value)
            info["throttled_now"] = sorted({d for b, d, now in THROTTLE_BITS if now and value >> b & 1})
            info["throttled_past"] = sorted({d for b, d, now in THROTTLE_BITS if not now and value >> b & 1})

    load = _safe(os.getloadavg)
    if load:
        info["load1"], info["load5"], info["load15"] = [round(x, 2) for x in load]

    mem = {}
    for line in (_read("/proc/meminfo", "") or "").splitlines():
        k, _, v = line.partition(":")
        if k in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
            mem[k] = _safe(lambda: int(v.split()[0]) * 1024)
    info["mem_total"], info["mem_available"] = mem.get("MemTotal"), mem.get("MemAvailable")
    if mem.get("SwapTotal"):
        info["swap_used"] = mem["SwapTotal"] - (mem.get("SwapFree") or 0)

    du = _safe(lambda: shutil.disk_usage("/"))
    if du:
        info["disk_total"], info["disk_used"] = du.total, du.used

    iface = _default_iface()
    info["iface"] = iface
    target = urlsplit_host(cfg.get("server_url", "")) or "1.1.1.1"
    info["ip"] = _local_ip(target)
    if iface:
        wifi = os.path.isdir(f"/sys/class/net/{iface}/wireless") or iface.startswith("wl")
        info["link"] = "wifi" if wifi else "lan"
        info["mac"] = _read(f"/sys/class/net/{iface}/address")
        if wifi:
            info.update(_wifi_info(iface))
        else:
            speed = _safe(lambda: int(_read(f"/sys/class/net/{iface}/speed")))
            info["lan_speed_mbit"] = speed if speed and speed > 0 else None
            duplex = _read(f"/sys/class/net/{iface}/duplex")
            info["lan_duplex"] = duplex if duplex in ("full", "half") else None

    info["probe_rss"] = _safe(lambda: int(next(l.split()[1] for l in _read("/proc/self/status", "").splitlines()
                                               if l.startswith("VmRSS:"))) * 1024)
    info["buffered"] = _safe(buffer_count, 0)
    info["full_update"] = full_update_ok()
    info["remote_ops"] = remote_ops_ok()          # False: manca sudo, niente operazioni da remoto
    info["speedtest"] = True                      # la sonda sa eseguire lo speedtest dalla pagina
    info["scan"] = True                           # e il controllo di sicurezza dei dispositivi
    info["scan_modes"] = True                     # con le modalità veloce, standard e approfondito
    w = wifi_state()
    info["wifi_nm"], info["wifi_cmd"], info["wifi_known"], info["wifi_why"] = w["nm"], w["cmd"], w["known"], w["why"]
    up = _safe(sysops.upgrade_status, {}) or {}
    info["upgrade_state"] = up.get("state")
    info["upgrade_finished"] = up.get("finished")
    info["reboot_required"] = bool(up.get("reboot_required"))
    return info


def server_endpoint(url):
    """(host, porta) del server, per la prova di collegamento dopo un cambio di rete Wi-Fi."""
    try:
        scheme, rest = url.split("://", 1)
        hostport = rest.split("/", 1)[0].rsplit("@", 1)[-1]
        if hostport.startswith("["):
            host, _, port = hostport[1:].partition("]")
            port = port.lstrip(":")
        else:
            host, _, port = hostport.partition(":")
        return host, int(port) if port else (443 if scheme.lower() == "https" else 80)
    except (ValueError, IndexError):
        return "", 0


def urlsplit_host(url):
    try:
        return url.split("://", 1)[1].split("/", 1)[0].split(":")[0]
    except IndexError:
        return None


def thresholds(cfg):
    """Soglie inviate al server: proporzionali all'intervallo oppure fisse in secondi."""
    if cfg["alert_mode"] == "fisso":
        stale, offline = cfg["stale_seconds"], cfg["offline_seconds"]
    else:
        stale = cfg["interval"] * float(cfg["stale_factor"])
        offline = cfg["interval"] * float(cfg["offline_factor"])
    return {"fail_threshold": int(cfg["fail_threshold"]),
            "stale": round(stale, 1), "offline": round(offline, 1)}


def ping(host, count, timeout):
    """Restituisce (risponde, rtt medio in ms o None)."""
    try:
        r = subprocess.run(
            ["ping", "-n", "-q", "-c", str(count), "-W", str(timeout), str(host)],
            capture_output=True, text=True,
            timeout=count * (timeout + 1) + 2)
    except subprocess.TimeoutExpired:
        return False, None
    m = re.search(r"= [\d.]+/([\d.]+)/", r.stdout)
    ok = r.returncode == 0
    return ok, (round(float(m.group(1)), 2) if ok and m else None)


class Background(threading.Thread):
    """Esegue una funzione in un thread; result() aspetta al massimo `timeout` secondi."""

    def __init__(self, fn, *args):
        super().__init__(daemon=True, name="fritz")
        self.fn, self.args, self.value, self.error = fn, args, None, None
        self.start()

    def run(self):
        try:
            self.value = self.fn(*self.args)
        except Exception as exc:  # noqa: BLE001
            self.error = exc

    def result(self, timeout):
        self.join(timeout)
        if self.is_alive():
            raise TimeoutError("FRITZ!Box: nessuna risposta in tempo")
        if self.error:
            raise self.error
        return self.value


LOG_OK_EVERY = 3600    # con tutto invariato, una riga "OK" nel registro all'ora (meno scritture)


# ---------------------------------------------------------------- speedtest (richiesto dalla pagina)
# Si misura con i server di velocità di Cloudflare (speed.cloudflare.com, gli stessi di
# speed.cloudflare.com nel browser): latenza, download e upload con più connessioni in parallelo,
# ognuna limitata nel tempo e nei byte. Solo libreria standard: niente programmi da installare.
# Parte alla fine del ciclo dei ping e il risultato viaggia con il report di quel ciclo.
# La velocità si calcola DOPO i primi secondi: all'inizio le connessioni TCP accelerano (slow start) e
# contarli abbasserebbe il risultato, soprattutto sulle linee veloci. Il tetto ai byte cresce con la
# velocità misurata, perché una linea veloce non esaurisca il budget proprio durante l'accelerazione.
SPEED_HOST = "speed.cloudflare.com"
SPEED_STREAMS = 4               # connessioni in parallelo (una sola sottostima le linee veloci)
SPEED_SECONDS = 8               # durata massima di download e di upload
SPEED_WARMUP = 2.0              # secondi iniziali esclusi dal calcolo (accelerazione delle connessioni)
SPEED_MIN_WINDOW = 1.0          # finestra minima dopo l'accelerazione; se più corta, si usa tutto il test
SPEED_MAX_DOWN = 120_000_000    # byte scaricati sulle linee fino a ~120 Mbit/s (linee a consumo, LTE)
SPEED_CAP_DOWN = 750_000_000    # tetto assoluto, per le linee veloci (circa 1 Gbit/s per 6 secondi)
SPEED_MAX_UP = 30_000_000       # byte caricati sulle linee fino a ~30 Mbit/s
SPEED_CAP_UP = 250_000_000      # tetto assoluto in upload
_speed_req = {}                 # richiesta in attesa: {"id": ...}
_speed_done = set()             # richieste già misurate (il server smette di inviarle col report)


def speedtest_requested(req):
    """Richiesta dal server (risposta al report o al controllo della configurazione)."""
    if isinstance(req, dict) and req.get("id") and str(req["id"]) not in _speed_done:
        _speed_req["id"] = str(req["id"])[:40]


def _speed_conn():
    return http.client.HTTPSConnection(SPEED_HOST, timeout=15, context=ssl.create_default_context())


def _unsent(sock):
    """Byte scritti sulla connessione ma non ancora confermati dall'altra parte (Linux). In upload
    send() ritorna appena i dati sono nel buffer del sistema: senza toglierli, l'inizio del test
    (buffer che si riempiono di colpo) sembrerebbe velocissimo."""
    try:
        return struct.unpack("i", fcntl.ioctl(sock.fileno(), termios.TIOCOUTQ, b"\0\0\0\0"))[0]
    except (OSError, ValueError, AttributeError):
        return 0


def _speed_streams(work, base, cap):
    """Esegue work(deadline, add, socks) su SPEED_STREAMS thread. Restituisce (byte al secondo, byte
    totali): la velocità è quella dopo SPEED_WARMUP secondi, se la misura è durata abbastanza.
    socks: le connessioni di upload si registrano qui, per contare solo i byte già arrivati."""
    lock = threading.Lock()
    st = {"total": 0, "budget": base}
    socks = []
    start = time.monotonic()
    deadline = start + SPEED_SECONDS

    def add(n):
        with lock:
            st["total"] += n
            return st["total"] < st["budget"]

    threads = [threading.Thread(target=work, args=(deadline, add, socks), daemon=True) for _ in range(SPEED_STREAMS)]
    for t in threads:
        t.start()
    samples = [(0.0, 0)]                          # (secondi dall'inizio, byte arrivati) ogni decimo di secondo
    while any(t.is_alive() for t in threads) and time.monotonic() < deadline + 20:
        time.sleep(0.1)
        now = time.monotonic() - start
        with lock:
            done = max(samples[-1][1], st["total"] - sum(_unsent(x) for x in list(socks)))
            # tetto: almeno quello di base; se la linea va più veloce, quanto serve per arrivare alla
            # fine del tempo alla velocità degli ultimi 0,5 secondi (con un po' di margine)
            old = next((x for x in reversed(samples) if now - x[0] >= 0.5), samples[0])
            rate = (done - old[1]) / max(0.05, now - old[0])
            st["budget"] = max(st["budget"], min(cap, st["total"] + rate * (SPEED_SECONDS - now + 0.5)))
        samples.append((now, done))
    for t in threads:
        t.join(1)
    total = st["total"]
    if not socks:                                 # download: l'ultimo byte è arrivato quando è stato contato
        samples.append((min(time.monotonic() - start, SPEED_SECONDS), total))
    # fine della misura: il primo campione con il totale finale (dopo non è arrivato più niente)
    end = next(x for x in samples if x[1] >= samples[-1][1])
    warm = next((x for x in samples if x[0] >= SPEED_WARMUP), None)
    if warm and end[0] - warm[0] >= SPEED_MIN_WINDOW and end[1] > warm[1]:
        return (end[1] - warm[1]) / (end[0] - warm[0]), total
    return end[1] / max(0.001, end[0]), total


def _download(deadline, add, socks):
    conn = _speed_conn()
    try:
        while time.monotonic() < deadline:
            conn.request("GET", "/__down?bytes=25000000")
            resp = conn.getresponse()
            while time.monotonic() < deadline:
                chunk = resp.read(65536)
                if not chunk:
                    break
                if not add(len(chunk)):
                    return
            else:
                return                  # tempo scaduto a metà: la connessione si chiude e basta
    except (OSError, http.client.HTTPException):
        pass
    finally:
        conn.close()


def _upload(deadline, add, socks):
    block = b"0" * 1_000_000
    conn = _speed_conn()
    try:
        conn.connect()
        socks.append(conn.sock)
        while time.monotonic() < deadline:
            conn.putrequest("POST", "/__up")
            conn.putheader("Content-Type", "application/octet-stream")
            conn.putheader("Content-Length", str(len(block) * 4))
            conn.endheaders()
            for _ in range(4):
                for i in range(0, len(block), 65536):
                    if time.monotonic() >= deadline:
                        return
                    piece = block[i:i + 65536]
                    conn.send(piece)
                    if not add(len(piece)):
                        return
            conn.getresponse().read()
    except (OSError, http.client.HTTPException):
        pass
    finally:
        if conn.sock in socks:
            add(-_unsent(conn.sock))            # i byte rimasti nel buffer non sono arrivati: non contano
            socks.remove(conn.sock)
        conn.close()


def run_speedtest():
    """Misura latenza, download e upload. Restituisce il risultato da allegare al report."""
    rid = _speed_req.pop("id", None)
    out = {"id": rid, "ts": time.time()}
    try:
        conn = _speed_conn()
        pings, colo = [], ""
        try:
            for _ in range(6):
                t = time.monotonic()
                conn.request("GET", "/__down?bytes=0")
                resp = conn.getresponse()
                resp.read()
                ms = (time.monotonic() - t) * 1000
                # tolto il tempo di elaborazione di Cloudflare (Server-Timing), come fa il loro sito
                m = re.search(r"dur=([\d.]+)", resp.getheader("server-timing") or "")
                pings.append(max(0.1, ms - (float(m.group(1)) if m else 0)))
                colo = (resp.getheader("cf-ray") or "").rsplit("-", 1)[-1] if "-" in (resp.getheader("cf-ray") or "") else colo
        finally:
            conn.close()
        pings = pings[1:]                         # il primo include l'apertura della connessione
        mid = sorted(pings)[len(pings) // 2]
        d_rate, down = _speed_streams(_download, SPEED_MAX_DOWN, SPEED_CAP_DOWN)
        u_rate, up = _speed_streams(_upload, SPEED_MAX_UP, SPEED_CAP_UP)
        if not down:
            raise OSError("download non riuscito")
        out.update(ok=True, ping_ms=round(mid, 1),
                   jitter_ms=round(sum(abs(a - b) for a, b in zip(pings, pings[1:])) / max(1, len(pings) - 1), 1),
                   down_mbps=round(d_rate * 8 / 1e6, 1), up_mbps=round(u_rate * 8 / 1e6, 1),
                   bytes_down=down, bytes_up=up, server=f"Cloudflare {colo}".strip())
    except (OSError, http.client.HTTPException, IndexError) as exc:
        out.update(ok=False, error=str(exc)[:200] or exc.__class__.__name__)
    if rid:
        _speed_done.add(rid)
    log.info("SpeedTest: %s", f"↓ {out.get('down_mbps')} ↑ {out.get('up_mbps')} Mbit/s, ping {out.get('ping_ms')} ms"
             if out.get("ok") else "non riuscito: " + out.get("error", ""))
    return out


# ---------------------------------------------------------------- controllo di sicurezza (porte aperte)
# Chiesto dalla pagina (o una volta al giorno dal server) per UN dispositivo della rete di casa.
# Solo indirizzi privati: la sonda non scansiona mai Internet, qualunque cosa chieda il server.
# Connessioni TCP normali, poche alla volta e con pause brevi, perché alcuni dispositivi IoT economici
# si bloccano con le scansioni aggressive. Sui servizi trovati solo domande innocue (intestazione,
# certificato, «serve una password?»): nessun tentativo di entrare o di sfruttare un difetto.
SCAN_PARALLEL = 6               # connessioni contemporanee
SCAN_TIMEOUT = 1.2              # secondi per porta
# Modalità scelta nella pagina: veloce (solo le porte a rischio), standard (le porte più usate dai
# dispositivi di casa), approfondito (anche tutte le porte da 1 a 1024 e molte altre note). Secondi
# al massimo per tutto il controllo, per modalità.
SCAN_BUDGET = {"veloce": 60, "standard": 150, "approfondito": 900}
# porta -> (servizio, rischio se aperta, nota). Rischio: alta | media | bassa | info
SCAN_PORTS = {
    21: ("FTP", "media", "trasferimento file senza cifratura: password in chiaro sulla rete"),
    22: ("SSH", "info", "accesso remoto cifrato: usa password robuste o chiavi"),
    23: ("Telnet", "alta", "accesso remoto senza cifratura, tipico delle botnet IoT (Mirai): va disattivato"),
    25: ("SMTP", "bassa", "server di posta"),
    53: ("DNS", "info", "server DNS"),
    80: ("HTTP", "info", "pagina web senza HTTPS"),
    81: ("HTTP", "info", "pagina web senza HTTPS"),
    110: ("POP3", "bassa", "posta senza cifratura"),
    111: ("RPC", "media", "servizio di sistema esposto (rpcbind)"),
    135: ("MS RPC", "media", "servizio Windows esposto"),
    139: ("NetBIOS", "media", "condivisione file Windows (vecchio protocollo)"),
    143: ("IMAP", "bassa", "posta senza cifratura"),
    161: ("SNMP", "media", "gestione di rete: spesso con password predefinite"),
    443: ("HTTPS", "info", "pagina web cifrata"),
    445: ("SMB", "media", "condivisione file Windows: tienila solo se serve"),
    502: ("Modbus", "alta", "protocollo industriale senza autenticazione"),
    554: ("RTSP", "media", "flusso video (telecamere)"),
    631: ("IPP", "bassa", "stampante"),
    873: ("rsync", "media", "sincronizzazione file"),
    1080: ("SOCKS", "media", "proxy"),
    1883: ("MQTT", "media", "messaggi IoT senza cifratura"),
    1900: ("UPnP", "media", "configurazione automatica del router e dei dispositivi"),
    2323: ("Telnet", "alta", "Telnet su porta alternativa, tipico delle botnet IoT: va disattivato"),
    2375: ("Docker", "alta", "API di Docker senza cifratura: chi la raggiunge controlla il computer"),
    3000: ("HTTP", "info", "pagina web (porta di sviluppo)"),
    3306: ("MySQL", "media", "database raggiungibile dalla rete"),
    3389: ("RDP", "alta", "desktop remoto di Windows: bersaglio frequente di attacchi"),
    5000: ("HTTP/UPnP", "bassa", "pagina web o descrizione UPnP"),
    5353: ("mDNS", "info", "scoperta dei dispositivi in rete"),
    5432: ("PostgreSQL", "media", "database raggiungibile dalla rete"),
    5555: ("ADB", "alta", "debug di Android aperto: chi lo raggiunge controlla il dispositivo"),
    5900: ("VNC", "alta", "desktop remoto"),
    5901: ("VNC", "alta", "desktop remoto"),
    6379: ("Redis", "media", "database in memoria"),
    6668: ("Tuya", "info", "dispositivo smart Tuya"),
    7547: ("TR-069", "media", "gestione remota del router da parte dell'operatore"),
    8000: ("HTTP", "info", "pagina web senza HTTPS"),
    8008: ("HTTP", "info", "pagina web (Chromecast e simili)"),
    8080: ("HTTP", "info", "pagina web senza HTTPS"),
    8081: ("HTTP", "info", "pagina web senza HTTPS"),
    8123: ("Home Assistant", "info", "Home Assistant"),
    8443: ("HTTPS", "info", "pagina web cifrata"),
    8883: ("MQTT TLS", "info", "messaggi IoT cifrati"),
    8888: ("HTTP", "info", "pagina web senza HTTPS"),
    9000: ("HTTP", "info", "pagina web"),
    9100: ("Stampa RAW", "bassa", "stampante: accetta lavori da chiunque in rete"),
    9200: ("Elasticsearch", "alta", "database spesso senza password"),
    11211: ("Memcached", "media", "cache in memoria"),
    1880: ("Node-RED", "media", "editor di automazioni"),
    27017: ("MongoDB", "media", "database raggiungibile dalla rete"),
    37777: ("Dahua DVR", "media", "videoregistratore di telecamere"),
    49152: ("UPnP", "bassa", "descrizione UPnP del dispositivo"),
    62078: ("iPhone sync", "info", "sincronizzazione di un dispositivo Apple"),
}
# Solo nel controllo approfondito, oltre a tutte le porte da 1 a 1024
SCAN_PORTS_DEEP = {
    1433: ("MS SQL", "media", "database raggiungibile dalla rete"),
    1521: ("Oracle", "media", "database raggiungibile dalla rete"),
    1723: ("PPTP", "media", "VPN con cifratura debole"),
    2049: ("NFS", "media", "cartelle condivise in rete (NFS)"),
    2379: ("etcd", "alta", "archivio di configurazione spesso senza password"),
    3128: ("Proxy", "media", "proxy web"),
    4444: ("?", "media", "porta usata spesso da programmi di controllo remoto non voluti"),
    5060: ("SIP", "info", "telefonia VoIP"),
    5357: ("WSD", "info", "scoperta dei dispositivi Windows"),
    5601: ("Kibana", "media", "pannello di analisi dati"),
    5672: ("AMQP", "media", "code di messaggi"),
    5985: ("WinRM", "media", "gestione remota di Windows"),
    5986: ("WinRM", "media", "gestione remota di Windows"),
    6000: ("X11", "alta", "schermo grafico raggiungibile dalla rete"),
    8009: ("AJP", "media", "connettore di Tomcat"),
    8086: ("InfluxDB", "media", "database raggiungibile dalla rete"),
    8090: ("HTTP", "info", "pagina web senza HTTPS"),
    8291: ("Winbox", "media", "gestione dei router MikroTik"),
    8384: ("Syncthing", "info", "pannello di Syncthing"),
    9090: ("HTTP", "info", "pagina web senza HTTPS"),
    9091: ("HTTP", "info", "pagina web (Transmission e simili)"),
    9443: ("HTTPS", "info", "pagina web cifrata"),
    10000: ("Webmin", "media", "pannello di amministrazione del sistema"),
    11434: ("Ollama", "media", "API di intelligenza artificiale senza password"),
    15672: ("RabbitMQ", "media", "pannello delle code di messaggi"),
    16992: ("Intel AMT", "alta", "gestione remota del computer a livello hardware"),
    16993: ("Intel AMT", "alta", "gestione remota del computer a livello hardware"),
    25565: ("Minecraft", "info", "server di gioco"),
    32400: ("Plex", "info", "server multimediale Plex"),
    51413: ("BitTorrent", "info", "condivisione file BitTorrent"),
}
for _p in (1080, 2082, 2083, 4443, 5000, 5001, 7000, 7001, 7070, 7443, 8001, 8002, 8010, 8088, 8089, 8180,
           8181, 8200, 8500, 8880, 8889, 8899, 9001, 9080, 9999, 10001, 18080, 20000, 49153, 50000):
    SCAN_PORTS_DEEP.setdefault(_p, ("?", "bassa", ""))
HTTP_PORTS = (80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8123, 8888, 9000, 1880, 49152)
TLS_PORTS = (443, 8443)
_scan_req = {}                  # richiesta in attesa: {"id", "host", "mode"}
_scan_done = set()              # richieste già eseguite
_scan_job = [None]              # thread del controllo in corso
_scan_result = [None]           # risultato da inviare finché il server non lo conferma


def scan_requested(req):
    if (isinstance(req, dict) and req.get("id") and str(req["id"]) not in _scan_done
            and _scan_job[0] is None and _scan_result[0] is None):
        mode = req.get("mode") if req.get("mode") in SCAN_BUDGET else "standard"
        _scan_req.update(id=str(req["id"])[:40], host=str(req.get("host") or "")[:253], mode=mode)


def scan_target(host):
    """IP privato del dispositivo, o ValueError: la sonda controlla solo la rete di casa."""
    if not valid_host(host):
        raise ValueError("indirizzo non valido")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = ipaddress.ip_address(socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)[0][4][0].split("%")[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if not ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
        raise ValueError(f"{ip} non è un indirizzo della rete di casa: controllo non eseguito")
    return str(ip)


def _recv(sock, n=512, wait=1.5):
    sock.settimeout(wait)
    try:
        return sock.recv(n)
    except OSError:
        return b""


def _probe_port(ip, port):
    """Connessione TCP alla porta: None se chiusa, altrimenti il socket aperto."""
    try:
        return socket.create_connection((ip, port), timeout=SCAN_TIMEOUT)
    except OSError:
        return None


def _detail(ip, port, sock):
    """Domande innocue al servizio aperto. Restituisce (rischio, nota) da sostituire, o None."""
    try:
        if port in (21,):
            banner = _recv(sock).decode("latin-1", "ignore").strip()[:80]
            sock.sendall(b"USER anonymous\r\n")
            r = _recv(sock).decode("latin-1", "ignore")
            if r.startswith("331"):
                sock.sendall(b"PASS netmon@example.com\r\n")
                if _recv(sock).decode("latin-1", "ignore").startswith("230"):
                    return "alta", "FTP accetta l'accesso anonimo, senza password" + (f" ({banner})" if banner else "")
            return None if not banner else ("media", "FTP senza cifratura: " + banner)
        if port in (23, 2323):
            return None
        if port == 22:
            banner = _recv(sock).decode("latin-1", "ignore").strip()[:80]
            return ("info", "accesso remoto cifrato: " + banner) if banner else None
        if port == 1883:
            # CONNECT MQTT 3.1.1 senza utente né password: CONNACK 0 vuol dire «entra chiunque»
            sock.sendall(bytes([0x10, 0x14, 0, 4]) + b"MQTT" + bytes([4, 2, 0, 30, 0, 8]) + b"netmon00")
            r = _recv(sock, 4)
            if len(r) >= 4 and r[0] == 0x20 and r[3] == 0:
                return "alta", "MQTT accetta connessioni senza password: chiunque in rete legge e comanda i dispositivi"
            return None
        if port == 6379:
            sock.sendall(b"PING\r\n")
            if _recv(sock, 64).startswith(b"+PONG"):
                return "alta", "Redis risponde senza password"
            return None
        if port in (5900, 5901):
            ver = _recv(sock, 12)
            if ver.startswith(b"RFB "):
                sock.sendall(ver)
                types = _recv(sock, 64)
                if len(types) >= 2 and types[0] > 0 and 1 in types[1:1 + types[0]]:
                    return "alta", "VNC senza password: chiunque in rete vede e usa lo schermo"
            return None
        if port == 554:
            sock.sendall(f"DESCRIBE rtsp://{ip}/ RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n".encode())
            r = _recv(sock, 200).decode("latin-1", "ignore")
            if r.startswith("RTSP/1.0 200"):
                return "alta", "il video della telecamera si apre senza password"
            return None
        if port == 9200:
            sock.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            if re.match(rb"HTTP/1\.[01] 200", _recv(sock, 200)):
                return "alta", "Elasticsearch risponde senza password"
            return None
        if port in HTTP_PORTS:
            sock.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: netmon\r\n\r\n".encode())
            head = b""
            while len(head) < 4096 and b"\r\n\r\n" not in head:
                chunk = _recv(sock, 1024)
                if not chunk:
                    break
                head += chunk
            text = head.decode("latin-1", "ignore")
            if not text.startswith("HTTP/"):
                return None
            server = re.search(r"(?im)^server:\s*(.{1,60})$", text)
            what = SCAN_PORTS[port][0]
            note = (f"{what}: {server.group(1).strip()}" if server else what) + " senza HTTPS"
            if port == 1880 and " 200 " in text.split("\r\n", 1)[0]:
                return "alta", "editor di Node-RED aperto senza password"
            if re.search(r"(?i)type=[\"']?password|www-authenticate:\s*basic", text):
                return "media", note + ": la password viaggia in chiaro"
            return SCAN_PORTS[port][1], note
    except OSError:
        return None
    return None


def _tls_detail(ip, port):
    """Certificato della pagina cifrata: scaduto, in scadenza o protocollo vecchio."""
    import datetime
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=3) as raw, ctx.wrap_socket(raw, server_hostname=ip) as s:
            version = s.version() or ""
            der = s.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None
    notes, risk = [], "info"
    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        notes.append(f"protocollo vecchio ({version})")
        risk = "media"
    try:   # data di scadenza dal certificato (DER), senza librerie esterne
        m = re.findall(rb"\x17\x0d(\d{12})Z", der or b"")
        if len(m) >= 2:
            end = datetime.datetime.strptime(m[1].decode(), "%y%m%d%H%M%S").replace(tzinfo=datetime.timezone.utc)
            days = (end - datetime.datetime.now(datetime.timezone.utc)).days
            if days < 0:
                notes.append("certificato scaduto")
                risk = "media"
            elif days < 21:
                notes.append(f"certificato in scadenza tra {days} giorni")
                risk = "bassa" if risk == "info" else risk
    except (ValueError, IndexError):
        pass
    return (risk, "pagina cifrata: " + ", ".join(notes)) if notes else None


def _unknown_detail(ip, sock):
    """Porta non in elenco (controllo approfondito): se risponde come pagina web lo dice."""
    try:
        sock.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: netmon\r\n\r\n".encode())
        text = _recv(sock, 1024).decode("latin-1", "ignore")
    except OSError:
        return None
    if not text.startswith("HTTP/"):
        return None
    server = re.search(r"(?im)^server:\s*(.{1,60})$", text)
    return "HTTP", "info", "pagina web" + (f" ({server.group(1).strip()})" if server else "") + " senza HTTPS"


def scan_ports(mode):
    """Porte da provare: {porta: (servizio, rischio, nota)}."""
    if mode == "veloce":
        return {p: v for p, v in SCAN_PORTS.items() if v[1] in ("alta", "media") or p in (22, 80, 443)}
    if mode == "approfondito":
        ports = {p: ("?", "bassa", "") for p in range(1, 1025)}
        ports.update(SCAN_PORTS_DEEP)
        ports.update(SCAN_PORTS)
        return ports
    return dict(SCAN_PORTS)


def run_scan(req):
    """Controlla le porte di un dispositivo. Restituisce il risultato da allegare al report."""
    mode = req.get("mode") if req.get("mode") in SCAN_BUDGET else "standard"
    out = {"id": req["id"], "host": req["host"], "mode": mode, "ts": time.time()}
    try:
        ip = scan_target(req["host"])
        out["ip"] = ip
        deadline = time.monotonic() + SCAN_BUDGET[mode]
        table = scan_ports(mode)
        found, lock, todo = [], threading.Lock(), sorted(table)

        def worker():
            while time.monotonic() < deadline:
                with lock:
                    if not todo:
                        return
                    port = todo.pop(0)
                sock = _probe_port(ip, port)
                if sock is None:
                    time.sleep(0.05)             # passo gentile anche sulle porte chiuse
                    continue
                service, risk, note = table[port]
                with sock:
                    if port in SCAN_PORTS:
                        detail = _detail(ip, port, sock)
                    else:
                        web = _unknown_detail(ip, sock)
                        detail = web[1:] if web else None
                        if web:
                            service = web[0]
                if port in TLS_PORTS:
                    detail = _tls_detail(ip, port) or detail
                if detail:
                    risk, note = detail
                if not note:
                    note = "servizio non riconosciuto: controlla che sia voluto"
                with lock:
                    found.append({"port": port, "service": service, "risk": risk, "note": note[:160]})
                time.sleep(0.1)

        threads = [threading.Thread(target=worker, daemon=True, name="scan") for _ in range(SCAN_PARALLEL)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(max(1, deadline - time.monotonic() + 5))
        out.update(ok=True, ports=sorted(found, key=lambda f: f["port"]), checked=len(table),
                   complete=not todo)
    except (OSError, ValueError, IndexError) as exc:
        out.update(ok=False, error=str(exc)[:200] or exc.__class__.__name__)
    out["seconds"] = round(time.time() - out["ts"], 1)
    log.info("Controllo di sicurezza (%s) di %s: %s", mode, req["host"],
             f"{len(out['ports'])} porte aperte" if out.get("ok") else "non riuscito: " + out.get("error", ""))
    return out


def scan_step():
    """Nel ciclo principale: avvia il controllo chiesto, raccoglie il risultato quando è pronto."""
    job = _scan_job[0]
    if job is None and _scan_req.get("id") and _scan_result[0] is None:
        req = dict(_scan_req)
        _scan_req.clear()
        _scan_done.add(req["id"])
        _scan_job[0] = Background(run_scan, req)
        _scan_job[0].name = "scan"
    elif job is not None and not job.is_alive():
        _scan_job[0] = None
        _scan_result[0] = job.value or {"id": job.args[0]["id"], "ok": False,
                                        "error": str(job.error or "non riuscito")[:200]}
    return _scan_result[0]


def scan_acked(ack):
    if ack and _scan_result[0] and ack == _scan_result[0].get("id"):
        _scan_result[0] = None


def main():
    try:
        cfg = load_config()
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise SystemExit(f"Configurazione non valida: {exc}")
    mtime = os.path.getmtime(CONFIG_PATH)
    client = Http()
    ping_ok = pinger.available()
    log.info("Sonda '%s' avviata: %d dispositivi, ogni %ss, ping %s",
             cfg["probe_name"], len(cfg["devices"]), cfg["interval"],
             "diretto (" + pinger.mode() + ")" if ping_ok else "con il comando ping")

    push_config = True   # al primo giro invio comunque la configurazione al server
    cycle = 0
    sampler = TrafficSampler()
    sampler.cfg = cfg
    sampler.start()
    last_contact = time.monotonic()      # ultimo scambio riuscito con il server
    last_down, last_ok_log, sent_once = None, 0.0, False
    server_ms = None          # durata dell'ultimo invio riuscito (ms): la pagina la mostra come latenza verso la VM

    fritz_job = None
    while True:
        start = time.monotonic()

        # Ricarica la configurazione se il file è stato modificato (es. dalla pagina web)
        try:
            new_mtime = os.path.getmtime(CONFIG_PATH)
            if new_mtime != mtime:
                mtime = new_mtime
                cfg = load_config()
                log.info("Configurazione ricaricata: %d dispositivi, ogni %ss",
                         len(cfg["devices"]), cfg["interval"])
        except (OSError, ValueError, yaml.YAMLError) as exc:
            log.error("Configurazione non valida, continuo con la precedente: %s", exc)

        sampler.cfg = cfg                 # il campionatore segue sempre la configurazione attuale
        devices = cfg["devices"]          # {nome: ip_o_hostname}
        # riepilogo FRITZ!Box in parallelo ai ping (se il precedente è ancora in corso, lo aspetto)
        fritz_job = Background(fritz_summaries, cfg) if fritz_job is None or not fritz_job.is_alive() else fritz_job
        cycle += 1
        results = run_pings(devices, cfg, cycle)
        down = [n for n, (ok, _) in results.items() if not ok]
        if down != last_down or start - last_ok_log >= LOG_OK_EVERY:
            log.info("OK %d/%d%s", len(results) - len(down), len(results),
                     f" — giù: {', '.join(down)}" if down else "")
            last_down, last_ok_log = down, start

        # speedtest chiesto dalla pagina: alla fine del ciclo dei ping, risultato con questo report
        speed = run_speedtest() if _speed_req else None
        scan = _safe(scan_step, None)      # controllo di sicurezza: gira in un thread a parte

        measured = {n: {"ok": ok, "host": str(devices[n]), "rtt": rtt} for n, (ok, rtt) in results.items()}
        record = {"ts": time.time(), "devices": measured}
        payload = {"probe": cfg["probe_name"], "interval": cfg["interval"],
                   "thresholds": thresholds(cfg), "config_rev": int(cfg["config_rev"]),
                   "devices": measured}
        if push_config:
            payload["config"] = shared_config(cfg)
        try:
            fritz, fritz_more = fritz_job.result(timeout=60)
        except Exception as exc:  # noqa: BLE001
            fritz, fritz_more = {"ok": False, "error": str(exc)[:200]}, []
        if fritz is not None:
            payload["fritz"] = fritz
        if fritz_more:
            payload["fritz_boxes"] = fritz_more    # gli altri FRITZ!Box (un server vecchio li ignora)
        payload["system"] = _safe(lambda: collect_system(cfg), None)
        if server_ms is not None and isinstance(payload["system"], dict):
            payload["system"]["server_ms"] = server_ms
        status_cmd = _safe(command_status, None)
        if status_cmd:
            payload["command_status"] = status_cmd
        if speed:
            payload["speedtest"] = speed
        if scan:
            payload["scan"] = scan
        traffic_by_box = sampler.take()
        traffic = traffic_by_box.pop("main", None)
        if traffic:
            payload["traffic"] = traffic
            record["traffic"] = traffic   # se l'invio fallisce finiscono nel buffer su disco
        if traffic_by_box:                # traffico degli altri FRITZ principali, per id
            payload["traffic_more"] = record["traffic_more"] = traffic_by_box

        try:
            flush_buffer(client, cfg)     # prima le misure in attesa, in ordine cronologico
            t_send = time.monotonic()
            reply = client.request("POST", cfg["server_url"], cfg["token"], payload, timeout=15) or {}
            if not isinstance(reply, dict):
                raise ValueError("risposta del server non valida")
            server_ms = round((time.monotonic() - t_send) * 1000)
            last_contact = time.monotonic()
            if not sent_once:
                sent_once = True
                log.info("Primo invio al server riuscito")
            command_acked(reply.get("command_ack"))
            handle_command(reply.get("command"), cfg)
            speedtest_requested(reply.get("speedtest"))
            scan_acked(reply.get("scan_ack"))
            scan_requested(reply.get("scan"))
            server_rev = int(reply.get("config_rev") or 0)
            if reply.get("config") and server_rev > int(cfg["config_rev"]):
                cfg = apply_remote_config(cfg, reply["config"], server_rev)
                mtime = os.path.getmtime(CONFIG_PATH)
                log.info("Configurazione aggiornata dal server (rev %d): %d dispositivi, ogni %ss",
                         server_rev, len(cfg["devices"]), cfg["interval"])
            if speed and reply.get("speedtest_ack") != speed["id"]:
                log.warning("Risultato dello speedtest non confermato dal server")
            # Se il server è indietro o non ha ancora la configurazione, gliela mando
            push_config = server_rev < int(cfg["config_rev"]) or not reply.get("has_config")
        except (OSError, ValueError) as exc:
            if isinstance(exc, ProbeMoved):
                follow_move(cfg, exc.url)
            else:
                log.error("Invio al server fallito: %s", exc)
            try:
                buffer_append(record)
            except OSError as buf_exc:
                log.error("Impossibile scrivere il buffer: %s", buf_exc)
        del payload, record, results, measured, traffic, traffic_by_box, speed, scan

        # Attesa fino al prossimo controllo. La risposta al report porta già configurazione e
        # comandi: il server viene interrogato a parte solo se è passato config_poll secondi
        # dall'ultimo scambio riuscito (con controllo ogni 60 s e config_poll 60, mai).
        deadline = start + cfg["interval"]
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            poll_every = int(cfg.get("config_poll") or 0)
            due = last_contact + poll_every - time.monotonic() if poll_every else left
            time.sleep(max(0.5, min(left, due)))
            if poll_every and time.monotonic() - last_contact >= poll_every \
                    and deadline - time.monotonic() > 2:
                try:
                    cfg, changed = poll_config(client, cfg)
                    last_contact = time.monotonic()
                    if changed:
                        mtime = os.path.getmtime(CONFIG_PATH)
                        break   # riparte subito con la nuova configurazione
                except (OSError, ValueError) as exc:
                    last_contact = time.monotonic()       # riprova al giro successivo, non subito
                    if isinstance(exc, ProbeMoved):
                        follow_move(cfg, exc.url)
                        break                             # riparte subito verso la VM nuova
                    log.error("Controllo configurazione fallito: %s", exc)


if __name__ == "__main__":
    main()
