"""Avvio della sonda netmon come add-on di Home Assistant.

Fa la parte di installa-sonda.sh e delle unità systemd: dalle opzioni dell'add-on scrive
config.yaml (indirizzo del server, token, nome), prepara la password della pagina locale e poi
tiene in vita la sonda (probe.py) con gli stessi riavvii di systemd (Restart=always, RestartSec=10).
La pagina locale (config_web.py) parte solo quando qualcuno la apre, come con netmon-config.socket
sul Raspberry: qui si tiene la porta in ascolto e alla prima connessione si avvia la pagina, che si
chiude da sola dopo IDLE_MINUTES senza richieste e da ferma non occupa memoria. Tutto quello che deve
restare tra un riavvio e l'altro sta in /data, la cartella persistente dell'add-on.

Senza sudo e systemd la sonda misura e invia come sul Raspberry: mancano solo riavvio,
aggiornamenti e reti Wi-Fi da remoto, che qui fa Home Assistant (la sonda lo segnala da sola al
server). Gli aggiornamenti di netmon arrivano come aggiornamenti dell'add-on.
"""
import ipaddress
import json
import os
import re
import secrets
import select
import signal
import socket
import subprocess
import sys
import time
from urllib.parse import urlsplit

import yaml

DATA = os.getenv("ADDON_DATA", "/data")
APP = os.path.dirname(os.path.abspath(__file__))
OPTIONS = os.path.join(DATA, "options.json")
CONFIG = os.path.join(DATA, "config.yaml")
WEB_ENV = os.path.join(DATA, "web.env")
APPLIED = os.path.join(DATA, "options-applied.json")
WEB_PORT = 8080
RESTART_SEC = 10
# pagina locale ferma dopo 10 minuti senza richieste, come sul Raspberry (ADDON_IDLE_MINUTES: per le prove)
IDLE_MINUTES = float(os.getenv("ADDON_IDLE_MINUTES", "10"))
# per il systemctl minimo del container (stato nella pagina locale); ADDON_PID: per le prove
PROBE_PID = os.getenv("ADDON_PID", "/run/netmon-probe.pid")
DEFAULT_NAME = "Home Assistant"
# Nomi della rete di casa, come LOCAL_SUFFIXES della sonda (probe.py, config_web.py)
LOCAL_SUFFIXES = (".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain", ".fritz.box")


def log(msg):
    print(f"[netmon] {msg}", flush=True)


def report_url(server):
    """Dominio o indirizzo scritto nelle opzioni → indirizzo dei report, come installa-sonda.sh:
    https se non si scrive esplicitamente http://."""
    s = server.strip()
    scheme = "http" if s.lower().startswith("http://") else "https"
    host = s.split("://", 1)[-1].split("/", 1)[0].strip()
    return f"{scheme}://{host}/api/report" if host else ""


def is_local_host(host):
    """Indirizzo della rete di casa (IP privato, localhost o nome locale): stessa regola della sonda."""
    host = (host or "").strip("[]").lower()
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return host == "localhost" or host.endswith(LOCAL_SUFFIXES)


def server_url_ok(url):
    """https:// sempre; http:// solo verso la rete di casa, altrimenti il token viaggerebbe in chiaro
    su Internet (la stessa regola di valid_server_url nella sonda)."""
    try:
        u = urlsplit(url)
        host = u.hostname
    except ValueError:
        return False
    return bool(host) and not u.username and (u.scheme == "https" or (u.scheme == "http" and is_local_host(host)))


def default_gateway():
    """IP del router (rotta predefinita), letto da /proc/net/route: con la rete dell'host è
    quello della casa."""
    try:
        with open("/proc/net/route", encoding="ascii") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) > 2 and parts[1] == "00000000" and parts[2] != "00000000":
                    return str(ipaddress.IPv4Address(bytes.fromhex(parts[2])[::-1]))
    except (OSError, ValueError):
        pass
    return None


def write_private(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def prepare_config(opts):
    """config.yaml in /data. Server, token e nome vengono dalle opzioni dell'add-on, ma solo quando
    cambiano lì: la sonda stessa li può cambiare (nome rinominato dalla pagina di stato, indirizzo
    nuovo quando l'utente viene spostato su un'altra VM) e un riavvio non deve annullarlo. Tutto il
    resto (dispositivi, FRITZ!Box, soglie) viene dalla pagina locale e dal server, come sul Raspberry."""
    wanted = {"server_url": report_url(str(opts.get("server") or "")),
              "token": str(opts.get("token") or "").strip(),
              "probe_name": str(opts.get("name") or "").strip()}
    if not wanted["server_url"] or not wanted["token"]:
        log("Manca l'indirizzo del server o il token della sonda: scrivili nella scheda "
            "Configurazione dell'add-on (il token si crea nella pagina di stato, Impostazioni → Sonde).")
        return False
    if not server_url_ok(wanted["server_url"]):
        log(f"Indirizzo del server non accettato ({wanted['server_url']}): con http:// il token viaggerebbe "
            "in chiaro su Internet. Scrivi solo il dominio (si usa https://); http:// va bene solo per un "
            "server nella rete di casa.")
        return False
    cfg = read_config()
    try:
        with open(APPLIED, encoding="utf-8") as f:
            applied = json.load(f)
    except (OSError, ValueError):
        applied = {}
    for key, value in wanted.items():
        if value and (value != applied.get(key) or not cfg.get(key)):
            cfg[key] = value
    cfg.setdefault("probe_name", DEFAULT_NAME)
    cfg.setdefault("language", "it")
    if not cfg.get("devices"):
        # probe.py non parte senza dispositivi: si comincia dal router, gli altri si aggiungono
        # dalla pagina locale o dalla pagina di stato del server
        gw = default_gateway()
        cfg["devices"] = {"router": gw or "192.168.1.1"}
        log(f"Primo avvio: controllo il router ({cfg['devices']['router']}). Aggiungi gli altri "
            "dispositivi dalla pagina locale o dalla pagina di stato.")
    write_private(CONFIG, "# netmon · scritto dall'add-on di Home Assistant — modificabile dalla "
                          "pagina locale (server e token: dalle opzioni dell'add-on)\n"
                  + yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False))
    write_private(APPLIED, json.dumps(wanted))
    return True


def read_config():
    """config.yaml di /data. Se è danneggiato (spegnimento durante una scrittura, backup rovinato) lo
    mette da parte e si riparte da capo, invece di fermare l'add-on a ogni avvio: dispositivi e
    impostazioni li rimanda il server alla prima risposta (configurazione con revisione più alta)."""
    try:
        with open(CONFIG, encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        if cfg is None or isinstance(cfg, dict):
            return cfg or {}
        err = "non è un elenco di impostazioni"
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, yaml.YAMLError) as exc:
        err = exc
    aside = f"{CONFIG}.danneggiato-{time.strftime('%Y%m%d-%H%M%S')}"
    try:
        os.replace(CONFIG, aside)
    except OSError:
        aside = "(non spostato)"
    log(f"config.yaml danneggiato ({err}): messo da parte in {aside}, riparto dalle opzioni dell'add-on. "
        "Dispositivi e impostazioni tornano dal server alla prima risposta.")
    return {}


def read_web_env():
    env = {}
    try:
        with open(WEB_ENV, encoding="utf-8") as f:
            for line in f.read().splitlines():
                k, sep, v = line.partition("=")
                if sep and k.strip() and not k.startswith("#"):
                    env[k.strip()] = v
    except FileNotFoundError:
        pass
    return env


def prepare_web_password(opts):
    """Password della pagina locale: quella delle opzioni se c'è (vince a ogni avvio), altrimenti
    quella già salvata (anche se cambiata dalla pagina), altrimenti una nuova, scritta nel registro."""
    env = read_web_env()
    chosen = str(opts.get("web_password") or "")
    if chosen:
        # come WEB_PW_BAD della pagina locale (più l'apice inverso): niente spazi né a capo, che
        # aggiungerebbero righe a web.env
        if len(chosen) < 12 or re.search(r"[\s\"'\\$`]", chosen):
            log("La password della pagina locale nelle opzioni non va bene (almeno 12 caratteri, senza "
                "spazi, virgolette, \\ e $): tengo quella di prima.")
        else:
            env["WEB_PASSWORD"] = chosen
    if not env.get("WEB_PASSWORD"):
        env["WEB_PASSWORD"] = secrets.token_urlsafe(12)
        log("=" * 64)
        log(f"Password della pagina locale della sonda: {env['WEB_PASSWORD']}")
        log("Salvala: si vede solo adesso. Si cambia dalla pagina locale o nelle opzioni.")
        log("=" * 64)
    write_private(WEB_ENV, "".join(f"{k}={v}\n" for k, v in env.items()))
    return env


def web_port(opts):
    """Porta della pagina locale: 8080 come sul Raspberry, o quella scelta nelle opzioni se è occupata."""
    try:
        port = int(opts.get("web_port") or WEB_PORT)
    except (TypeError, ValueError):
        port = WEB_PORT
    return port if 1024 <= port <= 65535 else WEB_PORT


def start_page(sock, env):
    """Avvia la pagina locale con la porta già aperta, come la passa systemd: descrittore 3,
    LISTEN_FDS=1 e LISTEN_PID uguale al pid della pagina (config_web.systemd_socket). La password si
    rilegge da web.env a ogni avvio: quella cambiata dalla pagina vale anche dopo che si è chiusa."""
    fd = sock.fileno()
    code = ("import os, sys; os.environ['LISTEN_PID'] = str(os.getpid()); os.environ['LISTEN_FDS'] = '1'; "
            f"sys.path.insert(0, {APP!r}); import config_web; config_web.main()")
    return subprocess.Popen([sys.executable, "-c", code], env={**env, **read_web_env()}, cwd=APP,
                            pass_fds=(fd,), preexec_fn=None if fd == 3 else (lambda: os.dup2(fd, 3)))


def main():
    # tutto quello che add-on, sonda e pagina scrivono in /data è leggibile solo dall'add-on
    # (come UMask=0077 delle unità systemd)
    os.umask(0o077)
    try:
        with open(OPTIONS, encoding="utf-8") as f:
            opts = json.load(f)
    except (OSError, ValueError):
        opts = {}
    os.makedirs(os.path.join(DATA, "state"), exist_ok=True)
    os.makedirs(os.path.join(DATA, "sys"), exist_ok=True)
    if not prepare_config(opts):
        # l'add-on resta acceso (senza far ripartire il container a vuoto) finché non si
        # configurano le opzioni: salvandole, Home Assistant lo riavvia
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        while True:
            time.sleep(3600)
    prepare_web_password(opts)
    port = web_port(opts)

    # la password della pagina non va alla sonda: la pagina la legge da web.env (start_page)
    env = {**os.environ,
           "PROBE_CONFIG": CONFIG,
           "PROBE_BUFFER": os.path.join(DATA, "buffer.jsonl"),
           "PROBE_STATE_DIR": os.path.join(DATA, "state"),
           "PROBE_SYS_DIR": os.path.join(DATA, "sys"),
           "WEB_ENV": WEB_ENV,
           "WEB_PORT": str(port),
           "IDLE_MINUTES": str(IDLE_MINUTES),
           "MALLOC_ARENA_MAX": "2",
           # la sonda è gestita da Home Assistant: aggiornamenti, riavvio, reti Wi-Fi e disinstallazione
           # li fa Home Assistant, e la sonda lo dice al server e nella pagina locale
           "NETMON_MANAGED_BY": "Home Assistant",
           "PYTHONUNBUFFERED": "1"}
    probe_cmd = [sys.executable, os.path.join(APP, "probe.py")]
    probe = page = sock = None
    probe_at = page_at = listen_at = 0.0
    stopping = []

    def stop(*_):
        stopping.append(True)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping:
        now = time.monotonic()
        if probe is not None and probe.poll() is not None:
            log(f"sonda: terminata (codice {probe.returncode}), riparte tra {RESTART_SEC} s")
            probe, probe_at = None, now + RESTART_SEC
        if probe is None and now >= probe_at:
            probe = subprocess.Popen(probe_cmd, env=env, cwd=APP)
            with open(PROBE_PID, "w", encoding="ascii") as f:
                f.write(str(probe.pid))
        if page is not None and page.poll() is not None:
            if page.returncode:            # chiusa da sola dopo IDLE_MINUTES: codice 0, nessun messaggio
                log(f"pagina locale: terminata (codice {page.returncode}), riparte tra {RESTART_SEC} s")
                page_at = now + RESTART_SEC
            page = None
        if sock is None and now >= listen_at:
            try:
                # porta tenuta aperta da qui, come netmon-config.socket sul Raspberry
                sock = socket.create_server(("0.0.0.0", port), backlog=64)
                log(f"Pagina locale su http://{socket.gethostname()}:{port} (o l'IP di Home Assistant): "
                    "parte alla prima visita")
            except OSError as exc:
                log(f"Porta {port} della pagina locale non disponibile ({exc}): riprovo tra un minuto. "
                    "Se un'altra app la usa, scegli un'altra porta nelle opzioni (web_port).")
                listen_at = now + 60
        # attesa: un secondo, o meno se qualcuno apre la pagina mentre è ferma
        ready = [sock] if sock is not None and page is None and now >= page_at else []
        try:
            readable = select.select(ready, [], [], 1.0)[0]
        except InterruptedError:
            readable = []
        if readable and not stopping:
            page = start_page(sock, env)
    procs = [p for p in (probe, page) if p is not None]
    for proc in procs:
        proc.terminate()
    for proc in procs:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
