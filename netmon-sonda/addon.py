"""Avvio della sonda netmon come add-on di Home Assistant.

Fa la parte di installa-sonda.sh e delle unità systemd: dalle opzioni dell'add-on scrive
config.yaml (indirizzo del server, token, nome), prepara la password della pagina locale e poi
tiene in vita i due programmi della sonda, probe.py e la pagina locale (config_web.py), con gli
stessi riavvii di systemd (Restart=always, RestartSec=10). Tutto quello che deve restare tra un
riavvio e l'altro sta in /data, la cartella persistente dell'add-on.

Senza sudo e systemd la sonda misura e invia come sul Raspberry: mancano solo riavvio,
aggiornamenti e reti Wi-Fi da remoto, che qui fa Home Assistant (la sonda lo segnala da sola al
server). Gli aggiornamenti di netmon arrivano come aggiornamenti dell'add-on.
"""
import ipaddress
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import time

import yaml

DATA = os.getenv("ADDON_DATA", "/data")
APP = os.path.dirname(os.path.abspath(__file__))
OPTIONS = os.path.join(DATA, "options.json")
CONFIG = os.path.join(DATA, "config.yaml")
WEB_ENV = os.path.join(DATA, "web.env")
APPLIED = os.path.join(DATA, "options-applied.json")
WEB_PORT = 8080
RESTART_SEC = 10
PROBE_PID = "/run/netmon-probe.pid"      # per il systemctl minimo del container (stato nella pagina locale)
DEFAULT_NAME = "Home Assistant"


def log(msg):
    print(f"[netmon] {msg}", flush=True)


def report_url(server):
    """Dominio o indirizzo scritto nelle opzioni → indirizzo dei report, come installa-sonda.sh:
    https se non si scrive esplicitamente http://."""
    s = server.strip()
    scheme = "http" if s.lower().startswith("http://") else "https"
    host = s.split("://", 1)[-1].split("/", 1)[0].strip()
    return f"{scheme}://{host}/api/report" if host else ""


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
    try:
        with open(CONFIG, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except FileNotFoundError:
        cfg = {}
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
        if len(chosen) < 12 or any(c in chosen for c in " \t\"'\\$`"):
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


def main():
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
    web = prepare_web_password(opts)
    port = web_port(opts)

    env = {**os.environ, **web,
           "PROBE_CONFIG": CONFIG,
           "PROBE_BUFFER": os.path.join(DATA, "buffer.jsonl"),
           "PROBE_STATE_DIR": os.path.join(DATA, "state"),
           "PROBE_SYS_DIR": os.path.join(DATA, "sys"),
           "WEB_ENV": WEB_ENV,
           "WEB_PORT": str(port),
           "MALLOC_ARENA_MAX": "2",
           "PYTHONUNBUFFERED": "1"}
    py = sys.executable
    programs = {
        "sonda": [py, os.path.join(APP, "probe.py")],
        "pagina locale": [py, "-c", f"import sys; sys.path.insert(0, {APP!r}); import config_web; config_web.main()"],
    }
    running, restart_at = {}, {name: 0.0 for name in programs}
    stopping = []

    def stop(*_):
        stopping.append(True)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    log(f"Pagina locale su http://{socket.gethostname()}:{port} (o l'IP di Home Assistant)")
    while not stopping:
        now = time.monotonic()
        for name, cmd in programs.items():
            proc = running.get(name)
            if proc is not None and proc.poll() is not None:
                log(f"{name}: terminata (codice {proc.returncode}), riparte tra {RESTART_SEC} s")
                running.pop(name)
                restart_at[name] = now + RESTART_SEC
            if name not in running and now >= restart_at[name]:
                running[name] = subprocess.Popen(cmd, env=env, cwd=APP)
                if name == "sonda":
                    with open(PROBE_PID, "w", encoding="ascii") as f:
                        f.write(str(running[name].pid))
        time.sleep(1)
    for proc in running.values():
        proc.terminate()
    for proc in running.values():
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
