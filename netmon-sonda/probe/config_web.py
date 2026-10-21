#!/usr/bin/env python3
"""Pagina web locale per modificare /etc/netprobe/config.yaml dal browser.

- Accetta connessioni solo da indirizzi privati (LAN) e da localhost, e solo se l'indirizzo
  scritto nel browser è l'IP della sonda o un suo nome locale (difesa dal DNS rebinding).
- Password obbligatoria (WEB_PASSWORD in /etc/netprobe/web.env): il browser la chiede al
  primo accesso. Senza password la pagina non si apre e spiega come impostarla. La password
  si cambia da questa pagina, sezione «Password della pagina».
- Il nome della sonda si cambia qui (sezione in cima) o dalla pagina di stato del server:
  i due lati si sincronizzano tramite la configurazione.
- Token del server e password del FRITZ!Box non vengono mai inviati alla pagina se non si
  preme "Mostra".
- La sonda rilegge da sola il file salvato al ciclo successivo: nessun riavvio.
- Con systemd parte solo quando qualcuno apre la pagina (netmon-config.socket) e si chiude da
  sola dopo IDLE_MINUTES minuti senza richieste: da ferma non occupa memoria.

Dipendenze: python3-yaml (già installato per la sonda).
"""
__version__ = "1.1.20261021-152315"
import base64
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit

import yaml

import sysops

CONFIG_PATH = os.getenv("PROBE_CONFIG", "/etc/netprobe/config.yaml")
PORT = int(os.getenv("WEB_PORT", "8080"))
PASSWORD = os.getenv("WEB_PASSWORD", "")
WEB_ENV = os.getenv("WEB_ENV", "/etc/netprobe/web.env")
# Caratteri che systemd non sa leggere in un file ambiente: la password deve evitarli
# (stessi divieti e stesso motivo di installa-sonda.sh).
WEB_PW_BAD = re.compile(r'[\s"\'\\$]')
# Nomi con cui si può aprire la pagina oltre all'IP (separati da virgola), per esempio sonda.casa
EXTRA_HOSTS = {h.strip().lower() for h in os.getenv("WEB_ALLOWED_HOSTS", "").split(",") if h.strip()}
# Suffissi dei nomi locali (mDNS, FRITZ!Box, router): non registrabili su Internet da un estraneo
LOCAL_SUFFIXES = (".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain", ".fritz.box")
SECRET_FIELDS = ("token", "fritz_password")
MASK = "••••••••"                 # al posto dei segreti nella pagina (finché non si preme "Mostra")
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                "style-src 'self' 'unsafe-inline'; "
                                "font-src 'self'; img-src 'self' data:; connect-src 'self'; "
                                "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
}
# Logo di netmon (copia di server/brand.py, generato da tools/genera-icone.py)
LOGO_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#174A72"/><path d="M32.00 12.00L49.32 22.00L49.32 42.00L32.00 52.00L14.68 42.00L14.68 22.00Z" fill="none" stroke="#FFFFFF" stroke-opacity=".45" stroke-width="1.8" stroke-linejoin="round"/><path d="M32 32L32.00 12.00M32 32L49.32 22.00M32 32L49.32 42.00M32 32L32.00 52.00M32 32L14.68 42.00M32 32L14.68 22.00" stroke="#FFFFFF" stroke-width="1.8" stroke-linecap="round"/><circle cx="32.00" cy="12.00" r="4" fill="#FFFFFF"/><circle cx="49.32" cy="22.00" r="4" fill="#FFFFFF"/><circle cx="49.32" cy="42.00" r="4" fill="#FFFFFF"/><circle cx="32.00" cy="52.00" r="4" fill="#FFFFFF"/><circle cx="14.68" cy="42.00" r="4" fill="#FFFFFF"/><circle cx="14.68" cy="22.00" r="4" fill="#FFFFFF"/><circle cx="32" cy="32" r="9.00" fill="#174A72"/><path d="M32.00 24.50L24.00 31.50L26.60 31.50L26.60 39.00L37.40 39.00L37.40 31.50L40.00 31.50Z" fill="#7FB8E0" stroke="#7FB8E0" stroke-width="1.50" stroke-linejoin="round"/></svg>'
FAVICON_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="12.5" fill="#174A72"/><path d="M32.00 9.00L51.92 20.50L51.92 43.50L32.00 55.00L12.08 43.50L12.08 20.50Z" fill="none" stroke="#FFFFFF" stroke-opacity=".45" stroke-width="3" stroke-linejoin="round"/><path d="M32 32L32.00 9.00M32 32L51.92 20.50M32 32L51.92 43.50M32 32L32.00 55.00M32 32L12.08 43.50M32 32L12.08 20.50" stroke="#FFFFFF" stroke-width="3" stroke-linecap="round"/><circle cx="32.00" cy="9.00" r="5.5" fill="#FFFFFF"/><circle cx="51.92" cy="20.50" r="5.5" fill="#FFFFFF"/><circle cx="51.92" cy="43.50" r="5.5" fill="#FFFFFF"/><circle cx="32.00" cy="55.00" r="5.5" fill="#FFFFFF"/><circle cx="12.08" cy="43.50" r="5.5" fill="#FFFFFF"/><circle cx="12.08" cy="20.50" r="5.5" fill="#FFFFFF"/><circle cx="32" cy="32" r="12.15" fill="#174A72"/><path d="M32.00 21.88L21.20 31.32L24.71 31.32L24.71 41.45L39.29 41.45L39.29 31.32L42.80 31.32Z" fill="#7FB8E0" stroke="#7FB8E0" stroke-width="2.03" stroke-linejoin="round"/></svg>'
# Icone PNG per i browser che non usano quella SVG (Safari chiede /favicon.ico e l'icona per la
# schermata Home): le stesse di server/brand.py.
FAVICON_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAFk0lEQVR4nKxXfUzUZRz//O4FBEU94O5QAUNAUTBJBRGjUAGFMJLp"
    "QN2yNnOWfxSaremaZZuz3JRaOttqxVrhZmnLdxEjXdgwlfIN8JVUkJdDeRG8g7tf3+/D7nZ3HNzvnJ/t7vd7nt/z/X6f5/v+aOAE"
    "w4L3MqBWraTXZAmYiGcIWZZrIUnnYLWVNB8vPmmfl/hPn7MhTCX37aQFhT7wREy4QTxv3GuGjyi1Qb2u5cj2BxoeqWRrMQkvUEo9"
    "JmQUfvxkFaZEjRXjq7cbsGLzN2g0tStlsYxkquhZqA5dWFSoUkmb4QM2vfEKsmbFO8Z6XRD8tRqU/31NORMJCQHRKbUatYQ18BGT"
    "o8YomvMGlq2SJcQpJZAkCYmxEf2O4/6Nfs/HhIs1iiFJz6lHxKZuV7I2MiwY2SkJiIkw4E5jK8bqRyN45HDxjZ3wtzP/YBzNxZJj"
    "Pux8jM7uJ96ZynKAZMxZJzvPsT0zkybD30+LsqqrglHatFiEG3Tos9pwobYe1dfvwmaTcXTnu4Imu+gLil4VppF2pk+KhEatQv0D"
    "Eyov3URQ4DBkJk+B2dKLsnPX0PKw02UPGucBq3ff1jWCiLHlrTyUllXh5v0W1P3XhL8u30K32eJY32Pudbxbbf2bq7nTiNlToxFL"
    "mpo7PQ7LspKh1ajFGj7M0o17xAHsUDlv4M3cOQ7hDCbkUx2ouIBT52tchA8GXsPRcOCPi0icGOEQzmDeLGNQDUQYgwcw1AUFotlJ"
    "bZTR+j2OvPejHyr4xWkODidsauvAaKJ1h7sMFw2crq4bQBBJBKVbViNqbGi/ILAsCTOSk5A2P4N+mUicmSTm7BvkDLn309WC1h3u"
    "MigKZn9sH5yvqUeAvxbR4wzCpuzZbPuFKfF4PTsVv5ApOrrNSM/IRFx8PDlbv3qNYUaMGq1D/Z3bGB8WgordG4iHHr+evogrtxoo"
    "gkLQ1WPG94crsaO0TDiwHQOigJGTOhXDKAr2k0AGx/fshAn49lAlFuTmwmA0UpT4w54QmIHFbEZzUxOOHTyIVYvm4Cw57L837onv"
    "+enTyWEtOHr2srsoVx8YDMyo7l4r8gsKMSIoCFqtFs7ZiF/9aEMGYxitKUDJ/v148kRBHoCbDwwGNn3ua4uhC9aBfcxTsuM5NcV/"
    "SEgosvPyIMtQBEUaYJSXHYdeb8SL6emDrmHblpefQFubCUqhaAN8uocmE2Tb0MdixbAftD9qU1wTFJmA0+v65QugFLyWHVcJXDTA"
    "WWvjyhwUZCTDT6vGvBlxIq/nvZQo6sDx8ze8MgzX61BUmIn3l2eJbGglumyKKktvH5KnRGFryRH09lk9b2Dtkrl4Oz/dMV4yb4Z4"
    "nqm+jg92/QxTdx9SaZNmCjlP4Oiob2pF2prP8PnaJSL8HAjwF7zbH/egeO9JzxvgYuSOmvoHWLppj3iXJBUOUojZMXJEgHh2dFHI"
    "SbJICF2dnejqkAUNJ6S48WEYSobLBtq7euAOVp2BSjTXA1m2obGhwfFt17Z3xDP/w90D6IzBIwWtO9xluDjhd4f+dGkk2FbVdXex"
    "mFTJ/hDo7wdv4DXzZ07G4pdfELTO9mbeLMMZLhrgOp26epvHhmRipBETKL87NyRcN+zw1JBwL/HlvvIhGxKPtcATuCVLTYgWJZa6"
    "aCzPmuVyL/jpRBVtyiZUzBXvfssjJWyhHh6TsoySRqi3hcz4yu1GYddVr6a5xDn3htyWlxyppMalFh2PldUBvi3RWaRqKATXelHh"
    "BmmLL9287+gZlIBlq+h+8jV8RC2FppI5b7DKtj2q1sM7fqddl/hC+NW+U+I6Zge/85wvYJmtx4orhDKDFq0PDbTKfK/y6gvOeOrL"
    "qSybui2WSZ3lu0wu1tTnFC0ku6ygBUnkmJPwDEGewc1glfv1/H8AAAD//1An9dAAAAAGSURBVAMAqlZFBHbmv1QAAAAASUVORK5C"
    "YII=")
TOUCH_PNG = base64.b64decode(
    "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")
AUTH_MAX_FAILS = 10               # password sbagliate da uno stesso IP prima di una pausa
AUTH_MAX_FAILS_ALL = 50           # da tutti gli IP insieme: cambiare IP non dà altri tentativi
AUTH_WINDOW = 15 * 60
_auth_fails: dict = {}
_auth_lock = threading.Lock()
IDLE_MINUTES = float(os.getenv("IDLE_MINUTES", "10"))   # solo con l'avvio su richiesta

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("config-web")

# Valori usati quando config.yaml non contiene ancora la voce (stessi della sonda)
DEFAULTS = {"config_rev": 0, "config_poll": 60, "traffic_interval": 30, "ping_parallel": 2, "fritz_enabled": False, "fritz_host": "",
            "fritz_user": "", "fritz_password": "", "fritz_more": [], "fritz_max": 4, "devices_max": 30, "interval": 60, "ping_count": 2, "ping_timeout": 1, "fail_threshold": 3,
            "alert_mode": "proporzionale", "stale_factor": 1.5, "offline_factor": 3,
            "stale_seconds": 90, "offline_seconds": 180}

NUMERIC_LABELS = {"config_poll": "Controllo configurazioni dal server",
                  "traffic_interval": "Campionamento del traffico",
                  "ping_parallel": "Ping contemporanei",
                  "interval": "Controllo ogni (secondi)",
                  "ping_count": "Pacchetti ping per controllo",
                  "ping_timeout": "Attesa per ogni pacchetto",
                  "fail_threshold": "Controlli falliti prima dell'alert",
                  "stale_factor": "Sonda in ritardo dopo (intervalli)",
                  "offline_factor": "Sonda irraggiungibile dopo (intervalli)",
                  "stale_seconds": "Sonda in ritardo dopo (secondi)",
                  "offline_seconds": "Sonda irraggiungibile dopo (secondi)"}

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,39}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
                     r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$")


def valid_host(h):
    try:
        ipaddress.ip_address(h)
        return "%" not in h                  # niente zona IPv6 (fe80::1%eth0): testo libero
    except ValueError:
        return bool(HOST_RE.match(h))


def is_local_host(host):
    """Indirizzo della rete locale (IP privato, localhost o nome locale)."""
    host = (host or "").strip("[]").lower()
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return host == "localhost" or host.endswith(LOCAL_SUFFIXES)


def server_url_ok(url):
    """https:// sempre; http:// solo verso un server della rete locale (il token viaggerebbe in chiaro)."""
    if not re.match(r"^https?://\S+$", url or ""):
        return False
    parts = urlsplit(url)
    return parts.scheme == "https" or is_local_host(parts.hostname or "")


def unmask(data, current, fields=SECRET_FIELDS):
    """La pagina rimanda il segnaposto se il segreto non è stato toccato: rimetto il valore vero."""
    data = dict(data)
    for k in fields:
        if str(data.get(k, "")) == MASK:
            data[k] = (current or {}).get(k, "")
    return data


def save_web_password(new):
    """Nuova password della pagina: riscrive WEB_PASSWORD in web.env senza toccare le altre righe
    (per esempio WEB_ALLOWED_HOSTS) e la aggiorna anche in memoria, così vale subito senza
    riavviare il servizio. Il file è della sonda (600): la cartella può invece essere di root,
    quindi si riscrive il file com'è invece di crearne uno nuovo."""
    global PASSWORD
    righe = []
    try:
        with open(WEB_ENV, encoding="utf-8") as f:
            righe = [r for r in f.read().splitlines() if not r.startswith("WEB_PASSWORD=")]
    except FileNotFoundError:
        pass
    righe.append("WEB_PASSWORD=" + new)
    with open(WEB_ENV, "w", encoding="utf-8") as f:
        f.write("\n".join(righe) + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(WEB_ENV, 0o600)
    PASSWORD = new
    with _auth_lock:
        _auth_fails.clear()      # i tentativi sbagliati di prima non bloccano chi ha appena cambiato


# Altri FRITZ!Box oltre al primo (ripetitori, secondo FRITZ in casa, FRITZ in un altro posto).
# Ognuno ha un id fisso: serve a ritrovare la sua password quando la pagina rimanda il segnaposto
# (le righe si possono togliere e aggiungere, la posizione non basta) e al server per tenere
# separati riquadri e traffico. Stessi limiti di probe.fritz_boxes().
FRITZ_MAX = 4
DEVICES_MAX = 30                     # dispositivi per sonda se il server non ha mandato un limite
FRITZ_ID_RE = re.compile(r"^[a-z0-9]{1,16}$")


def clean_fritz_more(raw, current, errors):
    """Controlla l'elenco degli altri FRITZ!Box arrivato dalla pagina."""
    cur = {b.get("id"): b for b in (current or {}).get("fritz_more") or [] if isinstance(b, dict)}
    items = raw if isinstance(raw, list) else []
    # Il limite lo decide l'amministratore sul server (fritz_max, con default FRITZ_MAX)
    # 0 è un valore vero (nessun FRITZ!Box oltre al primo), non «mancante»
    raw = (current or {}).get("fritz_max")
    lim = max(0, min(8, int(FRITZ_MAX if raw in (None, "") else raw)))
    if len(items) > lim:
        errors.append(f"Al massimo {lim} FRITZ!Box oltre al primo.")
        items = items[:lim]
    out, seen = [], set()
    for i, b in enumerate(items, start=2):
        if not isinstance(b, dict):
            continue
        name, host = str(b.get("name", "")).strip(), str(b.get("host", "")).strip()
        if not name and not host:
            continue                                   # riga lasciata vuota
        bid = str(b.get("id") or "")
        if not FRITZ_ID_RE.match(bid) or bid in seen or bid == "main":
            bid = secrets.token_hex(4)
        seen.add(bid)
        password = str(b.get("password", ""))
        if password == MASK:
            password = (cur.get(bid) or {}).get("password", "")
        label = f"FRITZ!Box {i}" + (f" «{name}»" if name else "")
        if not valid_host(host):
            errors.append(f"{label}: indica un indirizzo valido (es. 192.168.178.2).")
        if name and not NAME_RE.match(name):
            errors.append(f"{label}: nome non valido (lettere, numeri, spazi, punti o trattini, max 40).")
        out.append({"id": bid, "name": name, "host": host, "user": str(b.get("user", "")).strip(),
                    "password": password, "role": "main" if b.get("role") == "main" else "wifi"})
    return out


def read_config():
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return {**DEFAULTS, **(yaml.safe_load(f) or {})}


def validate(data, current=None):
    """Controlla i dati arrivati dalla pagina e restituisce (config, errori).

    I campi non presenti nella pagina (frequenza e soglie) mantengono il valore attuale.
    """
    errors = []
    base = {**DEFAULTS, **(current or {})}
    cfg = {
        "config_rev": int(base.get("config_rev") or 0) + 1,
        "server_url": str(data.get("server_url", "")).strip(),
        "token": str(data.get("token", "")).strip(),
        "probe_name": str(data.get("probe_name", "")).strip(),
        "alert_mode": str(data.get("alert_mode", base.get("alert_mode", "proporzionale"))).strip(),
        "fritz_enabled": bool(data.get("fritz_enabled", base.get("fritz_enabled", False))),
        "fritz_host": str(data.get("fritz_host", base.get("fritz_host", ""))).strip(),
        "fritz_user": str(data.get("fritz_user", base.get("fritz_user", ""))).strip(),
        "fritz_password": str(data.get("fritz_password", base.get("fritz_password", ""))),
        # Non è un campo della pagina: arriva dal server insieme alla configurazione
        "fritz_max": max(0, min(8, int(FRITZ_MAX if base.get("fritz_max") in (None, "") else base["fritz_max"]))),
        # Anche questo arriva dal server: quanti dispositivi può controllare la sonda
        "devices_max": max(1, min(200, int(base.get("devices_max") or DEVICES_MAX))),
        # lingua della pagina: si cambia con il selettore in alto (/api/language)
        "language": base.get("language") if base.get("language") in LANGS else "it",
    }
    if cfg["fritz_enabled"] and not valid_host(cfg["fritz_host"]):
        errors.append("Indica l'indirizzo del FRITZ!Box (es. 192.168.178.1).")
    cfg["fritz_more"] = clean_fritz_more(data.get("fritz_more", base.get("fritz_more")), base, errors)
    for key, label in NUMERIC_LABELS.items():
        raw = str(data.get(key, "")).strip()
        if raw == "":
            cfg[key] = base[key]              # campo assente nella pagina: valore attuale
            continue
        try:
            cfg[key] = float(raw) if key.endswith("_factor") else int(float(raw))
        except ValueError:
            errors.append(f"Campo «{label}»: '{raw}' non è un numero valido.")
            cfg[key] = base[key]

    if not server_url_ok(cfg["server_url"]):
        errors.append("L'indirizzo del server deve iniziare con https:// "
                      "(http:// solo per un server nella rete locale).")
    if not cfg["token"]:
        errors.append("Il token non può essere vuoto.")
    if not NAME_RE.match(cfg["probe_name"]):
        errors.append("Nome sonda: usa lettere, numeri, spazi, punti o trattini (max 40).")
    if cfg["config_poll"] != 0 and not 10 <= cfg["config_poll"] <= 3600:
        errors.append("Il controllo delle configurazioni deve essere 0 (disattivato) o tra 10 e 3600 secondi.")
    if cfg["traffic_interval"] != 0 and not 2 <= cfg["traffic_interval"] <= 300:
        errors.append("Il campionamento del traffico deve essere 0 (disattivato) o tra 2 e 300 secondi.")
    if not 1 <= cfg["ping_parallel"] <= 16:
        errors.append("I ping contemporanei devono essere tra 1 e 16.")
    if not 10 <= cfg["interval"] <= 3600:
        errors.append("L'intervallo deve essere tra 10 e 3600 secondi.")
    if not 1 <= cfg["ping_count"] <= 10:
        errors.append("I pacchetti ping per controllo devono essere tra 1 e 10.")
    if not 1 <= cfg["ping_timeout"] <= 10:
        errors.append("L'attesa per ogni pacchetto deve essere tra 1 e 10 secondi.")

    if cfg["alert_mode"] not in ("proporzionale", "fisso"):
        errors.append("Modalità degli alert non valida.")
    if not 1 <= cfg["fail_threshold"] <= 20:
        errors.append("I controlli falliti prima dell'alert devono essere tra 1 e 20.")
    if cfg["alert_mode"] == "proporzionale":
        if not 1 <= cfg["stale_factor"] <= 20 or not 1 <= cfg["offline_factor"] <= 20:
            errors.append("I moltiplicatori devono essere tra 1 e 20.")
        elif cfg["stale_factor"] > cfg["offline_factor"]:
            errors.append("La soglia «in ritardo» deve essere minore di quella «irraggiungibile».")
    else:
        if not 10 <= cfg["stale_seconds"] <= 86400 or not 10 <= cfg["offline_seconds"] <= 86400:
            errors.append("Le soglie fisse devono essere tra 10 e 86400 secondi.")
        elif cfg["stale_seconds"] > cfg["offline_seconds"]:
            errors.append("La soglia «in ritardo» deve essere minore di quella «irraggiungibile».")

    devices = {}
    for i, d in enumerate(data.get("devices") or [], start=1):
        name, host = str(d.get("name", "")).strip(), str(d.get("host", "")).strip()
        if not name and not host:
            continue
        if not NAME_RE.match(name):
            errors.append(f"Riga {i}: nome dispositivo non valido.")
        elif name in devices:
            errors.append(f"Riga {i}: il nome '{name}' è già usato.")
        if not valid_host(host):
            errors.append(f"Riga {i}: '{host}' non è un IP o un nome host valido.")
        devices[name] = host
    if not devices:
        errors.append("Aggiungi almeno un dispositivo.")
    # Oltre il limite dell'account no, ma solo se se ne aggiungono: se l'amministratore l'ha
    # abbassato, la sonda resta modificabile (togliere, rinominare) anche con qualcuno in più
    lim, prima = cfg["devices_max"], len(base.get("devices") or {})
    if len(devices) > lim and len(devices) > prima:
        errors.append(f"Al massimo {lim} dispositivi per questa sonda (limite dell'account).")
    cfg["devices"] = devices
    return cfg, errors


def write_config(cfg):
    """Scrittura atomica: la sonda non legge mai un file a metà."""
    text = "# Modificato dalla pagina web di configurazione\n" + \
        yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False, default_flow_style=False)
    folder = os.path.dirname(CONFIG_PATH)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".config-", suffix=".yaml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, 0o640)
        os.replace(tmp, CONFIG_PATH)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


# Campi della configurazione che il server conosce (uguali a SHARED in probe.py)
SHARED_KEYS = ("devices", "interval", "ping_count", "ping_timeout", "fail_threshold",
               "alert_mode", "stale_factor", "offline_factor", "stale_seconds", "offline_seconds",
               "traffic_interval", "ping_parallel", "probe_name", "fritz_max", "devices_max")


def backup_payload():
    """Backup completo della sonda, compresi token e credenziali del FRITZ!Box."""
    cfg = read_config()
    cfg.pop("config_rev", None)
    return {"netmon_backup": 1, "source": "sonda", "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "probe_name": cfg.get("probe_name"), "config": cfg}


def restore_config(backup, chosen=None):
    """Prepara la configurazione da un backup della sonda o del server.

    Restituisce (config, errori, scelta): se il backup del server contiene più sonde e non si
    capisce quale usare, `scelta` è l'elenco dei nomi tra cui scegliere."""
    if not isinstance(backup, dict) or backup.get("netmon_backup") != 1:
        return None, ["Il file non è un backup di netmon."], None
    try:
        current = read_config()
    except (OSError, yaml.YAMLError):
        current = dict(DEFAULTS)

    if backup.get("source") == "sonda":
        src = backup.get("config")
        if not isinstance(src, dict):
            return None, ["Il backup della sonda è vuoto o danneggiato."], None
        data = {**current, **src}
    elif backup.get("source") == "server":
        probes = backup.get("probes") or {}
        usable = {n: e for n, e in probes.items()
                  if isinstance(e, dict) and isinstance(e.get("config"), dict)}
        if not usable:
            return None, ["Il backup del server non contiene configurazioni di sonde."], None
        if chosen in usable:
            name = chosen
        elif current.get("probe_name") in usable:
            name = current["probe_name"]
        elif len(usable) == 1:
            name = next(iter(usable))
        else:
            return None, [], sorted(usable)
        entry = usable[name]
        src = entry["config"]
        # Il server non conosce indirizzo, token e FRITZ!Box: restano quelli attuali
        data = {**current, **{k: v for k, v in src.items() if k in SHARED_KEYS}}
        devices = src.get("devices") or {}
        order = [n for n in entry.get("order") or [] if n in devices]
        data["devices"] = {n: devices[n] for n in order + [n for n in devices if n not in order]}
    else:
        return None, ["Tipo di backup non riconosciuto."], None

    devices = data.get("devices")
    if not isinstance(devices, dict) or not devices:
        return None, ["Il backup non contiene dispositivi."], None
    page = {k: ("" if v is None else v) for k, v in data.items() if k != "devices"}
    page["devices"] = [{"name": str(k), "host": str(v)} for k, v in devices.items()]
    cfg, errors = validate(page, current)      # stessa validazione della pagina, revisione +1
    return cfg, errors, None


def ping(host):
    r = subprocess.run(["ping", "-n", "-c", "2", "-W", "1", host],
                       capture_output=True, text=True, timeout=10)
    m = re.search(r"= [\d.]+/([\d.]+)/", r.stdout)
    return r.returncode == 0, (float(m.group(1)) if m else None)


def probe_service_state():
    try:
        r = subprocess.run(["systemctl", "is-active", "netmon-probe"],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() or "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def test_fritz(host, user, password):
    """Prova il collegamento TR-064 e restituisce un piccolo riepilogo."""
    try:
        from fritzconnection import FritzConnection
        from fritzconnection.lib.fritzstatus import FritzStatus
    except ImportError:
        return {"ok": False, "error": "Libreria fritzconnection non installata sulla sonda"}
    try:
        kw = dict(address=host, user=user or None, password=password or None, timeout=8)
        try:   # stessa cache della sonda: sul Raspberry Pi Zero la prova è molto più rapida
            fc = FritzConnection(**kw, use_cache=True, cache_directory=sysops.STATE_DIR)
        except TypeError:          # fritzconnection precedente alla 1.10
            fc = FritzConnection(**kw)
        fs = FritzStatus(fc)
        info = {"model": fc.modelname, "firmware": fc.system_version}
        try:
            info["external_ip"] = fs.external_ip
            info["connected"] = fs.is_connected
        except Exception:  # noqa: BLE001
            pass
        return {"ok": True, **info}
    except Exception as exc:  # noqa: BLE001
        text = str(exc)
        if "401" in text or "nauthorized" in text:
            text = "Utente o password non accettati dal FRITZ!Box"
        elif "timed out" in text or "Connection refused" in text or "Max retries" in text:
            text = "FRITZ!Box non raggiungibile a questo indirizzo"
        return {"ok": False, "error": text[:200]}


def health_url(server_url):
    parts = urlsplit(server_url)
    return urlunsplit((parts.scheme, parts.netloc, "/health", "", ""))


ACTIVITY = {"last": time.monotonic(), "busy": 0}
_activity_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server_version = "netprobe-config"

    def handle(self):
        # conta le richieste in corso: la pagina non si chiude mentre qualcuno la sta usando
        with _activity_lock:
            ACTIVITY["busy"] += 1
        try:
            super().handle()
        finally:
            with _activity_lock:
                ACTIVITY["busy"] -= 1
                ACTIVITY["last"] = time.monotonic()

    def log_message(self, fmt, *args):
        log.info("%s %s", self.client_address[0], fmt % args)

    # --- controlli di accesso -------------------------------------------------
    def host_ok(self):
        """L'indirizzo scritto nel browser deve essere l'IP della sonda o un suo nome locale.
        Così un sito esterno non può far puntare un proprio nome alla sonda (DNS rebinding) e
        usare il browser di chi è in casa per leggere o cambiare la configurazione."""
        host = (self.headers.get("Host") or "").strip().lower()
        name = host[1:host.index("]")] if host.startswith("[") and "]" in host else host.rsplit(":", 1)[0]
        if not name:
            return False
        try:
            ipaddress.ip_address(name)
            return True
        except ValueError:
            pass
        me = socket.gethostname().lower()
        return name in ("localhost", me, me + ".local") or name in EXTRA_HOSTS or name.endswith(LOCAL_SUFFIXES)

    def _plain(self, code, text, extra=None):
        body = tr_plain(text, page_lang()).encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in {**SECURITY_HEADERS, **(extra or {})}.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def allowed(self):
        ip = ipaddress.ip_address(self.client_address[0])
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            self.send_json({"error": "Accesso consentito solo dalla rete locale."}, 403)
            return False
        if not self.host_ok():
            self._plain(403, "Apri la pagina con l'indirizzo IP della sonda, per esempio http://192.168.1.20:8080\n")
            return False
        if not PASSWORD:
            self._plain(503, "La pagina locale della sonda richiede una password, che non è impostata.\n"
                             "Sulla sonda lancia:  sudo bash probe/installa-sonda.sh --aggiorna\n"
                             "(genera la password e la mostra alla fine), oppure crea /etc/netprobe/web.env\n"
                             "con la riga WEB_PASSWORD=... come descritto nella guida.\n")
            return False
        who = str(ip)
        with _auth_lock:
            now = time.monotonic()
            for k in list(_auth_fails):
                kept = [t for t in _auth_fails[k] if now - t < AUTH_WINDOW]
                if kept:
                    _auth_fails[k] = kept
                else:
                    del _auth_fails[k]
            recent = _auth_fails.get(who, [])
            blocked = (len(recent) >= AUTH_MAX_FAILS
                       or sum(map(len, _auth_fails.values())) >= AUTH_MAX_FAILS_ALL)
        if blocked:
            self._plain(429, "Troppe password sbagliate: riprova tra qualche minuto.\n")
            return False
        header = self.headers.get("Authorization", "")
        ok = False
        if header.startswith("Basic "):
            try:
                _, _, pw = base64.b64decode(header[6:]).decode("utf-8").partition(":")
                ok = hmac.compare_digest(pw.encode("utf-8"), PASSWORD.encode("utf-8"))
            except (ValueError, UnicodeDecodeError, TypeError):
                ok = False
        if not ok:
            if header:                         # tentativo con una password: conta come errore
                with _auth_lock:
                    _auth_fails.setdefault(who, []).append(time.monotonic())
                time.sleep(1)
            self._plain(401, "Password richiesta.\n",
                        {"WWW-Authenticate": 'Basic realm="netprobe", charset="UTF-8"'})
            return False
        return True

    def origin_ok(self):
        """Richieste che cambiano qualcosa: solo dalla pagina stessa (niente siti esterni)."""
        origin = self.headers.get("Origin")
        if origin is None:
            return True                         # non partita da una pagina web (es. curl)
        return urlsplit(origin).netloc.lower() == (self.headers.get("Host") or "").lower()

    # --- risposte -------------------------------------------------------------
    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return None
        try:
            length = max(0, min(int(self.headers.get("Content-Length", 0)), 200_000))
        except ValueError:
            return None
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return None

    # --- rotte ----------------------------------------------------------------
    def do_GET(self):
        if not self.allowed():
            return
        if self.path in ("/", "/index.html"):
            body = PAGES[page_lang()].encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        elif self.path in ("/favicon.ico", "/favicon-32.png", "/apple-touch-icon.png"):
            body = TOUCH_PNG if self.path == "/apple-touch-icon.png" else FAVICON_PNG
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "private, max-age=86400")
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/fonts/") and self.path[7:] in FONTS:
            body = FONTS[self.path[7:]]
            self.send_response(200)
            self.send_header("Content-Type", "font/woff2")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "private, max-age=31536000, immutable")
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/system":
            st = sysops.upgrade_status()
            # aggiornamento di netmon: completo (pacchetto) o dei soli programmi, il più recente dei due
            su, zu = sysops.selfupdate_status(), sysops.zipupdate_status()
            zip_last = (zu.get("started") or 0) >= (su.get("started") or 0) and zu.get("state") != "none"
            nm = zu if zip_last else su
            nm_log = (sysops.zipupdate_log(6000) if zip_last else sysops.selfupdate_log(6000)) \
                if nm.get("state") != "none" else ""
            try:
                server_url = read_config().get("server_url", "")
            except (OSError, yaml.YAMLError):
                server_url = ""
            self.send_json({"can_reboot": sysops.can_sudo(sysops.REBOOT_CMD),
                            "upgrade": st, "log": sysops.upgrade_log(6000) if st.get("state") != "none" else "",
                            "selfupdate": nm, "self_log": nm_log,
                            "version": __version__,
                            "server_version": sysops.server_version(server_url, timeout=4) if server_url else None})
        elif self.path == "/api/backup":
            try:
                payload = backup_payload()
            except (OSError, yaml.YAMLError) as exc:
                return self.send_json({"error": f"Impossibile leggere la configurazione: {exc}"}, 500)
            name = re.sub(r"[^A-Za-z0-9_-]+", "-", str(payload.get("probe_name") or "sonda")).strip("-")
            body = json.dumps(payload, indent=2, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition",
                             f'attachment; filename="netmon-sonda-{name}-{time.strftime("%Y%m%d-%H%M")}.json"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/config":
            try:
                cfg = read_config()
            except (OSError, yaml.YAMLError) as exc:
                return self.send_json({"error": f"Impossibile leggere {CONFIG_PATH}: {exc}"}, 500)
            devices = [{"name": k, "host": str(v)} for k, v in (cfg.get("devices") or {}).items()]
            safe = {**cfg, "devices": devices, "service": probe_service_state()}
            for k in SECRET_FIELDS:            # mai in chiaro: la pagina li chiede con "Mostra"
                safe[k] = MASK if cfg.get(k) else ""
            safe["fritz_more"] = [{**b, "password": MASK if b.get("password") else ""}
                                  for b in cfg.get("fritz_more") or [] if isinstance(b, dict)]
            self.send_json(safe)
        else:
            self.send_json({"error": "Pagina non trovata"}, 404)

    def do_POST(self):
        if not self.allowed():
            return
        if not self.origin_ok():
            return self.send_json({"error": "Richiesta da un'altra pagina: rifiutata."}, 403)
        # Solo JSON: un modulo HTML di un altro sito non può inviarlo (difesa dalle richieste
        # contraffatte, insieme al controllo dell'origine qui sopra). Non togliere.
        data = self.read_json()
        if not isinstance(data, dict):
            return self.send_json({"error": "Richiesta non valida"}, 400)

        if self.path == "/api/reveal":
            field = str(data.get("field") or "")
            box_id = field.split(":", 1)[1] if field.startswith("fritz_more:") else None
            if field not in SECRET_FIELDS and not (box_id and FRITZ_ID_RE.match(box_id)):
                return self.send_json({"error": "Campo non valido"}, 400)
            try:
                cfg = read_config()
            except (OSError, yaml.YAMLError) as exc:
                return self.send_json({"error": f"Impossibile leggere la configurazione: {exc}"}, 500)
            if box_id:
                box = next((b for b in cfg.get("fritz_more") or [] if isinstance(b, dict) and b.get("id") == box_id), {})
                value = box.get("password", "")
            else:
                value = cfg.get(field, "")
            return self.send_json({"value": value or ""})

        if self.path == "/api/language":
            lang = str(data.get("lang") or "")
            if lang not in LANGS:
                return self.send_json({"error": "Lingua non valida"}, 400)
            try:
                cfg = read_config()
                if cfg.get("language") != lang:
                    cfg["language"] = lang
                    write_config(cfg)
            except (OSError, yaml.YAMLError) as exc:
                return self.send_json({"error": f"Impossibile scrivere {CONFIG_PATH}: {exc}"}, 500)
            return self.send_json({"ok": True, "lang": lang})

        if self.path == "/api/uninstall":
            # Toglie netmon dalla sonda: serve scrivere DISINSTALLA e rimettere la password della
            # pagina (chi trovasse la pagina aperta su un PC non può farlo con un clic)
            if str(data.get("confirm") or "") != "DISINSTALLA":
                return self.send_json({"ok": False, "message": "Per confermare scrivi DISINSTALLA."}, 422)
            pw = str(data.get("password") or "")
            if not PASSWORD or not hmac.compare_digest(pw.encode("utf-8"), PASSWORD.encode("utf-8")):
                time.sleep(1)
                return self.send_json({"ok": False, "message": "Password di accesso alla sonda non corretta."}, 403)
            ok, message = sysops.uninstall(delay=2)
            log.warning("Disinstallazione richiesta dalla pagina locale: %s", message)
            return self.send_json({"ok": ok, "message": message}, 200 if ok else 409)

        if self.path == "/api/system/reboot":
            ok, message = sysops.reboot(delay=3)
            log.warning("Riavvio richiesto dalla pagina locale: %s", message)
            return self.send_json({"ok": ok, "message": message}, 200 if ok else 409)
        # Gli aggiornamenti (netmon e sistema operativo) si comandano SOLO dal pannello di
        # amministrazione del server: da qui non si avviano. La sonda li esegue quando il server
        # glieli ordina (probe.handle_command), e questa pagina ne mostra solo stato e registro.

        if self.path == "/api/restore":
            cfg, errors, choose = restore_config(data.get("backup"), data.get("probe"))
            if choose:
                return self.send_json({"ok": False, "choose": choose})
            if errors:
                return self.send_json({"errors": errors}, 422)
            try:
                write_config(cfg)
            except OSError as exc:
                return self.send_json({"errors": [f"Salvataggio non riuscito: {exc}"]}, 500)
            log.info("Configurazione ripristinata da backup: %d dispositivi", len(cfg["devices"]))
            return self.send_json({"ok": True, "devices": len(cfg["devices"]),
                                   "source": data["backup"].get("source")})

        if self.path == "/api/password":
            # Cambio della password della pagina: stessi divieti dell'installazione
            new = str(data.get("password") or "")
            repeat = str(data.get("repeat") or "")
            if WEB_PW_BAD.search(new):
                return self.send_json({"errors": ["Senza spazi, virgolette, \\ e $ "
                                                  "(li interpreterebbe systemd)."]}, 422)
            if len(new) < 12:
                return self.send_json({"errors": ["La nuova password deve avere almeno 12 caratteri."]}, 422)
            if new != repeat:
                return self.send_json({"errors": ["Le due password non coincidono."]}, 422)
            try:
                save_web_password(new)
            except OSError as exc:
                return self.send_json({"errors": [f"Impossibile scrivere {WEB_ENV}: {exc}. "
                                                  "(Serve che il file sia della sonda: "
                                                  "sudo chown netprobe:netprobe " + WEB_ENV + ")"]}, 500)
            log.warning("Password della pagina locale cambiata")
            return self.send_json({"ok": True})

        if self.path == "/api/config":
            try:
                current = read_config()
            except (OSError, yaml.YAMLError):
                current = {}
            cfg, errors = validate(unmask(data, current), current)
            if errors:
                return self.send_json({"errors": errors}, 422)
            try:
                write_config(cfg)
            except OSError as exc:
                return self.send_json({"errors": [f"Salvataggio non riuscito: {exc}"]}, 500)
            log.info("Configurazione salvata: %d dispositivi", len(cfg["devices"]))
            self.send_json({"ok": True})

        elif self.path == "/api/ping":
            host = str(data.get("host", "")).strip()
            if not valid_host(host):
                return self.send_json({"ok": False, "error": "Indirizzo non valido"})
            try:
                ok, ms = ping(host)
            except (subprocess.TimeoutExpired, OSError):
                ok, ms = False, None
            self.send_json({"ok": ok, "ms": ms})

        elif self.path == "/api/test-fritz":
            host = str(data.get("fritz_host", "")).strip()
            if not valid_host(host):
                return self.send_json({"ok": False, "error": "Indirizzo non valido"})
            try:
                current = read_config()
            except (OSError, yaml.YAMLError):
                current = {}
            box_id = str(data.get("id") or "")
            if box_id and FRITZ_ID_RE.match(box_id):
                if str(data.get("fritz_password", "")) == MASK:
                    box = next((b for b in current.get("fritz_more") or []
                                if isinstance(b, dict) and b.get("id") == box_id), {})
                    data = {**data, "fritz_password": box.get("password", "")}
            else:
                data = unmask(data, current, ("fritz_password",))
            self.send_json(test_fritz(host, str(data.get("fritz_user", "")).strip(),
                                      str(data.get("fritz_password", ""))))

        elif self.path == "/api/test-server":
            url = str(data.get("server_url", "")).strip()
            if not re.match(r"^https?://\S+$", url):
                return self.send_json({"ok": False, "error": "Indirizzo non valido"})
            import urllib.error
            import urllib.request
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None                 # un redirect non porta la sonda altrove
            try:
                with urllib.request.build_opener(NoRedirect).open(health_url(url), timeout=8) as r:
                    ok = json.loads(r.read(10_000) or b"{}").get("ok") is True
                self.send_json({"ok": ok, "error": None if ok else "Risposta inattesa dal server"})
            except urllib.error.HTTPError as exc:
                self.send_json({"ok": False, "error": f"Risposta HTTP {exc.code}"})
            except (OSError, ValueError) as exc:
                self.send_json({"ok": False, "error": type(exc).__name__})
        else:
            self.send_json({"error": "Pagina non trovata"}, 404)


PAGE = r"""<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sonda di rete</title>
<link rel="icon" href="__NETMON_ICON__" type="image/svg+xml">
<link rel="icon" href="/favicon-32.png" sizes="32x32" type="image/png">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<meta name="theme-color" content="#0F3352">
<!--FONTS-->
<style>
:root{
  /* Tema «Oceano», lo stesso della pagina del server */
  --bg:#F0F4F8; --panel:#FFFFFF; --ink:#1C2430; --muted:#5A6878; --line:#D5DFE9;
  --field:#FFFFFF; --accent:#174A72; --accent-ink:#FFFFFF; --hover:#E2ECF5;
  --ok:#3E9A4A; --warn:#D99A06; --bad:#D1410C; --off:#B4BEC9;
  --sans:Roboto,system-ui,-apple-system,"Segoe UI",sans-serif;
  --mono:"Roboto Mono",ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace;
}
@media (prefers-color-scheme: dark){:root{
  color-scheme:dark;
  --bg:#11161C; --panel:#19212A; --ink:#E6ECF2; --muted:#9AA8B8; --line:#2C3846;
  --field:#1F2832; --accent:#6FA8DC; --accent-ink:#0B1622; --ok:#6CC070; --warn:#F2C04A;
  --bad:#FF7B47; --off:#4A5664; --hover:#22303E;
}}
*{box-sizing:border-box}
[hidden]{display:none !important}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 var(--sans)}
main{max-width:1230px;margin:0 auto;padding:18px 20px 110px}   /* come le pagine del server */
header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:24px;flex-wrap:wrap}
.headstart{display:flex;align-items:center;gap:12px;min-width:0}
.brandmark{display:flex;flex:none}
.brandmark svg{width:36px;height:36px;border-radius:8px}
@media (prefers-color-scheme: dark){.brandmark svg{box-shadow:0 0 0 1px var(--line)}}
h1{margin:0;font-size:2rem;font-weight:600;letter-spacing:-.01em;line-height:1.1;overflow-wrap:anywhere}
h1 .crumb{font-weight:300;color:var(--muted)}
/* Menu a sinistra con le sezioni, come nella pagina di stato e nel pannello del server: una
   sezione alla volta. Su schermo largo affianca il contenuto, su telefono ci passa sopra con un
   velo e si richiude da solo dopo la scelta. Tutto nel browser: alla sonda non costa niente. */
.sidenav{position:fixed;top:0;left:0;bottom:0;width:220px;z-index:40;overflow-y:auto;
  background:var(--panel);border-right:1px solid var(--line);padding:16px 10px;
  transform:translateX(-100%);transition:transform .18s ease;visibility:hidden}
body.nav-open .sidenav{transform:none;visibility:visible}
.sidenav .navhead{font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
  padding:4px 10px 10px;margin:0}
.navveil{position:fixed;inset:0;z-index:35;background:rgba(0,0,0,.35);border:0;border-radius:0;padding:0;display:none}
body.nav-open .navveil{display:block}
@media (min-width:900px){
  body.nav-open main{margin-left:220px}
  body.nav-open .bar{left:220px}
  body.nav-open .navveil{display:none}
  main{transition:margin-left .18s ease}
}
.navtoggle{flex:none;line-height:1;padding:6px 10px;font-size:1.1rem}
.pagetabs{display:flex;flex-direction:column;gap:2px;align-items:stretch}
.pagetabs button{border:0;background:transparent;padding:9px 12px;margin:0;width:100%;text-align:left;
  border-radius:8px;font-size:1rem;font-weight:500;line-height:1.3;color:var(--muted)}
.pagetabs button:hover{color:var(--ink);background:var(--hover)}
.pagetabs button[aria-selected=true]{color:var(--accent-ink);background:var(--accent);font-weight:600}
.pagetabs button.navdanger{margin-top:10px;padding-top:12px;border-top:1px solid var(--line);border-radius:0 0 8px 8px}
.svc{display:flex;align-items:center;gap:8px;font-size:.9rem;color:var(--muted);white-space:nowrap}
section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px;margin-bottom:18px}
h2{margin:0 0 4px;font-size:1.1rem;font-weight:600}
.hint{margin:0 0 16px;color:var(--muted);font-size:.9rem}
label{display:block;font-size:.85rem;color:var(--muted);margin-bottom:4px}
input{width:100%;font:inherit;color:var(--ink);background:var(--field);border:1px solid var(--line);
  border-radius:6px;padding:9px 11px;min-width:0}
input.mono{font-family:var(--mono);font-size:.95rem}
/* Pallini delle password tutti uguali; carattere monospaziato solo quando il contenuto è visibile */
input[type=password]{font-family:var(--sans) !important;font-size:1rem !important;letter-spacing:.06em}
input:focus-visible,button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
input[aria-invalid=true]{border-color:var(--bad)}
button{font:inherit;cursor:pointer;border-radius:9999px;border:1px solid var(--line);
  background:transparent;color:var(--ink);padding:8px 14px}
button:hover{border-color:var(--muted)}
button:disabled{opacity:.55;cursor:default}
.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink);font-weight:600;padding:10px 20px}

/* Pannello porte: la parte caratteristica della pagina */
.panel{border:1px solid var(--line);border-radius:8px;overflow:hidden;background:var(--field)}
.port{display:grid;grid-template-columns:1.6rem 16px minmax(0,1fr) minmax(0,1.2fr) auto 4.8em auto;
  align-items:center;gap:10px;padding:10px 12px;border-top:1px solid var(--line)}
.port:first-child{border-top:0}
.num{font-family:var(--mono);font-size:.8rem;color:var(--muted);text-align:right}
.port input{border-color:transparent;background:transparent;padding:6px 8px}
.port input:hover{border-color:var(--line)}
.port input:focus{border-color:var(--accent);background:var(--panel)}
.port .ms{font-family:var(--mono);font-size:.8rem;color:var(--muted);min-width:4.5em;text-align:right}
.del{border:0;color:var(--muted);font-size:1.2rem;line-height:1;padding:4px 8px}
.del:hover{color:var(--bad)}
.led{width:14px;height:14px;border-radius:50%;background:var(--off);justify-self:center;
  box-shadow:inset 0 0 0 2px rgba(0,0,0,.12)}
.led.ok{background:var(--ok);box-shadow:0 0 0 3px color-mix(in srgb,var(--ok) 25%,transparent)}
.led.bad{background:var(--bad);box-shadow:0 0 0 3px color-mix(in srgb,var(--bad) 25%,transparent)}
.led.busy{background:var(--warn);animation:blink .5s steps(2,start) infinite}
@keyframes blink{to{opacity:.25}}
@media (prefers-reduced-motion: reduce){.led.busy{animation:none}}
.panel-actions{display:flex;gap:10px;margin-top:12px;flex-wrap:wrap}

.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.row{display:flex;gap:10px;align-items:flex-end}
.row > div{flex:1;min-width:0}
.field{margin-bottom:14px}
.result{font-size:.9rem;margin-top:8px;min-height:1.4em}
.switch{display:flex;align-items:center;gap:10px;font-size:.95rem;color:var(--ink);margin:0 0 14px;cursor:pointer}
.switch input{width:20px;height:20px;accent-color:var(--accent);flex:none}
#fritz-fields[hidden]{display:none}
.subhead{font-size:1.05rem;margin:26px 0 4px}
.fbox{border:1px solid var(--line);border-radius:10px;padding:14px 14px 6px;margin:12px 0;background:var(--field)}
.fbox-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:0 14px;align-items:end}
.fbox .panel-actions{margin-top:4px}

/* Sezioni a tendina */
section > h2{display:flex;align-items:center;gap:6px}
/* Freccia dei registri a tendina: triangolo pieno, ruota verso il basso quando è aperto */
details.arrow > summary{list-style:none;display:flex;align-items:center;gap:8px}
details.arrow > summary::-webkit-details-marker{display:none}
details.arrow > summary::before{content:"\25B6";display:inline-block;font-size:.82rem;width:1em;
  text-align:center;transition:transform .25s ease}
details.arrow[open] > summary::before{transform:rotate(90deg)}
@media (prefers-reduced-motion: reduce){details.arrow > summary::before{transition:none}}

button.danger{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 45%,var(--line))}
button.danger:hover{border-color:var(--bad)}
#sys-log-box,#nm-log-box{margin-top:10px}
#sys-log-box summary,#nm-log-box summary{cursor:pointer;color:var(--muted);font-size:.9rem}
#sys-log,#nm-log{background:var(--field);border:1px solid var(--line);border-radius:6px;padding:10px;margin:8px 0 0;
  max-height:320px;overflow:auto;font-family:var(--mono);font-size:.78rem;white-space:pre-wrap;word-break:break-word}
select{font:inherit;color:var(--ink);background:var(--field);border:1px solid var(--line);
  border-radius:6px;padding:9px 11px;width:100%}

.note{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--accent);
  border-radius:8px;padding:12px 16px;color:var(--muted);font-size:.92rem}
.result.ok{color:var(--ok)} .result.bad{color:var(--bad)}
.hint.warn{color:var(--warn)}
.limits-note{border:1px dashed var(--line);border-radius:8px;padding:10px 14px;margin:14px 0 0;
  color:var(--muted);font-size:.9rem}
.limits-note p{margin:0 0 6px} .limits-note p:last-child{margin-bottom:0}
.limits-note b{color:var(--ink)} .limits-note .warn{color:var(--warn)}

.bar{position:fixed;left:0;right:0;bottom:0;background:var(--panel);border-top:1px solid var(--line);
  padding:12px 18px calc(12px + env(safe-area-inset-bottom,0px))}
.bar-in{max-width:1190px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;gap:14px}
#msg{font-size:.9rem;color:var(--muted)}
#msg.bad{color:var(--bad)} #msg.ok{color:var(--ok)}
.errors{margin:0;padding-left:18px}

@media (max-width:600px){
  main{padding:12px 10px 110px}
  h1{font-size:1.6rem}
  header{flex-direction:column;align-items:flex-start}
  .grid{grid-template-columns:1fr}
  .port{grid-template-columns:16px minmax(0,1fr) auto auto;grid-template-areas:"led name ms del" "led host test del";
    column-gap:8px;row-gap:2px;padding:8px 6px 8px 10px}
  .port input{padding:5px 4px}
  .port .test{padding:6px 10px}
  .del{padding:4px}
  .port .num{display:none}
  .port .led{grid-area:led}
  .port .name{grid-area:name} .port .host{grid-area:host}
  .port .test{grid-area:test} .port .ms{grid-area:ms}
  .port .del{grid-area:del}
}
.headend{display:flex;align-items:center;gap:10px;margin-left:auto}
select.pill{font:inherit;cursor:pointer;border-radius:9999px;border:1px solid var(--line);
  background:transparent url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M1 1l4 4 4-4' fill='none' stroke='%23888' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") no-repeat right 14px center;color:var(--ink);
  padding:8px 36px 8px 14px;width:auto;-webkit-appearance:none;appearance:none}
select.pill:hover{border-color:var(--muted)}
</style>
</head>
<body>
<button type="button" class="navveil" id="navveil" tabindex="-1" aria-hidden="true"></button>
<aside class="sidenav" id="sidenav">
  <p class="navhead">Sezioni</p>
  <nav class="pagetabs" id="pagetabs" aria-label="Sezioni"></nav>
</aside>
<main>
  <header>
    <div class="headstart">
      <button type="button" class="navtoggle" id="navtoggle" aria-controls="sidenav"
        aria-expanded="false" aria-label="Mostra o nascondi le sezioni" title="Sezioni">☰</button>
      <span class="brandmark" title="netmon">__NETMON_LOGO__</span>
      <h1><span class="crumb" id="title">Sonda di rete</span><span class="crumb"> › </span><span id="secname"></span></h1>
    </div>
    <div class="headend">
      <select id="lang-pick" class="pill" aria-label="Lingua della pagina">
        <option value="it" translate="no">Italiano</option><option value="en" translate="no">English</option>
        <option value="de" translate="no">Deutsch</option><option value="fr" translate="no">Français</option>
      </select>
      <div class="svc"><span class="led" id="svc-led"></span><span id="svc-text">Stato sonda…</span></div>
    </div>
  </header>

  <section aria-labelledby="h-name">
    <h2 id="h-name">Nome della sonda</h2>
    <p class="hint">È il nome che compare nella pagina di stato del server (Stato rete e
      Impostazioni → Sonde). Si può cambiare anche da lì: i due lati si sincronizzano
      da soli, al prossimo controllo. Salva con il pulsante in fondo.</p>
    <div class="field">
      <label for="probe_name">Nome</label>
      <input id="probe_name" autocomplete="off" maxlength="40" placeholder="es. Casa">
    </div>
  </section>

  <section aria-labelledby="h-srv">
    <h2 id="h-srv">Server</h2>
    <p class="hint">Il token deve coincidere con quello del server.</p>
    <div class="field">
      <label for="server_url">Indirizzo del server</label>
      <input id="server_url" class="mono" inputmode="url" autocomplete="off" spellcheck="false">
    </div>
    <div class="row">
      <div>
        <label for="token">Token</label>
        <input id="token" type="password" class="mono" autocomplete="off" spellcheck="false">
      </div>
      <button type="button" id="show-token">Mostra</button>
    </div>
    <div class="field" style="max-width:19rem;margin-top:14px">
      <label for="config_poll">Controllo configurazioni dal server (secondi)</label>
      <input id="config_poll" type="number" min="0" max="3600">
    </div>
    <p class="hint">0 = solo all'invio dei risultati.</p>
    <div class="panel-actions"><button type="button" id="test-server">Prova collegamento</button></div>
    <div class="result" id="server-result" role="status"></div>
  </section>

  <section aria-labelledby="h-fritz">
    <h2 id="h-fritz">FRITZ!Box</h2>
    <p class="hint">Facoltativo. Le credenziali restano sulla sonda.</p>
    <label class="switch"><input type="checkbox" id="fritz_enabled"> Collega il FRITZ!Box</label>
    <div id="fritz-fields">
      <div class="field">
        <label for="fritz_host">Indirizzo del FRITZ!Box</label>
        <input id="fritz_host" class="mono" placeholder="192.168.178.1" autocomplete="off" spellcheck="false">
      </div>
      <div class="field">
        <label for="fritz_user">Utente</label>
        <input id="fritz_user" autocomplete="off" spellcheck="false">
      </div>
      <div class="row">
        <div>
          <label for="fritz_password">Password</label>
          <input id="fritz_password" type="password" autocomplete="off">
        </div>
        <button type="button" id="show-fritz">Mostra</button>
      </div>
      <div class="panel-actions"><button type="button" id="test-fritz">Prova collegamento</button></div>
      <div class="result" id="fritz-result" role="status"></div>
    </div>

    <h3 class="subhead">Altri FRITZ!Box</h3>
    <p class="hint">Un ripetitore o un secondo FRITZ!Box nella stessa casa: <b>solo Wi-Fi</b>, cioè i client
      collegati alle sue reti. Oppure un FRITZ!Box in un altro posto che la sonda raggiunge, per esempio con la
      VPN tra i due FRITZ: <b>principale</b>, cioè Internet, traffico, ospiti e dispositivi.
      Al massimo <span id="fritz-max">4</span>.
      Si aggiungono solo da questa pagina: le password restano sulla sonda.</p>
    <div id="fritz-more"></div>
    <div class="panel-actions"><button type="button" id="fritz-add">Aggiungi FRITZ!Box</button></div>
    <template id="fritz-tpl">
      <div class="fbox">
        <div class="fbox-grid">
          <div class="field"><label>Nome</label>
            <input class="f-name" placeholder="ripetitore piano di sopra" autocomplete="off"></div>
          <div class="field"><label>Ruolo</label>
            <select class="f-role">
              <option value="wifi">Solo Wi-Fi (ripetitore)</option>
              <option value="main">Principale (Internet e traffico)</option>
            </select></div>
          <div class="field"><label>Indirizzo</label>
            <input class="f-host mono" placeholder="192.168.178.2" autocomplete="off" spellcheck="false"></div>
          <div class="field"><label>Utente</label>
            <input class="f-user" autocomplete="off" spellcheck="false"></div>
          <div class="field row">
            <div><label>Password</label><input class="f-pass" type="password" autocomplete="off"></div>
            <button type="button" class="f-show">Mostra</button>
          </div>
        </div>
        <div class="panel-actions">
          <button type="button" class="f-test">Prova collegamento</button>
          <button type="button" class="f-del danger">Rimuovi</button>
        </div>
        <div class="result f-result" role="status"></div>
      </div>
    </template>
  </section>

  <section aria-labelledby="h-dev">
    <h2 id="h-dev">Dispositivi</h2>
    <div class="panel" id="ports"></div>
    <div class="panel-actions">
      <button type="button" id="add">Aggiungi dispositivo</button>
      <button type="button" id="test-all">Prova tutti</button>
    </div>
    <div class="limits-note">
      <p><b>Limiti del tuo account</b> (li decide l'amministratore del server): questa sonda può avere fino a
        <b><span id="dev-max">30</span> dispositivi</b> e <b><span id="lim-fritz">4</span> FRITZ!Box aggiuntivi</b>
        (la parte che le resta del totale del tuo account, condiviso con le altre sonde).</p>
      <p><b>Se superi i limiti</b>: arrivato al massimo, «Aggiungi dispositivo» si disattiva e il salvataggio
        rifiuta le righe in più. Se il limite viene abbassato quando ne hai già di più, gli ultimi della
        lista (e i FRITZ!Box aggiuntivi oltre il limite) smettono di essere controllati e spariscono da
        questa pagina, ma restano salvati sul server: tornano da soli se il limite si alza o se ne togli
        qualcuno.</p>
      <p class="warn" id="limits-over" hidden></p>
    </div>
  </section>

  <section aria-labelledby="h-sys">
    <h2 id="h-sys">Sistema</h2>
    <p class="hint">Gli aggiornamenti si comandano dal pannello di amministrazione del server.</p>
    <p class="hint" id="sys-versions"></p>
    <div class="panel-actions">
      <button type="button" id="sys-reboot" class="danger">Riavvia la sonda</button>
    </div>
    <div class="result" id="nm-result" role="status"></div>
    <details id="nm-log-box" class="arrow" hidden>
      <summary>Registro dell'ultimo aggiornamento di netmon (comandato dal server)</summary>
      <pre id="nm-log"></pre>
    </details>
    <div class="result" id="sys-result" role="status"></div>
    <details id="sys-log-box" class="arrow" hidden>
      <summary>Registro dell'ultimo aggiornamento di sistema (comandato dal server)</summary>
      <pre id="sys-log"></pre>
    </details>
  </section>

  <section aria-labelledby="h-pw">
    <h2 id="h-pw">Password di accesso alla sonda</h2>
    <p class="hint">È la password che il browser chiede quando apri la pagina della sonda: la stessa
      scelta all'installazione. Cambiandola qui non serve riavviare nulla: al prossimo
      aggiornamento della pagina il browser chiederà quella nuova (almeno 8 caratteri, senza
      spazi, virgolette, \ e $ — li legge systemd).</p>
    <div class="row">
      <div>
        <label for="pw-new">Nuova password</label>
        <input id="pw-new" type="password" autocomplete="new-password">
      </div>
      <div>
        <label for="pw-repeat">Ripeti la password</label>
        <input id="pw-repeat" type="password" autocomplete="new-password">
      </div>
      <button type="button" id="pw-go">Cambia password</button>
    </div>
    <div class="result" id="pw-result" role="status"></div>
  </section>

  <section aria-labelledby="h-bak">
    <h2 id="h-bak">Backup e ripristino</h2>
    <p class="hint">Contiene token e password del FRITZ!Box: tienilo al sicuro. Si può ripristinare anche
      un backup del server (solo dispositivi e impostazioni).</p>
    <div class="panel-actions">
      <button type="button" id="bak-download">Scarica backup</button>
      <button type="button" id="bak-restore">Ripristina da file…</button>
      <input type="file" id="bak-file" accept=".json,application/json" hidden>
    </div>
    <div class="row" id="bak-choose" hidden style="margin-top:12px">
      <div>
        <label for="bak-probe">Il backup contiene più sonde: quale ripristinare?</label>
        <select id="bak-probe"></select>
      </div>
      <button type="button" id="bak-go">Ripristina</button>
    </div>
    <div class="result" id="bak-result" role="status"></div>
  </section>

  <section aria-labelledby="h-del">
    <h2 id="h-del">Disinstalla sonda</h2>
    <p class="hint">Toglie netmon da questa sonda: servizi, programmi, configurazione (token e password),
      dati, script di sistema, permessi e utente <code>netprobe</code>. Restano i pacchetti di sistema e le reti
      Wi-Fi salvate. Una copia della configurazione resta in <code>/root</code> sulla sonda (solo root può
      leggerla); per averla qui, prima usa <b>Scarica backup</b>.
      Questa pagina smette di funzionare subito dopo. Sul server la sonda resta nel tuo account: toglila da
      <i>Impostazioni → Sonde → Elimina</i>.</p>
    <div class="row">
      <div>
        <label for="del-confirm">Per confermare scrivi DISINSTALLA</label>
        <input id="del-confirm" autocomplete="off" spellcheck="false" placeholder="DISINSTALLA">
      </div>
      <div>
        <label for="del-pass">Password di accesso alla sonda</label>
        <input id="del-pass" type="password" autocomplete="current-password">
      </div>
      <button type="button" id="del-go" class="danger">Disinstalla la sonda</button>
    </div>
    <div class="result" id="del-result" role="status"></div>
  </section>

  <p class="note">Frequenze, soglie e notifiche si impostano dalla pagina di stato del server (Impostazioni).</p>
<p style="margin:18px 0 0;color:var(--muted);font-size:.78rem;font-family:monospace">netmon __NETMON_VERSION__</p>
<p id="privacy-foot" style="margin:6px 0 0;font-size:.78rem" hidden><a id="privacy-link" style="color:var(--muted)" target="_blank" rel="noopener noreferrer">Informativa sulla privacy</a></p>
</main>

<div class="bar">
  <div class="bar-in">
    <div id="msg" role="status">Caricamento…</div>
    <button type="button" class="primary" id="save" disabled>Salva modifiche</button>
  </div>
</div>

<template id="port-tpl">
  <div class="port">
    <span class="num"></span>
    <span class="led"></span>
    <input class="name" aria-label="Nome dispositivo" placeholder="nome" autocomplete="off">
    <input class="host mono" aria-label="Indirizzo IP o nome host" placeholder="192.168.1.10" autocomplete="off" spellcheck="false">
    <button type="button" class="test">Prova</button>
    <span class="ms"></span>
    <button type="button" class="del" aria-label="Rimuovi dispositivo" title="Rimuovi">×</button>
  </div>
</template>

<script>
const $ = s => document.querySelector(s);
const ports = $("#ports"), tpl = $("#port-tpl"), msg = $("#msg"), saveBtn = $("#save");
const FIELDS = ["probe_name", "server_url", "token", "config_poll",
                "fritz_host", "fritz_user", "fritz_password"];
let dirty = false;

function setMsg(text, cls = "") { msg.className = cls; msg.textContent = text; }
function markDirty() { dirty = true; saveBtn.disabled = false; setMsg("Modifiche non salvate"); }

let DEV_MAX = 30;                 // limite dell'account, arriva dal server con la configurazione
function renumber() {
  const rows = ports.querySelectorAll(".port");
  rows.forEach((p, i) => p.querySelector(".num").textContent = String(i + 1).padStart(2, "0"));
  $("#add").disabled = rows.length >= DEV_MAX;
  const over = rows.length - DEV_MAX, w = $("#limits-over");
  w.hidden = over <= 0;
  if (over > 0) w.textContent = `Ora ne hai ${rows.length}: ${over === 1 ? "l'ultimo della lista non viene controllato"
    : "gli ultimi " + over + " della lista non vengono controllati"}.`;
}

function addPort(name = "", host = "") {
  const node = tpl.content.firstElementChild.cloneNode(true);
  node.querySelector(".name").value = name;
  node.querySelector(".host").value = host;
  node.querySelector(".test").onclick = () => testPort(node);
  node.querySelector(".del").onclick = () => { node.remove(); renumber(); markDirty(); };
  node.querySelectorAll("input").forEach(i => i.addEventListener("input", () => {
    node.querySelector(".led").className = "led"; node.querySelector(".ms").textContent = "";
  }));
  ports.appendChild(node);
  renumber();
  return node;
}

async function api(path, body) {
  const r = await fetch(path, body === undefined ? {} :
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await r.json().catch(() => ({}));
  return { status: r.status, data };
}

async function testPort(node) {
  const host = node.querySelector(".host").value.trim();
  const led = node.querySelector(".led"), ms = node.querySelector(".ms");
  if (!host) return;
  led.className = "led busy"; ms.textContent = "";
  const { data } = await api("/api/ping", { host });
  led.className = "led " + (data.ok ? "ok" : "bad");
  ms.textContent = data.ok ? (data.ms != null ? data.ms.toFixed(1) + " ms" : "ok") : (data.error ? "errore" : "timeout");
}

// Informativa sulla privacy: sta sul server a cui la sonda invia i dati
function privacyLink(server) {
  let u = null;
  try { u = new URL("/privacy", server); } catch {}
  const ok = u && /^https?:$/.test(u.protocol);
  if (ok) { u.searchParams.set("lang", I18N.lang || "it"); $("#privacy-link").href = u.href; }
  $("#privacy-foot").hidden = !ok;
}

async function load() {
  const { status, data } = await api("/api/config");
  if (status !== 200) { setMsg(data.error || "Impossibile leggere la configurazione", "bad"); return; }
  FIELDS.forEach(f => $("#" + f).value = data[f] ?? "");
  privacyLink(data.server_url);
  $("#fritz_enabled").checked = !!data.fritz_enabled;
  $("#fritz-fields").hidden = !data.fritz_enabled;
  fmore.innerHTML = "";
  (data.fritz_more || []).forEach(b => addFritz(b));
  FRITZ_MAX = Number(data.fritz_max ?? 4);
  $("#fritz-max").textContent = FRITZ_MAX;
  syncFritzAdd();
  DEV_MAX = Number(data.devices_max ?? 30);
  $("#dev-max").textContent = DEV_MAX;
  $("#lim-fritz").textContent = Number(data.fritz_max ?? 4);
  ports.innerHTML = "";
  (data.devices.length ? data.devices : [{ name: "", host: "" }]).forEach(d => addPort(d.name, d.host));
  document.title = (data.probe_name || "Sonda") + " · configurazione";
  $("#title").textContent = "Sonda " + (data.probe_name || "di rete");
  const svc = data.service;
  $("#svc-led").className = "led " + (svc === "active" ? "ok" : svc === "unknown" ? "" : "bad");
  $("#svc-text").textContent = svc === "active" ? "Sonda in funzione"
    : svc === "unknown" ? "Stato sonda non disponibile" : "Sonda ferma (" + svc + ")";
  dirty = false; saveBtn.disabled = true; setMsg("Configurazione caricata");
}

async function save() {
  const body = Object.fromEntries(FIELDS.map(f => [f, $("#" + f).value]));
  body.fritz_enabled = $("#fritz_enabled").checked;
  body.fritz_more = fritzMore();
  body.devices = [...ports.querySelectorAll(".port")].map(p => ({
    name: p.querySelector(".name").value, host: p.querySelector(".host").value }));
  saveBtn.disabled = true; setMsg("Salvataggio…");
  const { status, data } = await api("/api/config", body);
  if (status === 200) {
    dirty = false;
    setMsg("Salvato. La sonda lo userà dal prossimo controllo.", "ok");
    $("#title").textContent = "Sonda " + body.probe_name;
  } else {
    saveBtn.disabled = false;
    msg.className = "bad";
    msg.innerHTML = "";
    const ul = document.createElement("ul"); ul.className = "errors";
    (data.errors || ["Salvataggio non riuscito"]).forEach(e => { const li = document.createElement("li"); li.textContent = e; ul.appendChild(li); });
    msg.appendChild(ul);
  }
}

$("#add").onclick = () => { addPort().querySelector(".name").focus(); markDirty(); };
$("#test-all").onclick = () => ports.querySelectorAll(".port").forEach(testPort);
// I segreti arrivano mascherati: "Mostra" chiede il valore vero solo quando serve
const MASK = "••••••••";
async function reveal(id) {
  const t = $("#" + id);
  if (t.value !== MASK) return;
  const { status, data } = await api("/api/reveal", { field: id });
  if (status === 200) t.value = data.value || "";
}
$("#show-token").onclick = async e => {
  const t = $("#token"), show = t.type === "password";
  if (show) await reveal("token");
  t.type = show ? "text" : "password"; e.target.textContent = show ? "Nascondi" : "Mostra";
};
$("#fritz_enabled").onchange = e => { $("#fritz-fields").hidden = !e.target.checked; markDirty(); };
$("#show-fritz").onclick = async e => {
  const t = $("#fritz_password"), show = t.type === "password";
  if (show) await reveal("fritz_password");
  t.type = show ? "text" : "password"; e.target.textContent = show ? "Nascondi" : "Mostra";
};
$("#test-fritz").onclick = async () => {
  const out = $("#fritz-result");
  out.className = "result"; out.textContent = "Collegamento in corso…";
  const { data } = await api("/api/test-fritz", {
    fritz_host: $("#fritz_host").value, fritz_user: $("#fritz_user").value,
    fritz_password: $("#fritz_password").value });
  out.className = "result " + (data.ok ? "ok" : "bad");
  out.textContent = data.ok
    ? `Collegato: ${data.model || "FRITZ!Box"}${data.firmware ? " · FRITZ!OS " + data.firmware : ""}`
      + (data.external_ip ? ` · IP pubblico ${data.external_ip}` : "")
    : "Collegamento non riuscito: " + (data.error || "errore sconosciuto");
};

// ---- altri FRITZ!Box ----
const fmore = $("#fritz-more"), ftpl = $("#fritz-tpl");
// Quante FRITZ!Box oltre al primo si possono collegare: lo decide l'amministratore
// (arriva con la configurazione, vedi fritz_max), 4 è il valore di ripiego.
let FRITZ_MAX = 4;
let fseq = 0;
// id fisso scelto qui: la sonda e il server lo usano per tenere separati riquadri e traffico
const newFritzId = () => [...crypto.getRandomValues(new Uint8Array(4))].map(b => b.toString(16).padStart(2, "0")).join("");
function syncFritzAdd() { $("#fritz-add").disabled = fmore.children.length >= FRITZ_MAX; }
function addFritz(b = {}) {
  const node = ftpl.content.firstElementChild.cloneNode(true);
  const q = c => node.querySelector(c);
  node.dataset.id = b.id || newFritzId();
  q(".f-name").value = b.name || ""; q(".f-host").value = b.host || "";
  q(".f-user").value = b.user || ""; q(".f-pass").value = b.password || "";
  q(".f-role").value = b.role === "main" ? "main" : "wifi";
  node.querySelectorAll("label").forEach(l => {
    const inp = l.parentElement.querySelector("input,select");
    if (inp) { inp.id = "fm" + (++fseq); l.htmlFor = inp.id; }
  });
  q(".f-role").onchange = markDirty;
  q(".f-del").onclick = () => { node.remove(); syncFritzAdd(); markDirty(); };
  q(".f-show").onclick = async e => {
    const t = q(".f-pass"), show = t.type === "password";
    if (show && t.value === MASK) {
      const { status, data } = await api("/api/reveal", { field: "fritz_more:" + node.dataset.id });
      if (status === 200) t.value = data.value || "";
    }
    t.type = show ? "text" : "password"; e.target.textContent = show ? "Nascondi" : "Mostra";
  };
  q(".f-test").onclick = async () => {
    const out = q(".f-result");
    out.className = "result f-result"; out.textContent = "Collegamento in corso…";
    const { data } = await api("/api/test-fritz", {
      id: node.dataset.id, fritz_host: q(".f-host").value, fritz_user: q(".f-user").value,
      fritz_password: q(".f-pass").value });
    out.className = "result f-result " + (data.ok ? "ok" : "bad");
    out.textContent = data.ok
      ? `Collegato: ${data.model || "FRITZ!Box"}${data.firmware ? " · FRITZ!OS " + data.firmware : ""}`
        + (q(".f-role").value === "main" && data.external_ip ? ` · IP pubblico ${data.external_ip}` : "")
      : "Collegamento non riuscito: " + (data.error || "errore sconosciuto");
  };
  fmore.appendChild(node);
  syncFritzAdd();
  return node;
}
function fritzMore() {
  return [...fmore.querySelectorAll(".fbox")].map(n => ({
    id: n.dataset.id, name: n.querySelector(".f-name").value, host: n.querySelector(".f-host").value,
    user: n.querySelector(".f-user").value, password: n.querySelector(".f-pass").value,
    role: n.querySelector(".f-role").value }));
}
$("#fritz-add").onclick = () => { addFritz().querySelector(".f-name").focus(); markDirty(); };

// ---- password della pagina ----
$("#pw-go").onclick = async () => {
  const out = $("#pw-result");
  out.className = "result"; out.textContent = "Salvataggio in corso…";
  const { status, data } = await api("/api/password",
    { password: $("#pw-new").value, repeat: $("#pw-repeat").value });
  if (status === 200) {
    $("#pw-new").value = ""; $("#pw-repeat").value = "";
    out.className = "result ok";
    out.textContent = "Password aggiornata: al prossimo aggiornamento della pagina il browser "
      + "chiederà quella nuova.";
  } else {
    out.className = "result bad";
    out.textContent = (data.errors || [data.error || "Cambio password non riuscito"]).join(" ");
  }
};

// ---- sistema: riavvio, piu' la SOLA LETTURA degli aggiornamenti comandati dal server ----
let sysTimer = null;
function sysResult(text, cls) { const o = $("#sys-result"); o.className = "result " + (cls || ""); o.textContent = text; }
const hhmm = ts => ts ? new Date(ts * 1000).toLocaleString(I18N.locale, { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }) : "";

function nmResult(text, cls) { const o = $("#nm-result"); o.className = "result " + (cls || ""); o.textContent = text; }
function showLog(box, pre, text) {
  box.hidden = !text;
  if (!text) return;
  const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 20;
  pre.textContent = text;
  if (atBottom) pre.scrollTop = pre.scrollHeight;
}
let nmWatching = false, nmStartedVersion = null;

async function loadSystem() {
  let status, data;
  try { ({ status, data } = await api("/api/system")); }
  catch { status = 0; }
  if (status !== 200) {                 // la pagina si sta riavviando durante l'aggiornamento
    if (nmWatching) { clearTimeout(sysTimer); sysTimer = setTimeout(loadSystem, 3000); }
    return;
  }
  const up = data.upgrade || {}, su = data.selfupdate || {};
  const nmRunning = su.state === "running", running = up.state === "running" || nmRunning;
  $("#sys-versions").textContent = "Versione installata: " + (data.version || "?")
    + " · sul server: " + (data.server_version || "non disponibile");
  // L'aggiornamento non parte piu' da qui, ma quando il server lo comanda la sonda si riavvia:
  // ci si mette in ascolto da soli, cosi' a fine aggiornamento la pagina si ricarica ed e' quella
  // della versione nuova invece di restare quella vecchia a video.
  if (nmRunning && !nmWatching) { nmWatching = true; nmStartedVersion = data.version || null; }
  if (nmRunning) {
    nmResult(`Aggiornamento di netmon in corso dal ${hhmm(su.started)}… la sonda si riavvierà.`, "");
  } else if (su.state === "ok") {
    nmResult(`netmon aggiornato il ${hhmm(su.finished)} alla versione ${su.version || data.version}.`, "ok");
  } else if (su.state === "error") {
    nmResult(`Ultimo aggiornamento di netmon non riuscito${su.finished ? " il " + hhmm(su.finished) : ""}: controlla il registro.`, "bad");
  } else {
    nmResult("", "");
  }
  showLog($("#nm-log-box"), $("#nm-log"), data.self_log);
  if (nmRunning) $("#nm-log-box").open = true;
  // a fine aggiornamento ricarica la pagina, che ora è quella della nuova versione
  if (nmWatching && !nmRunning && su.state !== "none") {
    nmWatching = false;
    if (data.version !== nmStartedVersion) return location.reload();
  }
  $("#sys-reboot").disabled = running || !data.can_reboot;
  if (!data.can_reboot) {
    sysResult("Permessi non configurati: installa /etc/sudoers.d/netprobe come descritto nella guida.", "bad");
  } else if (running) {
    sysResult(`Aggiornamento in corso dal ${hhmm(up.started)}…`, "");
  } else if (up.state === "ok") {
    sysResult(`Ultimo aggiornamento completato il ${hhmm(up.finished)}.`
      + (up.reboot_required ? " Per completarlo è consigliato un riavvio." : ""), up.reboot_required ? "" : "ok");
  } else if (up.state === "error") {
    sysResult(`Ultimo aggiornamento non riuscito${up.finished ? " il " + hhmm(up.finished) : ""}: controlla il registro.`, "bad");
  } else {
    sysResult("", "");
  }
  showLog($("#sys-log-box"), $("#sys-log"), data.log);
  if (up.state === "running") $("#sys-log-box").open = true;
  if (running || nmWatching) { clearTimeout(sysTimer); sysTimer = setTimeout(loadSystem, 3000); }
}

$("#sys-reboot").onclick = async () => {
  if (!confirm("Riavviare la sonda? Per circa un minuto non invierà dati e questa pagina non sarà raggiungibile.")) return;
  const { data } = await api("/api/system/reboot", {});
  if (!data.ok) return sysResult(data.message || "Riavvio non riuscito.", "bad");
  sysResult("Riavvio in corso… la pagina si ricaricherà da sola quando la sonda sarà di nuovo attiva.", "");
  $("#sys-reboot").disabled = true;
  let wentDown = false;
  const check = async () => {
    try {
      const r = await fetch("/api/config", { cache: "no-store" });
      if (r.ok && wentDown) return location.reload();
    } catch { wentDown = true; }
    setTimeout(check, 4000);
  };
  setTimeout(check, 6000);
};

loadSystem();

// ---- backup e ripristino ----
function bakResult(text, ok) {
  const out = $("#bak-result");
  out.className = "result " + (ok ? "ok" : "bad");
  out.textContent = text;
}

$("#bak-download").onclick = async () => {
  try {
    const r = await fetch("/api/backup", { cache: "no-store" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const blob = await r.blob();
    const m = (r.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = m ? m[1] : "netmon-sonda.json";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    bakResult("Backup scaricato: " + a.download, true);
  } catch (e) {
    bakResult("Backup non riuscito (" + e.message + ")", false);
  }
};

let pendingBackup = null;
$("#bak-restore").onclick = () => $("#bak-file").click();
$("#bak-file").onchange = async e => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;
  let backup;
  try { backup = JSON.parse(await file.text()); }
  catch { bakResult("Il file scelto non è un backup valido.", false); return; }
  await doRestore(backup);
};
$("#bak-go").onclick = () => doRestore(pendingBackup, $("#bak-probe").value);

async function doRestore(backup, probe) {
  if (!probe) {
    const warn = dirty ? " Le modifiche non salvate in questa pagina andranno perse." : "";
    if (!confirm("Sostituire la configurazione attuale con quella del backup?" + warn)) return;
  }
  const { status, data } = await api("/api/restore", { backup, probe });
  if (data.choose) {
    pendingBackup = backup;
    const sel = $("#bak-probe"); sel.innerHTML = "";
    data.choose.forEach(n => { const o = document.createElement("option"); o.value = o.textContent = n; sel.appendChild(o); });
    $("#bak-choose").hidden = false;
    bakResult("", true);
    return;
  }
  $("#bak-choose").hidden = true;
  pendingBackup = null;
  if (status === 200) {
    await load();
    bakResult(`Ripristinato dal backup ${data.source === "server" ? "del server" : "della sonda"}: `
      + `${data.devices} ${data.devices === 1 ? "dispositivo" : "dispositivi"}. `
      + "La sonda lo usa dal prossimo controllo e lo invia al server.", true);
  } else {
    bakResult("Ripristino non riuscito: " + (data.errors || ["errore sconosciuto"]).join(" "), false);
  }
}

// ---- menu delle sezioni: una alla volta, come negli altri pannelli ----
// Il nome nel menu e nel percorso in alto è il titolo della sezione; l'indirizzo porta la sezione
// (#server, #dispositivi…), quindi si può salvare nei segnalibri. Tutti i campi restano nella
// pagina anche quando la loro sezione non si vede: «Salva modifiche» salva tutto insieme.
const SECTIONS = [...document.querySelectorAll("main > section")].map(sec => {
  const h2 = sec.querySelector(":scope > h2");
  const label = h2.textContent.trim();
  const key = label.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  return { sec, label, key };
});
function navWide() { return window.matchMedia("(min-width:900px)").matches; }
function setNav(open, remember = true) {
  document.body.classList.toggle("nav-open", open);
  $("#navtoggle").setAttribute("aria-expanded", String(open));
  if (remember) { try { localStorage.setItem("netprobe.nav", open ? "1" : "0"); } catch {} }
}
function showSection(key, push = true) {
  const cur = SECTIONS.find(x => x.key === key) || SECTIONS[0];
  SECTIONS.forEach(x => {
    x.sec.hidden = x !== cur;
    x.btn.setAttribute("aria-selected", String(x === cur));
  });
  $("#secname").textContent = cur.label;
  if (push && location.hash !== "#" + cur.key) history.replaceState(null, "", "#" + cur.key);
  if (!navWide()) setNav(false, false);          // su telefono il menu copre la pagina: si richiude
  window.scrollTo(0, 0);
}
SECTIONS.forEach(x => {
  const b = document.createElement("button");
  b.type = "button"; b.textContent = x.label;
  if (x.key === "disinstalla-sonda") b.className = "navdanger";
  b.onclick = () => showSection(x.key);
  x.btn = b;
  $("#pagetabs").appendChild(b);
});
{
  let salvato = null;
  try { salvato = localStorage.getItem("netprobe.nav"); } catch {}
  setNav(salvato === null ? navWide() : salvato === "1", false);
  $("#navtoggle").onclick = () => setNav(!document.body.classList.contains("nav-open"));
  $("#navveil").onclick = () => setNav(false);
  document.addEventListener("keydown", e => {
    if (e.key === "Escape" && !navWide() && document.body.classList.contains("nav-open")) setNav(false);
  });
  window.addEventListener("hashchange", () => showSection(location.hash.slice(1), false));
  showSection(location.hash.slice(1), false);
}

$("#del-go").onclick = async () => {
  const out = $("#del-result");
  if ($("#del-confirm").value.trim() !== "DISINSTALLA") {
    out.className = "result bad"; out.textContent = "Per confermare scrivi DISINSTALLA nel primo campo."; return;
  }
  if (!$("#del-pass").value) {
    out.className = "result bad"; out.textContent = "Inserisci la password di accesso alla sonda."; return;
  }
  if (!confirm("Togliere netmon da questa sonda?\n\nLa sonda smette di controllare i dispositivi e di "
      + "inviare dati, e questa pagina non sarà più raggiungibile. Non si può annullare.")) return;
  $("#del-go").disabled = true;
  out.className = "result"; out.textContent = "Disinstallazione in corso…";
  const { data } = await api("/api/uninstall", { confirm: "DISINSTALLA", password: $("#del-pass").value });
  $("#del-pass").value = "";
  if (data.ok) {
    out.className = "result ok";
    out.textContent = "Disinstallazione avviata: tra pochi secondi netmon non sarà più sulla sonda e questa "
      + "pagina smetterà di rispondere. Ricordati di togliere la sonda anche dal server "
      + "(Impostazioni → Sonde → Elimina). Registro sulla sonda: /root/netmon-disinstallazione.log";
  } else {
    out.className = "result bad"; out.textContent = data.message || data.error || "Non riuscito.";
    $("#del-go").disabled = false;
  }
};

$("#test-server").onclick = async () => {
  const out = $("#server-result");
  out.className = "result"; out.textContent = "Verifica in corso…";
  const { data } = await api("/api/test-server", { server_url: $("#server_url").value });
  out.className = "result " + (data.ok ? "ok" : "bad");
  out.textContent = data.ok ? "Server raggiungibile." : "Server non raggiungibile: " + (data.error || "errore sconosciuto");
};
document.addEventListener("input", e => { if (e.target.matches("input:not([type=file])")) markDirty(); });
saveBtn.onclick = save;
window.addEventListener("beforeunload", e => { if (dirty) { e.preventDefault(); e.returnValue = ""; } });
load();

// ---- lingua della pagina
$("#lang-pick").value = I18N.lang;
$("#lang-pick").onchange = async e => {
  const r = await fetch("/api/language", { method: "POST", headers: { "Content-Type": "application/json" },
                                           body: JSON.stringify({ lang: e.target.value }) }).catch(() => null);
  if (r && r.ok) location.reload(); else e.target.value = I18N.lang;
};
</script>
</body>
</html>
"""


from urllib.parse import quote as _quote  # noqa: E402

# ------------------------------------------------------------------ lingue della pagina
# Italiano, inglese, tedesco, francese: si sceglie all'installazione (installa-sonda.sh) o in alto
# nella pagina, e sta in config.yaml (language). I testi restano in italiano nel codice; il
# traduttore nel browser (I18N_JS, copia identica di server/i18n.py) li sostituisce con quelli di
# TRANSLATIONS. Testi nuovi ancora da tradurre: python3 tools/i18n-estrai.py probe --mancanti
LANGS = ("it", "en", "de", "fr")
LANG_NAMES = {"it": "Italiano", "en": "English", "de": "Deutsch", "fr": "Français"}
LOCALES = {"it": "it-IT", "en": "en-GB", "de": "de-DE", "fr": "fr-FR"}


def page_lang():
    try:
        lang = str(read_config().get("language") or "it")
    except (OSError, yaml.YAMLError):
        lang = "it"
    return lang if lang in LANGS else "it"


def tr_plain(text, lang):
    """Messaggi in testo semplice (prima che la pagina si apra): riga per riga, solo testi noti."""
    table = TRANSLATIONS.get(lang) or {}
    return "\n".join(table.get(line.strip(), line) for line in text.split("\n"))


def page_script(lang):
    table = TRANSLATIONS.get(lang, {}) if lang != "it" else {}
    data = json.dumps({"lang": lang, "locale": LOCALES[lang], "names": LANG_NAMES, "table": table},
                      ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    return "<script>window.I18N=" + data + ";\n" + I18N_JS + "</script>"


I18N_JS = r"""
(function () {
  const I = window.I18N || {}; const table = I.table || {};
  I.t = s => s; I.text = s => s;
  if (I.lang === "it" || !Object.keys(table).length) { window.I18N = I; return; }
  const PH = /\{(\d+)\}/g, exact = new Map(), byPre = new Map(), bySuf = new Map(), loose = [], cache = new Map();
  const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const unb = s => s.replace(/\{\{/g, "{").replace(/\}\}/g, "}");
  const norm = s => s.replace(/\s+/g, " ").trim();
  const units = new Map();                // testi con formattazione (<strong>…), tradotti interi
  const canon = document.createElement("div");
  for (const [k0, v] of Object.entries(table)) {
    if (!v) continue;
    const k = norm(k0);
    if (k.includes("<")) { canon.innerHTML = k; units.set(norm(canon.innerHTML), v); continue; }
    if (!/\{\d+\}/.test(k)) { exact.set(unb(k), unb(v)); continue; }
    const parts = k.split(/(\{\d+\})/), order = [], lits = [];
    let rx = "^";
    parts.forEach((p, i) => {
      const m = /^\{(\d+)\}$/.exec(p);
      if (m) { rx += "(.+?)"; order.push(+m[1]); } else { const l = unb(p); rx += esc(l); lits.push(l); }
    });
    const lit = lits.reduce((a, l) => a + l.trim().length, 0);
    if (lit < 3) continue;
    const e = { rx: new RegExp(rx + "$", "s"), order, v, lit };
    const first = lits[0] || "", last = lits[lits.length - 1] || "";
    if (first.length >= 3) { const key = first.slice(0, 3); if (!byPre.has(key)) byPre.set(key, []); byPre.get(key).push(e); }
    else if (last.length >= 3) { const key = last.slice(-3); if (!bySuf.has(key)) bySuf.set(key, []); bySuf.get(key).push(e); }
    else loose.push(e);
  }
  [...byPre.values(), ...bySuf.values(), loose].forEach(l => l.sort((a, b) => b.lit - a.lit));
  function find(core, depth) {
    const x = exact.get(core);
    if (x !== undefined) return x;
    const cands = (byPre.get(core.slice(0, 3)) || []).concat(bySuf.get(core.slice(-3)) || [], loose);
    for (const e of cands) {
      const m = e.rx.exec(core);
      if (!m) continue;
      const g = {};
      e.order.forEach((n, i) => { g[n] = depth < 3 ? tr(m[i + 1], depth + 1) : m[i + 1]; });
      return unb(e.v.replace(PH, (all, n) => (n in g ? g[n] : all)));
    }
    const tg = /^\[([A-ZÀ-Ù' ]{2,20})\]\s+([\s\S]+)$/.exec(core);
    if (tg && depth < 3) return tr("[" + tg[1] + "]", depth + 1) + " " + tr(tg[2], depth + 1);
    for (const sep of [" · ", ", "]) {                 // elenchi: pezzo per pezzo
      if (depth < 3 && core.includes(sep)) {
        const segs = core.split(sep), out = segs.map(s => tr(s, depth + 1));
        if (out.some((s, i) => s !== segs[i])) return out.join(sep);
      }
    }
    return core;
  }
  function tr(text, depth = 0) {
    if (!text || !/[A-Za-zÀ-ÿ]/.test(text)) return text;
    const m = /^(\s*)([\s\S]*?)(\s*)$/.exec(text), core = norm(m[2]);
    let hit = cache.get(core);
    if (hit === undefined) { hit = find(core, depth); if (cache.size > 20000) cache.clear(); cache.set(core, hit); }
    return hit === core ? text : m[1] + hit + m[3];
  }
  function trText(text) {
    return String(text).split("\n").map(line => {
      let t = tr(line);
      if (t === line && /[.!?:]\s/.test(line)) t = line.split(/(?<=[.!?:])(\s+)/).map((p, i) => i % 2 ? p : tr(p)).join("");
      return t;
    }).join("\n");
  }
  I.t = tr; I.text = trText;
  const done = new WeakMap(), ATTRS = ["title", "placeholder", "aria-label", "alt"];
  const INLINE = new Set(["STRONG", "EM", "B", "I", "CODE", "BR", "A", "KBD"]);
  const skip = n => { const e = n.nodeType === 1 ? n : n.parentElement; return !e || !!e.closest('[translate="no"],script,style'); };
  const num = I.lang === "en" ? s => s.replace(/(\d),(\d)/g, "$1.$2") : s => s;   // punto decimale
  function doText(n) {
    if (done.get(n) === n.data || skip(n)) return;
    const t = num(tr(n.data));
    if (t !== n.data) n.data = t;
    done.set(n, n.data);
  }
  function doAttrs(e) {
    for (const a of ATTRS) {
      const v = e.getAttribute(a);
      if (!v) continue;
      const k = "a:" + a, seen = done.get(e) || {};
      if (seen[k] === v) continue;
      const t = num(tr(v));
      if (t !== v) e.setAttribute(a, t);
      seen[k] = t; done.set(e, seen);
    }
    if (e.tagName === "INPUT" && /^(button|submit)$/.test(e.type) && e.value) { const t = tr(e.value); if (t !== e.value) e.value = t; }
  }
  function doUnit(e) {                    // elemento con solo formattazione dentro: tradotto intero
    if (!units.size || !e.firstElementChild || e.querySelector("[id]")) return false;
    for (const c of e.children) if (!INLINE.has(c.tagName)) return false;
    const v = units.get(norm(e.innerHTML));
    if (v === undefined) return false;
    e.innerHTML = v; return true;
  }
  function walk(root) {
    if (root.nodeType === 3) { doText(root); return; }
    if (root.nodeType !== 1 || skip(root)) return;
    const stack = [root];
    while (stack.length) {
      const e = stack.pop();
      if (e.nodeType !== 1 || e.getAttribute("translate") === "no" || e.tagName === "SCRIPT" || e.tagName === "STYLE") continue;
      doAttrs(e);
      if (doUnit(e)) continue;
      for (const c of e.childNodes) { if (c.nodeType === 3) doText(c); else if (c.nodeType === 1) stack.push(c); }
    }
  }
  const obs = new MutationObserver(list => {
    for (const m of list) {
      if (m.type === "characterData") doText(m.target);
      else if (m.type === "attributes") { if (!skip(m.target)) doAttrs(m.target); }
      else m.addedNodes.forEach(walk);
    }
  });
  function start() {
    walk(document.documentElement);
    obs.observe(document.documentElement, { subtree: true, childList: true, characterData: true,
                                            attributes: true, attributeFilter: ATTRS });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
  const oc = window.confirm.bind(window), oa = window.alert.bind(window), op = window.prompt.bind(window);
  window.confirm = m => oc(trText(m)); window.alert = m => oa(trText(m)); window.prompt = (m, d) => op(trText(m), d);
  window.I18N = I;
})();
"""

TRANSLATIONS = {
"de": {
    "Informativa sulla privacy": "Datenschutzerklärung",
    "(genera la password e la mostra alla fine), oppure crea /etc/netprobe/web.env": "(erzeugt das Passwort und zeigt es am Ende an), oder lege /etc/netprobe/web.env an",
    "(li decide l'amministratore del server): fino a": "(legt der Administrator des Servers fest): bis zu",
    ", cioè Internet, traffico, ospiti e dispositivi. Al massimo": ", also Internet, Verkehr, Gäste und Geräte. Höchstens",
    ", cioè i client collegati alle sue reti. Oppure un FRITZ!Box in un altro posto che la sonda raggiunge, per esempio con la VPN tra i due FRITZ:": ", also die mit seinen Netzen verbundenen Clients. Oder eine FRITZ!Box an einem anderen Ort, den die Sonde erreicht, zum Beispiel per VPN zwischen den beiden FRITZ!Boxen:",
    ". Si aggiungono solo da questa pagina: le password restano sulla sonda.": ". Sie werden nur auf dieser Seite hinzugefügt: die Passwörter bleiben auf der Sonde.",
    "0 = solo all'invio dei risultati.": "0 = nur beim Senden der Ergebnisse.",
    ": arrivato al massimo, «Aggiungi dispositivo» si disattiva e il salvataggio rifiuta le righe in più. Se il limite viene abbassato quando ne hai già di più, gli ultimi della lista (e i FRITZ!Box aggiuntivi oltre il limite) smettono di essere controllati e spariscono da questa pagina, ma restano salvati sul server: tornano da soli se il limite si alza o se ne togli qualcuno.": ": ist das Maximum erreicht, wird „Gerät hinzufügen“ deaktiviert und das Speichern lehnt zusätzliche Zeilen ab. Wird das Limit gesenkt, wenn du schon mehr hast, werden die letzten der Liste (und die zusätzlichen FRITZ!Boxen über dem Limit) nicht mehr geprüft und verschwinden von dieser Seite, bleiben aber auf dem Server gespeichert: sie kehren von selbst zurück, wenn das Limit steigt oder du welche entfernst.",
    "<b>Se superi i limiti</b>: arrivato al massimo, «Aggiungi dispositivo» si disattiva e il salvataggio rifiuta le righe in più. Se il limite viene abbassato quando ne hai già di più, gli ultimi della lista (e i FRITZ!Box aggiuntivi oltre il limite) smettono di essere controllati e spariscono da questa pagina, ma restano salvati sul server: tornano da soli se il limite si alza o se ne togli qualcuno.": "<b>Wenn du die Limits überschreitest</b>: ist das Maximum erreicht, wird „Gerät hinzufügen“ deaktiviert und das Speichern lehnt zusätzliche Zeilen ab. Wird das Limit gesenkt, wenn du schon mehr hast, werden die letzten der Liste (und die zusätzlichen FRITZ!Boxen über dem Limit) nicht mehr geprüft und verschwinden von dieser Seite, bleiben aber auf dem Server gespeichert: sie kehren von selbst zurück, wenn das Limit steigt oder du welche entfernst.",
    "Accesso consentito solo dalla rete locale.": "Zugriff nur aus dem lokalen Netz erlaubt.",
    "Aggiornamento di netmon in corso dal {0}… la sonda si riavvierà.": "netmon-Aktualisierung läuft seit {0}… die Sonde startet neu.",
    "Aggiornamento in corso dal {0}…": "Aktualisierung läuft seit {0}…",
    "Aggiungi FRITZ!Box": "FRITZ!Box hinzufügen",
    "Aggiungi almeno un dispositivo.": "Füge mindestens ein Gerät hinzu.",
    "Aggiungi dispositivo": "Gerät hinzufügen",
    "Al massimo {0} FRITZ!Box oltre al primo.": "Höchstens {0} FRITZ!Boxen zusätzlich zur ersten.",
    "Al massimo {0} dispositivi per questa sonda (limite dell'account).": "Höchstens {0} Geräte für diese Sonde (Kontolimit).",
    "Altri FRITZ!Box": "Weitere FRITZ!Boxen",
    "Apri la pagina con l'indirizzo IP della sonda, per esempio http://192.168.1.20:8080": "Öffne die Seite mit der IP-Adresse der Sonde, zum Beispiel http://192.168.1.20:8080",
    "Attesa per ogni pacchetto": "Wartezeit pro Paket",
    "Backup e ripristino": "Sicherung und Wiederherstellung",
    "Backup non riuscito ({0})": "Sicherung fehlgeschlagen ({0})",
    "Backup scaricato: {0}": "Sicherung heruntergeladen: {0}",
    "Cambia password": "Passwort ändern",
    "Cambio password non riuscito": "Passwortänderung fehlgeschlagen",
    "Campionamento del traffico": "Verkehrsmessung",
    "Campo non valido": "Ungültiges Feld",
    "Campo «{0}»: '{1}' non è un numero valido.": "Feld „{0}“: '{1}' ist keine gültige Zahl.",
    "Caricamento…": "Wird geladen…",
    "Collega il FRITZ!Box": "FRITZ!Box verbinden",
    "Collegamento in corso…": "Verbindung wird hergestellt…",
    "Collegamento non riuscito: {0}": "Verbindung fehlgeschlagen: {0}",
    "Collegato: {0}": "Verbunden: {0}",
    "Configurazione caricata": "Konfiguration geladen",
    "Contiene token e password del FRITZ!Box: tienilo al sicuro. Si può ripristinare anche un backup del server (solo dispositivi e impostazioni).": "Sie enthält Token und FRITZ!Box-Passwort: bewahre sie sicher auf. Auch eine Sicherung des Servers lässt sich wiederherstellen (nur Geräte und Einstellungen).",
    "Controlli falliti prima dell'alert": "Fehlgeschlagene Prüfungen vor dem Alarm",
    "Controllo configurazioni dal server": "Konfigurationsabfrage vom Server",
    "Controllo configurazioni dal server (secondi)": "Konfigurationsabfrage vom Server (Sekunden)",
    "Controllo ogni (secondi)": "Prüfung alle (Sekunden)",
    "Disinstalla la sonda": "Sonde deinstallieren",
    "Disinstalla sonda": "Sonde deinstallieren",
    "Disinstallazione avviata: tra pochi secondi netmon non sarà più sulla sonda e questa pagina smetterà di rispondere. Ricordati di togliere la sonda anche dal server (Impostazioni → Sonde → Elimina). Registro sulla sonda: /root/netmon-disinstallazione.log": "Deinstallation gestartet: in wenigen Sekunden ist netmon nicht mehr auf der Sonde und diese Seite antwortet nicht mehr. Denk daran, die Sonde auch vom Server zu entfernen (Einstellungen → Sonden → Löschen). Protokoll auf der Sonde: /root/netmon-disinstallazione.log",
    "Disinstallazione in corso…": "Deinstallation läuft…",
    "Dispositivi": "Geräte",
    "FRITZ!Box aggiuntivi": "Zusätzliche FRITZ!Boxen",
    "FRITZ!Box non raggiungibile a questo indirizzo": "FRITZ!Box unter dieser Adresse nicht erreichbar",
    "FRITZ!Box {0}": "FRITZ!Box {0}",
    "Facoltativo. Le credenziali restano sulla sonda.": "Optional. Die Zugangsdaten bleiben auf der Sonde.",
    "Frequenze, soglie e notifiche si impostano dalla pagina di stato del server (Impostazioni).": "Frequenzen, Schwellen und Benachrichtigungen stellt man auf der Statusseite des Servers ein (Einstellungen).",
    "Gli aggiornamenti si comandano dal pannello di amministrazione del server.": "Aktualisierungen werden über das Administrationspanel des Servers gestartet.",
    "I controlli falliti prima dell'alert devono essere tra 1 e 20.": "Die fehlgeschlagenen Prüfungen vor dem Alarm müssen zwischen 1 und 20 liegen.",
    "I moltiplicatori devono essere tra 1 e 20.": "Die Faktoren müssen zwischen 1 und 20 liegen.",
    "I pacchetti ping per controllo devono essere tra 1 e 10.": "Die Ping-Pakete pro Prüfung müssen zwischen 1 und 10 liegen.",
    "I ping contemporanei devono essere tra 1 e 16.": "Die gleichzeitigen Pings müssen zwischen 1 und 16 liegen.",
    "Il backup contiene più sonde: quale ripristinare?": "Die Sicherung enthält mehrere Sonden: welche wiederherstellen?",
    "Il backup del server non contiene configurazioni di sonde.": "Die Sicherung des Servers enthält keine Sondenkonfigurationen.",
    "Il backup della sonda è vuoto o danneggiato.": "Die Sicherung der Sonde ist leer oder beschädigt.",
    "Il backup non contiene dispositivi.": "Die Sicherung enthält keine Geräte.",
    "Il campionamento del traffico deve essere 0 (disattivato) o tra 2 e 300 secondi.": "Die Verkehrsmessung muss 0 (aus) oder zwischen 2 und 300 Sekunden sein.",
    "Il controllo delle configurazioni deve essere 0 (disattivato) o tra 10 e 3600 secondi.": "Die Konfigurationsabfrage muss 0 (aus) oder zwischen 10 und 3600 Sekunden sein.",
    "Il file non è un backup di netmon.": "Die Datei ist keine netmon-Sicherung.",
    "Il file scelto non è un backup valido.": "Die gewählte Datei ist keine gültige Sicherung.",
    "Il token deve coincidere con quello del server.": "Das Token muss mit dem des Servers übereinstimmen.",
    "Il token non può essere vuoto.": "Das Token darf nicht leer sein.",
    "Impossibile leggere la configurazione": "Konfiguration kann nicht gelesen werden",
    "Impossibile leggere la configurazione: {0}": "Konfiguration kann nicht gelesen werden: {0}",
    "Impossibile leggere {0}: {1}": "{0} kann nicht gelesen werden: {1}",
    "Impossibile scrivere {0}: {1}. (Serve che il file sia della sonda: sudo chown netprobe:netprobe": "{0} kann nicht geschrieben werden: {1}. (Die Datei muss der Sonde gehören: sudo chown netprobe:netprobe",
    "Impostazioni → Sonde → Elimina": "Einstellungen → Sonden → Löschen",
    "Indica l'indirizzo del FRITZ!Box (es. 192.168.178.1).": "Gib die Adresse der FRITZ!Box an (z. B. 192.168.178.1).",
    "Indirizzo": "Adresse",
    "Indirizzo IP o nome host": "IP-Adresse oder Hostname",
    "Indirizzo del FRITZ!Box": "Adresse der FRITZ!Box",
    "Indirizzo del server": "Serveradresse",
    "Indirizzo non valido": "Ungültige Adresse",
    "Inserisci la password di accesso alla sonda.": "Gib das Zugangspasswort der Sonde ein.",
    "L'attesa per ogni pacchetto deve essere tra 1 e 10 secondi.": "Die Wartezeit pro Paket muss zwischen 1 und 10 Sekunden liegen.",
    "L'indirizzo del server deve iniziare con https:// (http:// solo per un server nella rete locale).": "Die Serveradresse muss mit https:// beginnen (http:// nur für einen Server im lokalen Netz).",
    "L'intervallo deve essere tra 10 e 3600 secondi.": "Das Intervall muss zwischen 10 und 3600 Sekunden liegen.",
    "La nuova password deve avere almeno 8 caratteri.": "Das neue Passwort muss mindestens 8 Zeichen haben.",
    "La pagina locale della sonda richiede una password, che non è impostata.": "Die lokale Seite der Sonde erfordert ein Passwort, das nicht gesetzt ist.",
    "La soglia «in ritardo» deve essere minore di quella «irraggiungibile».": "Die Schwelle „verspätet“ muss kleiner sein als „nicht erreichbar“.",
    "La sonda smette di controllare i dispositivi e di inviare dati, e questa pagina non sarà più raggiungibile. Non si può annullare.": "Die Sonde prüft keine Geräte mehr, sendet keine Daten und diese Seite ist nicht mehr erreichbar. Das kann nicht rückgängig gemacht werden.",
    "Le due password non coincidono.": "Die beiden Passwörter stimmen nicht überein.",
    "Le modifiche non salvate in questa pagina andranno perse.": "Ungespeicherte Änderungen auf dieser Seite gehen verloren.",
    "Le soglie fisse devono essere tra 10 e 86400 secondi.": "Feste Schwellen müssen zwischen 10 und 86400 Sekunden liegen.",
    "Libreria fritzconnection non installata sulla sonda": "Bibliothek fritzconnection auf der Sonde nicht installiert",
    "Limiti del tuo account": "Limits deines Kontos",
    "Lingua della pagina": "Sprache der Seite",
    "Modalità degli alert non valida.": "Ungültiger Alarmmodus.",
    "Modifiche non salvate": "Ungespeicherte Änderungen",
    "Mostra": "Anzeigen",
    "Mostra o nascondi le sezioni": "Bereiche ein- oder ausblenden",
    "Nascondi": "Ausblenden",
    "Nome": "Name",
    "Nome della sonda": "Name der Sonde",
    "Nome dispositivo": "Gerätename",
    "Nome sonda: usa lettere, numeri, spazi, punti o trattini (max 40).": "Sondenname: verwende Buchstaben, Zahlen, Leerzeichen, Punkte oder Bindestriche (max. 40).",
    "Non riuscito.": "Fehlgeschlagen.",
    "Nuova password": "Neues Passwort",
    "Ora ne hai {0}: {1}.": "Du hast jetzt {0}: {1}.",
    "Pacchetti ping per controllo": "Ping-Pakete pro Prüfung",
    "Pagina non trovata": "Seite nicht gefunden",
    "Password": "Passwort",
    "Password aggiornata: al prossimo aggiornamento della pagina il browser chiederà quella nuova.": "Passwort aktualisiert: beim nächsten Neuladen der Seite fragt der Browser nach dem neuen.",
    "Password di accesso alla sonda": "Zugangspasswort der Sonde",
    "Password di accesso alla sonda non corretta.": "Zugangspasswort der Sonde falsch.",
    "Password richiesta.": "Passwort erforderlich.",
    "Per completarlo è consigliato un riavvio.": "Zum Abschluss wird ein Neustart empfohlen.",
    "Per confermare scrivi DISINSTALLA": "Zur Bestätigung DISINSTALLA eingeben",
    "Per confermare scrivi DISINSTALLA nel primo campo.": "Zur Bestätigung DISINSTALLA in das erste Feld eingeben.",
    "Per confermare scrivi DISINSTALLA.": "Zur Bestätigung DISINSTALLA eingeben.",
    "Permessi non configurati: installa /etc/sudoers.d/netprobe come descritto nella guida.": "Berechtigungen nicht eingerichtet: installiere /etc/sudoers.d/netprobe wie in der Anleitung beschrieben.",
    "Ping contemporanei": "Gleichzeitige Pings",
    "Principale (Internet e traffico)": "Haupt (Internet und Verkehr)",
    "Prova": "Testen",
    "Prova collegamento": "Verbindung testen",
    "Prova tutti": "Alle testen",
    "Registro dell'ultimo aggiornamento di netmon (comandato dal server)": "Protokoll der letzten netmon-Aktualisierung (vom Server gestartet)",
    "Registro dell'ultimo aggiornamento di sistema (comandato dal server)": "Protokoll der letzten Systemaktualisierung (vom Server gestartet)",
    "Riavvia la sonda": "Sonde neu starten",
    "Riavviare la sonda? Per circa un minuto non invierà dati e questa pagina non sarà raggiungibile.": "Die Sonde neu starten? Etwa eine Minute lang sendet sie keine Daten und diese Seite ist nicht erreichbar.",
    "Riavvio in corso… la pagina si ricaricherà da sola quando la sonda sarà di nuovo attiva.": "Neustart läuft… die Seite lädt sich neu, sobald die Sonde wieder läuft.",
    "Riavvio non riuscito.": "Neustart fehlgeschlagen.",
    "Richiesta da un'altra pagina: rifiutata.": "Anfrage von einer anderen Seite: abgelehnt.",
    "Richiesta non valida": "Ungültige Anfrage",
    "Riga {0}: '{1}' non è un IP o un nome host valido.": "Zeile {0}: '{1}' ist keine gültige IP und kein gültiger Hostname.",
    "Riga {0}: il nome '{1}' è già usato.": "Zeile {0}: der Name '{1}' wird bereits verwendet.",
    "Riga {0}: nome dispositivo non valido.": "Zeile {0}: ungültiger Gerätename.",
    "Rimuovi": "Entfernen",
    "Rimuovi dispositivo": "Gerät entfernen",
    "Ripeti la password": "Passwort wiederholen",
    "Ripristina": "Wiederherstellen",
    "Ripristina da file…": "Aus Datei wiederherstellen…",
    "Ripristinato dal backup {0}: {1} {2}. La sonda lo usa dal prossimo controllo e lo invia al server.": "Aus Sicherung {0} wiederhergestellt: {1} {2}. Die Sonde verwendet sie ab der nächsten Prüfung und sendet sie an den Server.",
    "Ripristino non riuscito: {0}": "Wiederherstellung fehlgeschlagen: {0}",
    "Risposta HTTP {0}": "HTTP-Antwort {0}",
    "Risposta inattesa dal server": "Unerwartete Antwort vom Server",
    "Ruolo": "Rolle",
    "Salva modifiche": "Änderungen speichern",
    "Salvataggio in corso…": "Wird gespeichert…",
    "Salvataggio non riuscito": "Speichern fehlgeschlagen",
    "Salvataggio non riuscito: {0}": "Speichern fehlgeschlagen: {0}",
    "Salvataggio…": "Wird gespeichert…",
    "Salvato. La sonda lo userà dal prossimo controllo.": "Gespeichert. Die Sonde verwendet es ab der nächsten Prüfung.",
    "Scarica backup": "Backup herunterladen",
    "Se superi i limiti": "Wenn du die Limits überschreitest",
    "Senza spazi, virgolette, \\ e $ (li interpreterebbe systemd).": "Ohne Leerzeichen, Anführungszeichen, \\ und $ (systemd würde sie auswerten).",
    "Server non raggiungibile: {0}": "Server nicht erreichbar: {0}",
    "Server raggiungibile.": "Server erreichbar.",
    "Sezioni": "Bereiche",
    "Sistema": "System",
    "Solo Wi-Fi (ripetitore)": "Nur WLAN (Repeater)",
    "Sonda": "Sonde",
    "Sonda di rete": "Netzwerksonde",
    "Sonda ferma ({0})": "Sonde gestoppt ({0})",
    "Sonda in funzione": "Sonde läuft",
    "Sonda in ritardo dopo (intervalli)": "Sonde verspätet nach (Intervallen)",
    "Sonda in ritardo dopo (secondi)": "Sonde verspätet nach (Sekunden)",
    "Sonda irraggiungibile dopo (intervalli)": "Sonde nicht erreichbar nach (Intervallen)",
    "Sonda irraggiungibile dopo (secondi)": "Sonde nicht erreichbar nach (Sekunden)",
    "Sonda {0}": "Sonde {0}",
    "Sostituire la configurazione attuale con quella del backup?{0}": "Die aktuelle Konfiguration durch die der Sicherung ersetzen?{0}",
    "Stato sonda non disponibile": "Sondenstatus nicht verfügbar",
    "Stato sonda…": "Sondenstatus…",
    "Sulla sonda lancia: sudo bash probe/installa-sonda.sh --aggiorna": "Führe auf der Sonde aus: sudo bash probe/installa-sonda.sh --aggiorna",
    "Tipo di backup non riconosciuto.": "Sicherungstyp nicht erkannt.",
    "Toglie netmon da questa sonda: servizi, programmi, configurazione (token e password), dati, script di sistema, permessi e utente": "Entfernt netmon von dieser Sonde: Dienste, Programme, Konfiguration (Token und Passwörter), Daten, Systemskripte, Berechtigungen und den Benutzer",
    "Toglie netmon da questa sonda: servizi, programmi, configurazione (token e password), dati, script di sistema, permessi e utente <code>netprobe</code>. Restano i pacchetti di sistema e le reti Wi-Fi salvate. Una copia della configurazione resta in <code>/root</code> sulla sonda (solo root può leggerla); per averla qui, prima usa <b>Scarica backup</b>. Questa pagina smette di funzionare subito dopo. Sul server la sonda resta nel tuo account: toglila da <i>Impostazioni → Sonde → Elimina</i>.": "Entfernt netmon von dieser Sonde: Dienste, Programme, Konfiguration (Token und Passwörter), Daten, Systemskripte, Berechtigungen und den Benutzer <code>netprobe</code>. Systempakete und gespeicherte WLANs bleiben. Eine Kopie der Konfiguration bleibt in <code>/root</code> auf der Sonde (nur root kann sie lesen); um sie hier zu haben, nutze zuerst <b>Backup herunterladen</b>. Diese Seite funktioniert gleich danach nicht mehr. Auf dem Server bleibt die Sonde in deinem Konto: entferne sie unter <i>Einstellungen → Sonden → Löschen</i>.",
    "Togliere netmon da questa sonda?": "netmon von dieser Sonde entfernen?",
    "Token": "Token",
    "Troppe password sbagliate: riprova tra qualche minuto.": "Zu viele falsche Passwörter: versuche es in ein paar Minuten erneut.",
    "Ultimo aggiornamento completato il {0}.{1}": "Letzte Aktualisierung abgeschlossen am {0}.{1}",
    "Ultimo aggiornamento di netmon non riuscito{0}: controlla il registro.": "Letzte netmon-Aktualisierung fehlgeschlagen{0}: prüfe das Protokoll.",
    "Ultimo aggiornamento non riuscito{0}: controlla il registro.": "Letzte Aktualisierung fehlgeschlagen{0}: prüfe das Protokoll.",
    "Un ripetitore o un secondo FRITZ!Box nella stessa casa:": "Ein Repeater oder eine zweite FRITZ!Box im selben Haus:",
    "Utente": "Benutzer",
    "Utente o password non accettati dal FRITZ!Box": "Benutzer oder Passwort von der FRITZ!Box nicht akzeptiert",
    "Verifica in corso…": "Wird geprüft…",
    "Versione installata: {0} · sul server: {1}": "Installierte Version: {0} · auf dem Server: {1}",
    "con la riga WEB_PASSWORD=... come descritto nella guida.": "mit der Zeile WEB_PASSWORD=... wie in der Anleitung beschrieben.",
    "del server": "des Servers",
    "della sonda": "der Sonde",
    "dispositivi": "Geräte",
    "dispositivo": "Gerät",
    "e": "und",
    "errore sconosciuto": "unbekannter Fehler",
    "es. Casa": "z. B. Zuhause",
    "gli ultimi {0} della lista non vengono controllati": "die letzten {0} der Liste werden nicht geprüft",
    "l'ultimo della lista non viene controllato": "der letzte der Liste wird nicht geprüft",
    "netmon aggiornato il {0} alla versione {1}.": "netmon am {0} auf Version {1} aktualisiert.",
    "non disponibile": "nicht verfügbar",
    "principale": "Haupt",
    "ripetitore piano di sopra": "Repeater oben",
    "solo Wi-Fi": "nur WLAN",
    "sonda": "Sonde",
    "sulla sonda (solo root può leggerla); per averla qui, prima usa": "auf der Sonde (nur root kann sie lesen); um sie hier zu haben, nutze zuerst",
    "{0} · configurazione": "{0} · Konfiguration",
    "{0}: indica un indirizzo valido (es. 192.168.178.2).": "{0}: gib eine gültige Adresse an (z. B. 192.168.178.2).",
    "{0}: nome non valido (lettere, numeri, spazi, punti o trattini, max 40).": "{0}: ungültiger Name (Buchstaben, Zahlen, Leerzeichen, Punkte oder Bindestriche, max. 40).",
    "· FRITZ!OS {0}": "· FRITZ!OS {0}",
    "· IP pubblico {0}": "· öffentliche IP {0}",
    "È il nome che compare nella pagina di stato del server (Stato rete e Impostazioni → Sonde). Si può cambiare anche da lì: i due lati si sincronizzano da soli, al prossimo controllo. Salva con il pulsante in fondo.": "Es ist der Name, der auf der Statusseite des Servers erscheint (Netzwerkstatus und Einstellungen → Sonden). Er lässt sich auch dort ändern: beide Seiten gleichen sich bei der nächsten Prüfung von selbst ab. Speichere mit der Schaltfläche unten.",
    "È la password che il browser chiede quando apri la pagina della sonda: la stessa scelta all'installazione. Cambiandola qui non serve riavviare nulla: al prossimo aggiornamento della pagina il browser chiederà quella nuova (almeno 8 caratteri, senza spazi, virgolette, \\ e $ — li legge systemd).": "Es ist das Passwort, das der Browser beim Öffnen der Seite der Sonde abfragt: dasselbe, das bei der Installation gewählt wurde. Eine Änderung hier braucht keinen Neustart: beim nächsten Neuladen fragt der Browser nach dem neuen (mindestens 8 Zeichen, ohne Leerzeichen, Anführungszeichen, \\ und $ — systemd liest sie).",
},
"en": {
    "Informativa sulla privacy": "Privacy notice",
    "(genera la password e la mostra alla fine), oppure crea /etc/netprobe/web.env": "(it generates the password and shows it at the end), or create /etc/netprobe/web.env",
    "(li decide l'amministratore del server): fino a": "(set by the server administrator): up to",
    ", cioè Internet, traffico, ospiti e dispositivi. Al massimo": ", i.e. Internet, traffic, guests and devices. At most",
    ", cioè i client collegati alle sue reti. Oppure un FRITZ!Box in un altro posto che la sonda raggiunge, per esempio con la VPN tra i due FRITZ:": ", i.e. the clients connected to its networks. Or a FRITZ!Box in another place the probe can reach, for example with a VPN between the two FRITZ!Boxes:",
    ". Si aggiungono solo da questa pagina: le password restano sulla sonda.": ". They are added only from this page: the passwords stay on the probe.",
    "0 = solo all'invio dei risultati.": "0 = only when sending the results.",
    ": arrivato al massimo, «Aggiungi dispositivo» si disattiva e il salvataggio rifiuta le righe in più. Se il limite viene abbassato quando ne hai già di più, gli ultimi della lista (e i FRITZ!Box aggiuntivi oltre il limite) smettono di essere controllati e spariscono da questa pagina, ma restano salvati sul server: tornano da soli se il limite si alza o se ne togli qualcuno.": ": once the maximum is reached, “Add device” is disabled and saving rejects the extra rows. If the limit is lowered when you already have more, the last ones in the list (and the additional FRITZ!Boxes beyond the limit) stop being checked and disappear from this page, but stay saved on the server: they come back by themselves if the limit is raised or you remove some.",
    "<b>Se superi i limiti</b>: arrivato al massimo, «Aggiungi dispositivo» si disattiva e il salvataggio rifiuta le righe in più. Se il limite viene abbassato quando ne hai già di più, gli ultimi della lista (e i FRITZ!Box aggiuntivi oltre il limite) smettono di essere controllati e spariscono da questa pagina, ma restano salvati sul server: tornano da soli se il limite si alza o se ne togli qualcuno.": "<b>If you exceed the limits</b>: once the maximum is reached, “Add device” is disabled and saving rejects the extra rows. If the limit is lowered when you already have more, the last ones in the list (and the additional FRITZ!Boxes beyond the limit) stop being checked and disappear from this page, but stay saved on the server: they come back by themselves if the limit is raised or you remove some.",
    "Accesso consentito solo dalla rete locale.": "Access allowed only from the local network.",
    "Aggiornamento di netmon in corso dal {0}… la sonda si riavvierà.": "netmon update in progress since {0}… the probe will restart.",
    "Aggiornamento in corso dal {0}…": "Update in progress since {0}…",
    "Aggiungi FRITZ!Box": "Add FRITZ!Box",
    "Aggiungi almeno un dispositivo.": "Add at least one device.",
    "Aggiungi dispositivo": "Add device",
    "Al massimo {0} FRITZ!Box oltre al primo.": "At most {0} FRITZ!Boxes besides the first.",
    "Al massimo {0} dispositivi per questa sonda (limite dell'account).": "At most {0} devices for this probe (account limit).",
    "Altri FRITZ!Box": "Other FRITZ!Boxes",
    "Apri la pagina con l'indirizzo IP della sonda, per esempio http://192.168.1.20:8080": "Open the page with the probe's IP address, for example http://192.168.1.20:8080",
    "Attesa per ogni pacchetto": "Wait for each packet",
    "Backup e ripristino": "Backup and restore",
    "Backup non riuscito ({0})": "Backup failed ({0})",
    "Backup scaricato: {0}": "Backup downloaded: {0}",
    "Cambia password": "Change password",
    "Cambio password non riuscito": "Password change failed",
    "Campionamento del traffico": "Traffic sampling",
    "Campo non valido": "Invalid field",
    "Campo «{0}»: '{1}' non è un numero valido.": "Field “{0}”: '{1}' is not a valid number.",
    "Caricamento…": "Loading…",
    "Collega il FRITZ!Box": "Connect the FRITZ!Box",
    "Collegamento in corso…": "Connecting…",
    "Collegamento non riuscito: {0}": "Connection failed: {0}",
    "Collegato: {0}": "Connected: {0}",
    "Configurazione caricata": "Configuration loaded",
    "Contiene token e password del FRITZ!Box: tienilo al sicuro. Si può ripristinare anche un backup del server (solo dispositivi e impostazioni).": "It contains the token and the FRITZ!Box password: keep it safe. A server backup can be restored too (devices and settings only).",
    "Controlli falliti prima dell'alert": "Failed checks before the alert",
    "Controllo configurazioni dal server": "Configuration check from the server",
    "Controllo configurazioni dal server (secondi)": "Configuration check from the server (seconds)",
    "Controllo ogni (secondi)": "Check every (seconds)",
    "Disinstalla la sonda": "Uninstall the probe",
    "Disinstalla sonda": "Uninstall probe",
    "Disinstallazione avviata: tra pochi secondi netmon non sarà più sulla sonda e questa pagina smetterà di rispondere. Ricordati di togliere la sonda anche dal server (Impostazioni → Sonde → Elimina). Registro sulla sonda: /root/netmon-disinstallazione.log": "Uninstall started: in a few seconds netmon will no longer be on the probe and this page will stop responding. Remember to remove the probe from the server too (Settings → Probes → Delete). Log on the probe: /root/netmon-disinstallazione.log",
    "Disinstallazione in corso…": "Uninstalling…",
    "Dispositivi": "Devices",
    "FRITZ!Box aggiuntivi": "Additional FRITZ!Boxes",
    "FRITZ!Box non raggiungibile a questo indirizzo": "FRITZ!Box not reachable at this address",
    "FRITZ!Box {0}": "FRITZ!Box {0}",
    "Facoltativo. Le credenziali restano sulla sonda.": "Optional. The credentials stay on the probe.",
    "Frequenze, soglie e notifiche si impostano dalla pagina di stato del server (Impostazioni).": "Frequencies, thresholds and notifications are set from the server's status page (Settings).",
    "Gli aggiornamenti si comandano dal pannello di amministrazione del server.": "Updates are started from the server's administration panel.",
    "I controlli falliti prima dell'alert devono essere tra 1 e 20.": "Failed checks before the alert must be between 1 and 20.",
    "I moltiplicatori devono essere tra 1 e 20.": "The multipliers must be between 1 and 20.",
    "I pacchetti ping per controllo devono essere tra 1 e 10.": "Ping packets per check must be between 1 and 10.",
    "I ping contemporanei devono essere tra 1 e 16.": "Parallel pings must be between 1 and 16.",
    "Il backup contiene più sonde: quale ripristinare?": "The backup contains several probes: which one to restore?",
    "Il backup del server non contiene configurazioni di sonde.": "The server backup contains no probe configurations.",
    "Il backup della sonda è vuoto o danneggiato.": "The probe backup is empty or damaged.",
    "Il backup non contiene dispositivi.": "The backup contains no devices.",
    "Il campionamento del traffico deve essere 0 (disattivato) o tra 2 e 300 secondi.": "Traffic sampling must be 0 (off) or between 2 and 300 seconds.",
    "Il controllo delle configurazioni deve essere 0 (disattivato) o tra 10 e 3600 secondi.": "The configuration check must be 0 (off) or between 10 and 3600 seconds.",
    "Il file non è un backup di netmon.": "The file is not a netmon backup.",
    "Il file scelto non è un backup valido.": "The chosen file is not a valid backup.",
    "Il token deve coincidere con quello del server.": "The token must match the server's one.",
    "Il token non può essere vuoto.": "The token can't be empty.",
    "Impossibile leggere la configurazione": "Unable to read the configuration",
    "Impossibile leggere la configurazione: {0}": "Unable to read the configuration: {0}",
    "Impossibile leggere {0}: {1}": "Unable to read {0}: {1}",
    "Impossibile scrivere {0}: {1}. (Serve che il file sia della sonda: sudo chown netprobe:netprobe": "Unable to write {0}: {1}. (The file must belong to the probe: sudo chown netprobe:netprobe",
    "Impostazioni → Sonde → Elimina": "Settings → Probes → Delete",
    "Indica l'indirizzo del FRITZ!Box (es. 192.168.178.1).": "Enter the FRITZ!Box address (e.g. 192.168.178.1).",
    "Indirizzo": "Address",
    "Indirizzo IP o nome host": "IP address or host name",
    "Indirizzo del FRITZ!Box": "FRITZ!Box address",
    "Indirizzo del server": "Server address",
    "Indirizzo non valido": "Invalid address",
    "Inserisci la password di accesso alla sonda.": "Enter the probe access password.",
    "L'attesa per ogni pacchetto deve essere tra 1 e 10 secondi.": "The wait for each packet must be between 1 and 10 seconds.",
    "L'indirizzo del server deve iniziare con https:// (http:// solo per un server nella rete locale).": "The server address must start with https:// (http:// only for a server on the local network).",
    "L'intervallo deve essere tra 10 e 3600 secondi.": "The interval must be between 10 and 3600 seconds.",
    "La nuova password deve avere almeno 8 caratteri.": "The new password must have at least 8 characters.",
    "La pagina locale della sonda richiede una password, che non è impostata.": "The probe's local page requires a password, which is not set.",
    "La soglia «in ritardo» deve essere minore di quella «irraggiungibile».": "The “late” threshold must be lower than the “unreachable” one.",
    "La sonda smette di controllare i dispositivi e di inviare dati, e questa pagina non sarà più raggiungibile. Non si può annullare.": "The probe stops checking the devices and sending data, and this page will no longer be reachable. This cannot be undone.",
    "Le due password non coincidono.": "The two passwords don't match.",
    "Le modifiche non salvate in questa pagina andranno perse.": "Unsaved changes on this page will be lost.",
    "Le soglie fisse devono essere tra 10 e 86400 secondi.": "Fixed thresholds must be between 10 and 86400 seconds.",
    "Libreria fritzconnection non installata sulla sonda": "fritzconnection library not installed on the probe",
    "Limiti del tuo account": "Your account's limits",
    "Lingua della pagina": "Page language",
    "Modalità degli alert non valida.": "Invalid alert mode.",
    "Modifiche non salvate": "Unsaved changes",
    "Mostra": "Show",
    "Mostra o nascondi le sezioni": "Show or hide sections",
    "Nascondi": "Hide",
    "Nome": "Name",
    "Nome della sonda": "Probe name",
    "Nome dispositivo": "Device name",
    "Nome sonda: usa lettere, numeri, spazi, punti o trattini (max 40).": "Probe name: use letters, numbers, spaces, dots or hyphens (max 40).",
    "Non riuscito.": "Failed.",
    "Nuova password": "New password",
    "Ora ne hai {0}: {1}.": "You now have {0}: {1}.",
    "Pacchetti ping per controllo": "Ping packets per check",
    "Pagina non trovata": "Page not found",
    "Password": "Password",
    "Password aggiornata: al prossimo aggiornamento della pagina il browser chiederà quella nuova.": "Password updated: next time the page reloads the browser will ask for the new one.",
    "Password di accesso alla sonda": "Probe access password",
    "Password di accesso alla sonda non corretta.": "Incorrect probe access password.",
    "Password richiesta.": "Password required.",
    "Per completarlo è consigliato un riavvio.": "A restart is recommended to complete it.",
    "Per confermare scrivi DISINSTALLA": "To confirm type DISINSTALLA",
    "Per confermare scrivi DISINSTALLA nel primo campo.": "To confirm type DISINSTALLA in the first field.",
    "Per confermare scrivi DISINSTALLA.": "To confirm type DISINSTALLA.",
    "Permessi non configurati: installa /etc/sudoers.d/netprobe come descritto nella guida.": "Permissions not configured: install /etc/sudoers.d/netprobe as described in the guide.",
    "Ping contemporanei": "Parallel pings",
    "Principale (Internet e traffico)": "Main (Internet and traffic)",
    "Prova": "Test",
    "Prova collegamento": "Test connection",
    "Prova tutti": "Test all",
    "Registro dell'ultimo aggiornamento di netmon (comandato dal server)": "Log of the last netmon update (started by the server)",
    "Registro dell'ultimo aggiornamento di sistema (comandato dal server)": "Log of the last system update (started by the server)",
    "Riavvia la sonda": "Restart the probe",
    "Riavviare la sonda? Per circa un minuto non invierà dati e questa pagina non sarà raggiungibile.": "Restart the probe? For about a minute it won't send data and this page won't be reachable.",
    "Riavvio in corso… la pagina si ricaricherà da sola quando la sonda sarà di nuovo attiva.": "Restarting… the page will reload by itself when the probe is back up.",
    "Riavvio non riuscito.": "Restart failed.",
    "Richiesta da un'altra pagina: rifiutata.": "Request from another page: rejected.",
    "Richiesta non valida": "Invalid request",
    "Riga {0}: '{1}' non è un IP o un nome host valido.": "Row {0}: '{1}' is not a valid IP or host name.",
    "Riga {0}: il nome '{1}' è già usato.": "Row {0}: the name '{1}' is already used.",
    "Riga {0}: nome dispositivo non valido.": "Row {0}: invalid device name.",
    "Rimuovi": "Remove",
    "Rimuovi dispositivo": "Remove device",
    "Ripeti la password": "Repeat the password",
    "Ripristina": "Restore",
    "Ripristina da file…": "Restore from file…",
    "Ripristinato dal backup {0}: {1} {2}. La sonda lo usa dal prossimo controllo e lo invia al server.": "Restored from backup {0}: {1} {2}. The probe uses it from the next check and sends it to the server.",
    "Ripristino non riuscito: {0}": "Restore failed: {0}",
    "Risposta HTTP {0}": "HTTP response {0}",
    "Risposta inattesa dal server": "Unexpected response from the server",
    "Ruolo": "Role",
    "Salva modifiche": "Save changes",
    "Salvataggio in corso…": "Saving…",
    "Salvataggio non riuscito": "Save failed",
    "Salvataggio non riuscito: {0}": "Save failed: {0}",
    "Salvataggio…": "Saving…",
    "Salvato. La sonda lo userà dal prossimo controllo.": "Saved. The probe will use it from the next check.",
    "Scarica backup": "Download backup",
    "Se superi i limiti": "If you exceed the limits",
    "Senza spazi, virgolette, \\ e $ (li interpreterebbe systemd).": "No spaces, quotes, \\ or $ (systemd would interpret them).",
    "Server non raggiungibile: {0}": "Server unreachable: {0}",
    "Server raggiungibile.": "Server reachable.",
    "Sezioni": "Sections",
    "Sistema": "System",
    "Solo Wi-Fi (ripetitore)": "Wi-Fi only (repeater)",
    "Sonda": "Probe",
    "Sonda di rete": "Network probe",
    "Sonda ferma ({0})": "Probe stopped ({0})",
    "Sonda in funzione": "Probe running",
    "Sonda in ritardo dopo (intervalli)": "Probe late after (intervals)",
    "Sonda in ritardo dopo (secondi)": "Probe late after (seconds)",
    "Sonda irraggiungibile dopo (intervalli)": "Probe unreachable after (intervals)",
    "Sonda irraggiungibile dopo (secondi)": "Probe unreachable after (seconds)",
    "Sonda {0}": "Probe {0}",
    "Sostituire la configurazione attuale con quella del backup?{0}": "Replace the current configuration with the backup's?{0}",
    "Stato sonda non disponibile": "Probe status not available",
    "Stato sonda…": "Probe status…",
    "Sulla sonda lancia: sudo bash probe/installa-sonda.sh --aggiorna": "On the probe run: sudo bash probe/installa-sonda.sh --aggiorna",
    "Tipo di backup non riconosciuto.": "Backup type not recognised.",
    "Toglie netmon da questa sonda: servizi, programmi, configurazione (token e password), dati, script di sistema, permessi e utente": "Removes netmon from this probe: services, programs, configuration (token and passwords), data, system scripts, permissions and the user",
    "Toglie netmon da questa sonda: servizi, programmi, configurazione (token e password), dati, script di sistema, permessi e utente <code>netprobe</code>. Restano i pacchetti di sistema e le reti Wi-Fi salvate. Una copia della configurazione resta in <code>/root</code> sulla sonda (solo root può leggerla); per averla qui, prima usa <b>Scarica backup</b>. Questa pagina smette di funzionare subito dopo. Sul server la sonda resta nel tuo account: toglila da <i>Impostazioni → Sonde → Elimina</i>.": "Removes netmon from this probe: services, programs, configuration (token and passwords), data, system scripts, permissions and the user <code>netprobe</code>. System packages and saved Wi-Fi networks stay. A copy of the configuration stays in <code>/root</code> on the probe (only root can read it); to have it here, first use <b>Download backup</b>. This page stops working right after. On the server the probe stays in your account: remove it from <i>Settings → Probes → Delete</i>.",
    "Togliere netmon da questa sonda?": "Remove netmon from this probe?",
    "Token": "Token",
    "Troppe password sbagliate: riprova tra qualche minuto.": "Too many wrong passwords: try again in a few minutes.",
    "Ultimo aggiornamento completato il {0}.{1}": "Last update completed on {0}.{1}",
    "Ultimo aggiornamento di netmon non riuscito{0}: controlla il registro.": "Last netmon update failed{0}: check the log.",
    "Ultimo aggiornamento non riuscito{0}: controlla il registro.": "Last update failed{0}: check the log.",
    "Un ripetitore o un secondo FRITZ!Box nella stessa casa:": "A repeater or a second FRITZ!Box in the same home:",
    "Utente": "User",
    "Utente o password non accettati dal FRITZ!Box": "User or password not accepted by the FRITZ!Box",
    "Verifica in corso…": "Checking…",
    "Versione installata: {0} · sul server: {1}": "Installed version: {0} · on the server: {1}",
    "con la riga WEB_PASSWORD=... come descritto nella guida.": "with the line WEB_PASSWORD=... as described in the guide.",
    "del server": "of the server",
    "della sonda": "of the probe",
    "dispositivi": "devices",
    "dispositivo": "device",
    "e": "and",
    "errore sconosciuto": "unknown error",
    "es. Casa": "e.g. Home",
    "gli ultimi {0} della lista non vengono controllati": "the last {0} in the list are not checked",
    "l'ultimo della lista non viene controllato": "the last one in the list is not checked",
    "netmon aggiornato il {0} alla versione {1}.": "netmon updated on {0} to version {1}.",
    "non disponibile": "not available",
    "principale": "main",
    "ripetitore piano di sopra": "upstairs repeater",
    "solo Wi-Fi": "Wi-Fi only",
    "sonda": "probe",
    "sulla sonda (solo root può leggerla); per averla qui, prima usa": "on the probe (only root can read it); to have it here, first use",
    "{0} · configurazione": "{0} · configuration",
    "{0}: indica un indirizzo valido (es. 192.168.178.2).": "{0}: enter a valid address (e.g. 192.168.178.2).",
    "{0}: nome non valido (lettere, numeri, spazi, punti o trattini, max 40).": "{0}: invalid name (letters, numbers, spaces, dots or hyphens, max 40).",
    "· FRITZ!OS {0}": "· FRITZ!OS {0}",
    "· IP pubblico {0}": "· public IP {0}",
    "È il nome che compare nella pagina di stato del server (Stato rete e Impostazioni → Sonde). Si può cambiare anche da lì: i due lati si sincronizzano da soli, al prossimo controllo. Salva con il pulsante in fondo.": "It's the name shown on the server's status page (Network status and Settings → Probes). It can be changed from there too: the two sides sync by themselves at the next check. Save with the button at the bottom.",
    "È la password che il browser chiede quando apri la pagina della sonda: la stessa scelta all'installazione. Cambiandola qui non serve riavviare nulla: al prossimo aggiornamento della pagina il browser chiederà quella nuova (almeno 8 caratteri, senza spazi, virgolette, \\ e $ — li legge systemd).": "It's the password the browser asks for when you open the probe's page: the same one chosen at installation. Changing it here needs no restart: next time the page reloads the browser will ask for the new one (at least 8 characters, no spaces, quotes, \\ or $ — systemd reads them).",
},
"fr": {
    "Informativa sulla privacy": "Politique de confidentialité",
    "(genera la password e la mostra alla fine), oppure crea /etc/netprobe/web.env": "(il génère le mot de passe et l'affiche à la fin), ou crée /etc/netprobe/web.env",
    "(li decide l'amministratore del server): fino a": "(fixées par l'administrateur du serveur) : jusqu'à",
    ", cioè Internet, traffico, ospiti e dispositivi. Al massimo": ", c'est-à-dire Internet, trafic, invités et appareils. Au maximum",
    ", cioè i client collegati alle sue reti. Oppure un FRITZ!Box in un altro posto che la sonda raggiunge, per esempio con la VPN tra i due FRITZ:": ", c'est-à-dire les clients connectés à ses réseaux. Ou une FRITZ!Box dans un autre lieu que la sonde atteint, par exemple avec un VPN entre les deux FRITZ!Box :",
    ". Si aggiungono solo da questa pagina: le password restano sulla sonda.": ". Ils s'ajoutent uniquement depuis cette page : les mots de passe restent sur la sonde.",
    "0 = solo all'invio dei risultati.": "0 = seulement à l'envoi des résultats.",
    ": arrivato al massimo, «Aggiungi dispositivo» si disattiva e il salvataggio rifiuta le righe in più. Se il limite viene abbassato quando ne hai già di più, gli ultimi della lista (e i FRITZ!Box aggiuntivi oltre il limite) smettono di essere controllati e spariscono da questa pagina, ma restano salvati sul server: tornano da soli se il limite si alza o se ne togli qualcuno.": " : une fois le maximum atteint, « Ajouter un appareil » se désactive et l'enregistrement refuse les lignes en trop. Si la limite est abaissée alors que tu en as déjà plus, les derniers de la liste (et les FRITZ!Box supplémentaires au-delà de la limite) cessent d'être contrôlés et disparaissent de cette page, mais restent enregistrés sur le serveur : ils reviennent d'eux-mêmes si la limite est relevée ou si tu en retires.",
    "<b>Se superi i limiti</b>: arrivato al massimo, «Aggiungi dispositivo» si disattiva e il salvataggio rifiuta le righe in più. Se il limite viene abbassato quando ne hai già di più, gli ultimi della lista (e i FRITZ!Box aggiuntivi oltre il limite) smettono di essere controllati e spariscono da questa pagina, ma restano salvati sul server: tornano da soli se il limite si alza o se ne togli qualcuno.": "<b>Si tu dépasses les limites</b> : une fois le maximum atteint, « Ajouter un appareil » se désactive et l'enregistrement refuse les lignes en trop. Si la limite est abaissée alors que tu en as déjà plus, les derniers de la liste (et les FRITZ!Box supplémentaires au-delà de la limite) cessent d'être contrôlés et disparaissent de cette page, mais restent enregistrés sur le serveur : ils reviennent d'eux-mêmes si la limite est relevée ou si tu en retires.",
    "Accesso consentito solo dalla rete locale.": "Accès autorisé uniquement depuis le réseau local.",
    "Aggiornamento di netmon in corso dal {0}… la sonda si riavvierà.": "Mise à jour de netmon en cours depuis {0}… la sonde va redémarrer.",
    "Aggiornamento in corso dal {0}…": "Mise à jour en cours depuis {0}…",
    "Aggiungi FRITZ!Box": "Ajouter une FRITZ!Box",
    "Aggiungi almeno un dispositivo.": "Ajoute au moins un appareil.",
    "Aggiungi dispositivo": "Ajouter un appareil",
    "Al massimo {0} FRITZ!Box oltre al primo.": "Au maximum {0} FRITZ!Box en plus de la première.",
    "Al massimo {0} dispositivi per questa sonda (limite dell'account).": "Au maximum {0} appareils pour cette sonde (limite du compte).",
    "Altri FRITZ!Box": "Autres FRITZ!Box",
    "Apri la pagina con l'indirizzo IP della sonda, per esempio http://192.168.1.20:8080": "Ouvre la page avec l'adresse IP de la sonde, par exemple http://192.168.1.20:8080",
    "Attesa per ogni pacchetto": "Attente pour chaque paquet",
    "Backup e ripristino": "Sauvegarde et restauration",
    "Backup non riuscito ({0})": "Échec de la sauvegarde ({0})",
    "Backup scaricato: {0}": "Sauvegarde téléchargée : {0}",
    "Cambia password": "Changer le mot de passe",
    "Cambio password non riuscito": "Échec du changement de mot de passe",
    "Campionamento del traffico": "Échantillonnage du trafic",
    "Campo non valido": "Champ non valide",
    "Campo «{0}»: '{1}' non è un numero valido.": "Champ « {0} » : '{1}' n'est pas un nombre valide.",
    "Caricamento…": "Chargement…",
    "Collega il FRITZ!Box": "Connecter la FRITZ!Box",
    "Collegamento in corso…": "Connexion en cours…",
    "Collegamento non riuscito: {0}": "Échec de la connexion : {0}",
    "Collegato: {0}": "Connecté : {0}",
    "Configurazione caricata": "Configuration chargée",
    "Contiene token e password del FRITZ!Box: tienilo al sicuro. Si può ripristinare anche un backup del server (solo dispositivi e impostazioni).": "Elle contient le jeton et le mot de passe de la FRITZ!Box : garde-la en lieu sûr. On peut aussi restaurer une sauvegarde du serveur (appareils et réglages seulement).",
    "Controlli falliti prima dell'alert": "Contrôles échoués avant l'alerte",
    "Controllo configurazioni dal server": "Vérification des configurations depuis le serveur",
    "Controllo configurazioni dal server (secondi)": "Vérification des configurations depuis le serveur (secondes)",
    "Controllo ogni (secondi)": "Contrôle toutes les (secondes)",
    "Disinstalla la sonda": "Désinstaller la sonde",
    "Disinstalla sonda": "Désinstaller la sonde",
    "Disinstallazione avviata: tra pochi secondi netmon non sarà più sulla sonda e questa pagina smetterà di rispondere. Ricordati di togliere la sonda anche dal server (Impostazioni → Sonde → Elimina). Registro sulla sonda: /root/netmon-disinstallazione.log": "Désinstallation lancée : dans quelques secondes netmon ne sera plus sur la sonde et cette page cessera de répondre. N'oublie pas de retirer aussi la sonde du serveur (Réglages → Sondes → Supprimer). Journal sur la sonde : /root/netmon-disinstallazione.log",
    "Disinstallazione in corso…": "Désinstallation en cours…",
    "Dispositivi": "Appareils",
    "FRITZ!Box aggiuntivi": "FRITZ!Box supplémentaires",
    "FRITZ!Box non raggiungibile a questo indirizzo": "FRITZ!Box injoignable à cette adresse",
    "FRITZ!Box {0}": "FRITZ!Box {0}",
    "Facoltativo. Le credenziali restano sulla sonda.": "Facultatif. Les identifiants restent sur la sonde.",
    "Frequenze, soglie e notifiche si impostano dalla pagina di stato del server (Impostazioni).": "Les fréquences, seuils et notifications se règlent depuis la page d'état du serveur (Réglages).",
    "Gli aggiornamenti si comandano dal pannello di amministrazione del server.": "Les mises à jour se lancent depuis le panneau d'administration du serveur.",
    "I controlli falliti prima dell'alert devono essere tra 1 e 20.": "Les contrôles échoués avant l'alerte doivent être entre 1 et 20.",
    "I moltiplicatori devono essere tra 1 e 20.": "Les multiplicateurs doivent être entre 1 et 20.",
    "I pacchetti ping per controllo devono essere tra 1 e 10.": "Les paquets ping par contrôle doivent être entre 1 et 10.",
    "I ping contemporanei devono essere tra 1 e 16.": "Les pings simultanés doivent être entre 1 et 16.",
    "Il backup contiene più sonde: quale ripristinare?": "La sauvegarde contient plusieurs sondes : laquelle restaurer ?",
    "Il backup del server non contiene configurazioni di sonde.": "La sauvegarde du serveur ne contient aucune configuration de sonde.",
    "Il backup della sonda è vuoto o danneggiato.": "La sauvegarde de la sonde est vide ou endommagée.",
    "Il backup non contiene dispositivi.": "La sauvegarde ne contient aucun appareil.",
    "Il campionamento del traffico deve essere 0 (disattivato) o tra 2 e 300 secondi.": "L'échantillonnage du trafic doit être 0 (désactivé) ou entre 2 et 300 secondes.",
    "Il controllo delle configurazioni deve essere 0 (disattivato) o tra 10 e 3600 secondi.": "La vérification des configurations doit être 0 (désactivée) ou entre 10 et 3600 secondes.",
    "Il file non è un backup di netmon.": "Le fichier n'est pas une sauvegarde netmon.",
    "Il file scelto non è un backup valido.": "Le fichier choisi n'est pas une sauvegarde valide.",
    "Il token deve coincidere con quello del server.": "Le jeton doit correspondre à celui du serveur.",
    "Il token non può essere vuoto.": "Le jeton ne peut pas être vide.",
    "Impossibile leggere la configurazione": "Impossible de lire la configuration",
    "Impossibile leggere la configurazione: {0}": "Impossible de lire la configuration : {0}",
    "Impossibile leggere {0}: {1}": "Impossible de lire {0} : {1}",
    "Impossibile scrivere {0}: {1}. (Serve che il file sia della sonda: sudo chown netprobe:netprobe": "Impossible d'écrire {0} : {1}. (Le fichier doit appartenir à la sonde : sudo chown netprobe:netprobe",
    "Impostazioni → Sonde → Elimina": "Réglages → Sondes → Supprimer",
    "Indica l'indirizzo del FRITZ!Box (es. 192.168.178.1).": "Indique l'adresse de la FRITZ!Box (p. ex. 192.168.178.1).",
    "Indirizzo": "Adresse",
    "Indirizzo IP o nome host": "Adresse IP ou nom d'hôte",
    "Indirizzo del FRITZ!Box": "Adresse de la FRITZ!Box",
    "Indirizzo del server": "Adresse du serveur",
    "Indirizzo non valido": "Adresse non valide",
    "Inserisci la password di accesso alla sonda.": "Saisis le mot de passe d'accès à la sonde.",
    "L'attesa per ogni pacchetto deve essere tra 1 e 10 secondi.": "L'attente pour chaque paquet doit être entre 1 et 10 secondes.",
    "L'indirizzo del server deve iniziare con https:// (http:// solo per un server nella rete locale).": "L'adresse du serveur doit commencer par https:// (http:// seulement pour un serveur du réseau local).",
    "L'intervallo deve essere tra 10 e 3600 secondi.": "L'intervalle doit être entre 10 et 3600 secondes.",
    "La nuova password deve avere almeno 8 caratteri.": "Le nouveau mot de passe doit comporter au moins 8 caractères.",
    "La pagina locale della sonda richiede una password, che non è impostata.": "La page locale de la sonde nécessite un mot de passe, qui n'est pas défini.",
    "La soglia «in ritardo» deve essere minore di quella «irraggiungibile».": "Le seuil « en retard » doit être inférieur au seuil « injoignable ».",
    "La sonda smette di controllare i dispositivi e di inviare dati, e questa pagina non sarà più raggiungibile. Non si può annullare.": "La sonde cesse de contrôler les appareils et d'envoyer des données, et cette page ne sera plus joignable. C'est irréversible.",
    "Le due password non coincidono.": "Les deux mots de passe ne correspondent pas.",
    "Le modifiche non salvate in questa pagina andranno perse.": "Les modifications non enregistrées sur cette page seront perdues.",
    "Le soglie fisse devono essere tra 10 e 86400 secondi.": "Les seuils fixes doivent être entre 10 et 86400 secondes.",
    "Libreria fritzconnection non installata sulla sonda": "Bibliothèque fritzconnection non installée sur la sonde",
    "Limiti del tuo account": "Limites de ton compte",
    "Lingua della pagina": "Langue de la page",
    "Modalità degli alert non valida.": "Mode d'alerte non valide.",
    "Modifiche non salvate": "Modifications non enregistrées",
    "Mostra": "Afficher",
    "Mostra o nascondi le sezioni": "Afficher ou masquer les sections",
    "Nascondi": "Masquer",
    "Nome": "Nom",
    "Nome della sonda": "Nom de la sonde",
    "Nome dispositivo": "Nom de l'appareil",
    "Nome sonda: usa lettere, numeri, spazi, punti o trattini (max 40).": "Nom de la sonde : utilise des lettres, des chiffres, des espaces, des points ou des tirets (40 max.).",
    "Non riuscito.": "Échec.",
    "Nuova password": "Nouveau mot de passe",
    "Ora ne hai {0}: {1}.": "Tu en as maintenant {0} : {1}.",
    "Pacchetti ping per controllo": "Paquets ping par contrôle",
    "Pagina non trovata": "Page introuvable",
    "Password": "Mot de passe",
    "Password aggiornata: al prossimo aggiornamento della pagina il browser chiederà quella nuova.": "Mot de passe mis à jour : au prochain rechargement de la page, le navigateur demandera le nouveau.",
    "Password di accesso alla sonda": "Mot de passe d'accès à la sonde",
    "Password di accesso alla sonda non corretta.": "Mot de passe d'accès à la sonde incorrect.",
    "Password richiesta.": "Mot de passe requis.",
    "Per completarlo è consigliato un riavvio.": "Un redémarrage est conseillé pour la terminer.",
    "Per confermare scrivi DISINSTALLA": "Pour confirmer, écris DISINSTALLA",
    "Per confermare scrivi DISINSTALLA nel primo campo.": "Pour confirmer, écris DISINSTALLA dans le premier champ.",
    "Per confermare scrivi DISINSTALLA.": "Pour confirmer, écris DISINSTALLA.",
    "Permessi non configurati: installa /etc/sudoers.d/netprobe come descritto nella guida.": "Autorisations non configurées : installe /etc/sudoers.d/netprobe comme décrit dans le guide.",
    "Ping contemporanei": "Pings simultanés",
    "Principale (Internet e traffico)": "Principale (Internet et trafic)",
    "Prova": "Tester",
    "Prova collegamento": "Tester la connexion",
    "Prova tutti": "Tout tester",
    "Registro dell'ultimo aggiornamento di netmon (comandato dal server)": "Journal de la dernière mise à jour de netmon (lancée par le serveur)",
    "Registro dell'ultimo aggiornamento di sistema (comandato dal server)": "Journal de la dernière mise à jour du système (lancée par le serveur)",
    "Riavvia la sonda": "Redémarrer la sonde",
    "Riavviare la sonda? Per circa un minuto non invierà dati e questa pagina non sarà raggiungibile.": "Redémarrer la sonde ? Pendant environ une minute elle n'enverra pas de données et cette page sera injoignable.",
    "Riavvio in corso… la pagina si ricaricherà da sola quando la sonda sarà di nuovo attiva.": "Redémarrage en cours… la page se rechargera d'elle-même quand la sonde sera de nouveau active.",
    "Riavvio non riuscito.": "Échec du redémarrage.",
    "Richiesta da un'altra pagina: rifiutata.": "Demande provenant d'une autre page : refusée.",
    "Richiesta non valida": "Demande non valide",
    "Riga {0}: '{1}' non è un IP o un nome host valido.": "Ligne {0} : '{1}' n'est pas une IP ou un nom d'hôte valide.",
    "Riga {0}: il nome '{1}' è già usato.": "Ligne {0} : le nom '{1}' est déjà utilisé.",
    "Riga {0}: nome dispositivo non valido.": "Ligne {0} : nom d'appareil non valide.",
    "Rimuovi": "Retirer",
    "Rimuovi dispositivo": "Retirer l'appareil",
    "Ripeti la password": "Répète le mot de passe",
    "Ripristina": "Restaurer",
    "Ripristina da file…": "Restaurer depuis un fichier…",
    "Ripristinato dal backup {0}: {1} {2}. La sonda lo usa dal prossimo controllo e lo invia al server.": "Restauré depuis la sauvegarde {0} : {1} {2}. La sonde l'utilise dès le prochain contrôle et l'envoie au serveur.",
    "Ripristino non riuscito: {0}": "Échec de la restauration : {0}",
    "Risposta HTTP {0}": "Réponse HTTP {0}",
    "Risposta inattesa dal server": "Réponse inattendue du serveur",
    "Ruolo": "Rôle",
    "Salva modifiche": "Enregistrer les modifications",
    "Salvataggio in corso…": "Enregistrement en cours…",
    "Salvataggio non riuscito": "Échec de l'enregistrement",
    "Salvataggio non riuscito: {0}": "Échec de l'enregistrement : {0}",
    "Salvataggio…": "Enregistrement…",
    "Salvato. La sonda lo userà dal prossimo controllo.": "Enregistré. La sonde l'utilisera dès le prochain contrôle.",
    "Scarica backup": "Télécharger la sauvegarde",
    "Se superi i limiti": "Si tu dépasses les limites",
    "Senza spazi, virgolette, \\ e $ (li interpreterebbe systemd).": "Sans espaces, guillemets, \\ ni $ (systemd les interpréterait).",
    "Server non raggiungibile: {0}": "Serveur injoignable : {0}",
    "Server raggiungibile.": "Serveur joignable.",
    "Sezioni": "Sections",
    "Sistema": "Système",
    "Solo Wi-Fi (ripetitore)": "Wi-Fi seulement (répéteur)",
    "Sonda": "Sonde",
    "Sonda di rete": "Sonde réseau",
    "Sonda ferma ({0})": "Sonde arrêtée ({0})",
    "Sonda in funzione": "Sonde en marche",
    "Sonda in ritardo dopo (intervalli)": "Sonde en retard après (intervalles)",
    "Sonda in ritardo dopo (secondi)": "Sonde en retard après (secondes)",
    "Sonda irraggiungibile dopo (intervalli)": "Sonde injoignable après (intervalles)",
    "Sonda irraggiungibile dopo (secondi)": "Sonde injoignable après (secondes)",
    "Sonda {0}": "Sonde {0}",
    "Sostituire la configurazione attuale con quella del backup?{0}": "Remplacer la configuration actuelle par celle de la sauvegarde ?{0}",
    "Stato sonda non disponibile": "État de la sonde indisponible",
    "Stato sonda…": "État de la sonde…",
    "Sulla sonda lancia: sudo bash probe/installa-sonda.sh --aggiorna": "Sur la sonde, lance : sudo bash probe/installa-sonda.sh --aggiorna",
    "Tipo di backup non riconosciuto.": "Type de sauvegarde non reconnu.",
    "Toglie netmon da questa sonda: servizi, programmi, configurazione (token e password), dati, script di sistema, permessi e utente": "Retire netmon de cette sonde : services, programmes, configuration (jeton et mots de passe), données, scripts système, autorisations et l'utilisateur",
    "Toglie netmon da questa sonda: servizi, programmi, configurazione (token e password), dati, script di sistema, permessi e utente <code>netprobe</code>. Restano i pacchetti di sistema e le reti Wi-Fi salvate. Una copia della configurazione resta in <code>/root</code> sulla sonda (solo root può leggerla); per averla qui, prima usa <b>Scarica backup</b>. Questa pagina smette di funzionare subito dopo. Sul server la sonda resta nel tuo account: toglila da <i>Impostazioni → Sonde → Elimina</i>.": "Retire netmon de cette sonde : services, programmes, configuration (jeton et mots de passe), données, scripts système, autorisations et l'utilisateur <code>netprobe</code>. Les paquets système et les réseaux Wi-Fi enregistrés restent. Une copie de la configuration reste dans <code>/root</code> sur la sonde (seul root peut la lire) ; pour l'avoir ici, utilise d'abord <b>Télécharger la sauvegarde</b>. Cette page cesse de fonctionner juste après. Sur le serveur, la sonde reste dans ton compte : retire-la depuis <i>Réglages → Sondes → Supprimer</i>.",
    "Togliere netmon da questa sonda?": "Retirer netmon de cette sonde ?",
    "Token": "Jeton",
    "Troppe password sbagliate: riprova tra qualche minuto.": "Trop de mots de passe erronés : réessaie dans quelques minutes.",
    "Ultimo aggiornamento completato il {0}.{1}": "Dernière mise à jour terminée le {0}.{1}",
    "Ultimo aggiornamento di netmon non riuscito{0}: controlla il registro.": "Échec de la dernière mise à jour de netmon{0} : vérifie le journal.",
    "Ultimo aggiornamento non riuscito{0}: controlla il registro.": "Échec de la dernière mise à jour{0} : vérifie le journal.",
    "Un ripetitore o un secondo FRITZ!Box nella stessa casa:": "Un répéteur ou une seconde FRITZ!Box dans la même maison :",
    "Utente": "Utilisateur",
    "Utente o password non accettati dal FRITZ!Box": "Utilisateur ou mot de passe refusé par la FRITZ!Box",
    "Verifica in corso…": "Vérification en cours…",
    "Versione installata: {0} · sul server: {1}": "Version installée : {0} · sur le serveur : {1}",
    "con la riga WEB_PASSWORD=... come descritto nella guida.": "avec la ligne WEB_PASSWORD=... comme décrit dans le guide.",
    "del server": "du serveur",
    "della sonda": "de la sonde",
    "dispositivi": "appareils",
    "dispositivo": "appareil",
    "e": "et",
    "errore sconosciuto": "erreur inconnue",
    "es. Casa": "p. ex. Maison",
    "gli ultimi {0} della lista non vengono controllati": "les {0} derniers de la liste ne sont pas contrôlés",
    "l'ultimo della lista non viene controllato": "le dernier de la liste n'est pas contrôlé",
    "netmon aggiornato il {0} alla versione {1}.": "netmon mis à jour le {0} vers la version {1}.",
    "non disponibile": "indisponible",
    "principale": "principal",
    "ripetitore piano di sopra": "répéteur à l'étage",
    "solo Wi-Fi": "Wi-Fi seulement",
    "sonda": "sonde",
    "sulla sonda (solo root può leggerla); per averla qui, prima usa": "sur la sonde (seul root peut la lire) ; pour l'avoir ici, utilise d'abord",
    "{0} · configurazione": "{0} · configuration",
    "{0}: indica un indirizzo valido (es. 192.168.178.2).": "{0} : indique une adresse valide (p. ex. 192.168.178.2).",
    "{0}: nome non valido (lettere, numeri, spazi, punti o trattini, max 40).": "{0} : nom non valide (lettres, chiffres, espaces, points ou tirets, 40 max.).",
    "· FRITZ!OS {0}": "· FRITZ!OS {0}",
    "· IP pubblico {0}": "· IP publique {0}",
    "È il nome che compare nella pagina di stato del server (Stato rete e Impostazioni → Sonde). Si può cambiare anche da lì: i due lati si sincronizzano da soli, al prossimo controllo. Salva con il pulsante in fondo.": "C'est le nom affiché sur la page d'état du serveur (État du réseau et Réglages → Sondes). On peut aussi le changer de là : les deux côtés se synchronisent d'eux-mêmes au prochain contrôle. Enregistre avec le bouton en bas.",
    "È la password che il browser chiede quando apri la pagina della sonda: la stessa scelta all'installazione. Cambiandola qui non serve riavviare nulla: al prossimo aggiornamento della pagina il browser chiederà quella nuova (almeno 8 caratteri, senza spazi, virgolette, \\ e $ — li legge systemd).": "C'est le mot de passe que le navigateur demande quand tu ouvres la page de la sonde : le même que celui choisi à l'installation. Le changer ici ne nécessite aucun redémarrage : au prochain rechargement, le navigateur demandera le nouveau (au moins 8 caractères, sans espaces, guillemets, \\ ni $ — systemd les lit).",
},
}

# Limiti dell'account in totale (condivisi tra le sonde)
for _it, _tr in {
    "(li decide l'amministratore del server): questa sonda può avere fino a":
        ("(set by the server administrator): this probe can have up to",
         "(legt der Administrator des Servers fest): diese Sonde kann bis zu",
         "(fixées par l'administrateur du serveur) : cette sonde peut avoir jusqu'à"),
    "(la parte che le resta del totale del tuo account, condiviso con le altre sonde).":
        ("(what is left for it of your account's total, shared with your other probes).",
         "haben (was ihr vom Gesamtkontingent deines Kontos bleibt, das mit den anderen Sonden geteilt wird).",
         "(la part qui lui reste du total de ton compte, partagé avec tes autres sondes)."),
}.items():
    for _lang, _text in zip(("en", "de", "fr"), _tr):
        TRANSLATIONS[_lang].setdefault(_it, _text)


# Caratteri della pagina (copia di server/fonts.py): Roboto e Roboto Mono serviti dalla sonda stessa,
# senza richieste a Google Fonts. Copyright 2011 The Roboto Project Authors; Copyright 2015 The Roboto
# Mono Project Authors; licenza SIL Open Font License 1.1 (https://openfontlicense.org).
FONT_CSS = ("@font-face{font-family:'Roboto';font-style:normal;font-weight:300 700;font-display:swap;src:url(/fonts/roboto-latin.woff2) format('woff2');unicode-range:U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD}"
            "@font-face{font-family:'Roboto';font-style:normal;font-weight:300 700;font-display:swap;src:url(/fonts/roboto-latin-ext.woff2) format('woff2');unicode-range:U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C4, U+2113, U+2C60-2C7F, U+A720-A7FF}"
            "@font-face{font-family:'Roboto Mono';font-style:normal;font-weight:400 500;font-display:swap;src:url(/fonts/roboto-mono-latin.woff2) format('woff2');unicode-range:U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD}"
            "@font-face{font-family:'Roboto Mono';font-style:normal;font-weight:400 500;font-display:swap;src:url(/fonts/roboto-mono-latin-ext.woff2) format('woff2');unicode-range:U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C4, U+2113, U+2C60-2C7F, U+A720-A7FF}")

FONTS = {
    "roboto-latin.woff2": base64.b64decode(
        "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"
        "vh0u7hI+6c49y9XVnxF7htHvhOWF+wPrETaq16cyVddV8J1FU5ZiYXGPzB6rFFh6xShaQJ3vMR0mgjvNr0RrZo/I/BDKih/kfa70"
        "HcQaRImG9vvQMG8Y5E4QzuSNRO4/iejF79szKkMya3106WQ1V91KZbUZyc8JWUnCA//YtMhaHWaOdENggnDvBoy1BiErVOIMDDeu"
        "FhwAWMC8vqJXvm3ZtwT4nd6IDMwKLJLWYq2hbNJz5+b/inKHCcFiBisldngHEG0Ewk3COrXpBxsseMEqrfKcX7eS9yZZpu20VWFg"
        "ctP/pMPNu6i4NIsXdpgli0mwOfaLuPn8V/y757lgRcb67rZRsTWdbduebjrx6xkgOhL9RBsIcqv1JmFu53+PwsBv9YZv4LjAK2gt"
        "NujQI44P5nsVeLsTwZL5Kqn2XR1v7EpAgaf1cW/rEZ5T1VOqN5ZNOO7e7NPhbY5CNslQVM2BGMBmq1w+T7iY+9+qSiclt0bp91on"
        "r8lC4euytsnciRaT7raxr8rC4WsmK97I3CqFDgt8EbJQECbzfbBh6VYJjOP+cLVdHZsDawGC1Q2WUW4CZKhmKrNVtLnFabqvnXJt"
        "TSh4V+qb3p5DO3rGsAfOHWZ5fWQBn57JZMcbeAUvmeW7v7Aga54FCGXD0xqADNlkXspKVj4IjM2IHI6DLG9PdVMwqt/0dh/ezTYj"
        "9bN5K+dBn5fMu8fF3A7O2MmVuZCcr5rlzx35vc06OjpPuKpcBs6HdOygmAvobJhFS7LAzku7WnjqzXhgUp5TuIfhxrs3azaNom1c"
        "jJVOwYdcqolyXcdrOnPKMF9aUWPDcYVGRDG7MFukNOfyN3btPi+XN6nYhKi/JoUwjdyx249qb6bzxepIfqXAUYBhAmg+YZg7fGf5"
        "vAVuqzRna+EtkH+MtdaUEcLQWrwAhfyF2UK4tP0LQVoM/Lq1+yivXtxRajChDnhvzr/BhRh7WFmw2F5t1UHw5Cnpzok3t9UQkuua"
        "bDMzU5uPJrd1EQDncYY1Ht86l3Flb8NqWcL6tyzJa82ZJwiUxeb1m5pvZOaOzJyQkR6d/SS2CT2w9QJgyuTf9s7t/WTO8uY9+3nq"
        "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"
        "NaMeMM67GnE7WsTEsjA3ig0AAAA="
    ),
    "roboto-latin-ext.woff2": base64.b64decode(
        "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"
    ),
    "roboto-mono-latin.woff2": base64.b64decode(
        "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"
    ),
    "roboto-mono-latin-ext.woff2": base64.b64decode(
        "d09GMgABAAAAAFlUABEAAAAAm0gAAFjsAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHDQ/SFZBUi8GYD9TVEFUgRwnHgCEWi9qEQgK"
        "8yzeHQuDZAAwgZkCATYCJAODZAQgBYgYB45PG6yNBxi3X3A7YNou+a1uJELYOIAgaBMjEcLGARCFDSf//yckHUM2MAeAHn0FmmKC"
        "0mEIySQCZMBQXDsqEFWuJF2kPXhir0R72BZBuJvwFk6EtyBB5DLC8mw1WyZhxIqVIcI5dud7x78kQhpI5SddUvJDV9aLcuW8pgbV"
        "ourXtNo0ETRxfLXhPjjKnY8D+6D7In9t68mDUpszVg0S/2mpkrOcAe6woilOHp6nTb9zhxEgxKROLU1dyap56PysmHvm+fDXfKtI"
        "jMQmmchoIsPZBH9cpC1KYAe44WFu/Rs5Ul3B1tRYMmpBDBZNjhgRISAhGETZo2eQJgrCoIdd/1uBF6lnBeZRTquGahbYimWHHIJD"
        "5te+DiIpOXwtM14yEDKLeuDdzIcWWiwJcSdKkAQS8NYnKl9PrZcnKrc9E5lpJ969E93WUwo29Q+VFOq6Zfj3rF7ajjPqrbug25P+"
        "JDWbkctUcaGk9so4DOTZf5n5evDtcx9RIklj1GnSRm2n9UhZ3vYEnsCThFlQnec3rVIbXR3Zzop3XfXz3nU4M207Uos4CRA8iAax"
        "BEKI14bcKgdY9s0kad3aFK224kBMiiYpevFKxM8UfIcxHcLTdmmTYlDbQcQD5KDCyRHUro3tYghuLoakCH7mX/IPgEWdJSUs2YUH"
        "mmhcAy0f0fbURIu9Nusjw7Gc3u1JajKzUFITB6byMkeBuYVcIZNp/zG3CQqbQ4eHEvCr/Lr0pfdiW7r8/ZScrmO5quV0LfEWfVgV"
        "sK8CUnhxpmu/jpVxP11rATYRKdtLfKMShqr+valm+x+A0y2lBrq4l6mLsJVA3oxrpcpdyKXYrVP78UESccElQJ6XwXMrXFpRablM"
        "K+U1LpJySpRTJBwJR8oz/lilT/LCJy8t5bQ6XYAcL8TOIabWtavGbWuVHtf269eWuf8W8UiLu7WdOOIaCZEIpUFoTGc6UDJWzibq"
        "PV8sRxUBaV/+6wp0bONpLmKMKaU08obj42uNx2qu8lXNDYeFhfg29Nfh3pzXv/g00nQhRkqe468L0DXgyeSylw+OAoTbVJcVAswd"
        "yrIKAOauaeXFAAMgB1ICAVgHmCHGx61uKmI95hV5/oVoYwrFcwsv8lvio1pfkZ2B0N0x4cXAI/R2vfIK1wiTAwGbrdOF9LVvAP6q"
        "jN7PQF50jQDIzxR6Svsgs9TLfkoAPXIHowfcIbd8Xnr9yzdBlrGJwqHwJhEuUa7BIDp7II1bTCxiH7QmZOzx5Eb2/vzGTvwd4pHs"
        "hm60bP4WG3tMABTbpuvDVvnsdQoABbPXcxHHIACUabmZahOjSXb5JH13AVNuIVUig+Ee6qiNjhgKfbwOG45l3CwuO5pdyC5lT7J3"
        "LdyKV3Ra2y0gZCdGwjtGc/ZvH+TonWP3jT00TrXjjBTcJGXAkew3cDs+trg0HBaosdTMnHBBeNto9v5Dx36t9zVJ3cjE3gO55vkR"
        "+vvd3Xxy/fDi7/Xl484ym689s/bA2v1rd62d/JJd+xuQ4Sf/C7se/daRbxy97QepGBb0C37js4lxKPs2cnUlcSXRz74uc3R9QjGb"
        "izaWbC3fXbn/7e9k91YdFA7hlmIANSNtYBPWgbZ/93t4J9lNdHH9TC/Vw/bRGz7HDwiKu6JSVksqRaNqNays13VHpdY6XjHUTAZl"
        "Mi3aYm1rx9I2//gnrt2xDTw9t+dY4buuPjfyTYOzn8Lr0bXI56vGdOUZxbOWj3WSDSkzY6VJpaZVmAMBE4zYJJnzPyUEkNk4nsks"
        "aVsR/nGzaIFPB/MoqmJfZxlVxSnRjk7i7wp2Y6Qqu2FnL0alsjE260reuFD1F8H4qdvwBGD0LcD0tQCo+kB+R5N09jTBqdAc7Hau"
        "gV+G3Y4xyZdLviCR4mRZsjGNJXa+YV5gPkcGrQJFtqhwuCpWjrEH4t9ONi/kc2wxBzJOd+1OguPqDI+yNt04vmx5jqhYXrZnvXHU"
        "bLy7uIhDqjZhumh5YqZNYSrIWS8Blmf7DEOsO/MoV1reil2HAPQx93M+ZDLa29FCzAgWlqOO0dYbGLh83+BshMG0RiBlVwW2i1HB"
        "Fftqcc6ks5hjejQvLPz2rLexa5mv21yy7s1tpiom+cb9WMkkX+jtViBtLmnE3XzYZ/3f8sUhrMpJtfGzI5wP9kj8g0cV+i1LCe7K"
        "UYyjqXyXS2IuQhCy4XahP7ksGVeH7FNCtGbalZS1amnk/E/zX+oxYPgFyz8/IvwlV0dfqUu9+G11gh2I/46a+HTTU/7LnAn8pgh/"
        "ECUHoJBgza1jo2jMM34ar1kcBwp06wqSfqR3G3l2ca/2V2wPZ39oy8d2/l7t1Xwq2K97AjpS0EQVa5TgRIPx6qHW2U/rDjLcvcjl"
        "Mi0kDfKu6k5L1t5EATEM+iw9LwWpt7p5VF7vlELo5cbfcAz+wxq5yXcfvC+cwC5h0yfdh05vukfyZ5HXL2243oo2SCb20ee/r6Qh"
        "UCnxUD1QTtBg+EpWDe99g++Uj2ofcSFmpSrxj6yyYGZZ/tHXFoWrQBcsfu3RXhHlng1YZ5Zte52RWefm/f+jz2X3EhV9HgpNS9aA"
        "+ihtYpPxmtC1riD+MO3W2F3AYQZhVRNgaB49BScG0gLGzM1YfrvQbmkpawwH3tkwXspC/VVk/sLGaxKy9TMZ188b/JWlIw5purzd"
        "T6Ys5L3exIEU7hRSBDzx9GQ6u7L2mQQ2bWeHT6ltHqD23x87DNCrYFkFgLEXcXSf8gsZ9j7iGTPGlFxa0ujwWxu2TUhwZc2sKJKK"
        "WXp4+ReIdWz5niEbwWP/L/HVsWh9P87y0jzNJGEExlj7hxWhiMP9Na/lpFUDN5aBgEMbx8Mtr2Z2cyKV7SJ3wJj5qq5J7bBdVebw"
        "+pAEkW0cfIPsxcGXqknW5yvYF0/kCWsvCWBQfRF5pe8mUR2xfzve1FZ+rtJi6lQJD9dVG45+pkES2UGgDX57F23v3ojo2hw3LWBS"
        "N3LX0lHkKNBeMVXijCUTsu8lZn/4kya82aOvUTU5puDImqVEc9h950XkmVw2S83DPO3na2eSDY6ys1VI45F9tKAvUZEcOC9Y75sc"
        "6QssbwXjGYG+GtVAJ9RxqI24q9uDYb9AcfbM+5JyDG8MzXVdFvGWsEwiBNZmmfGqjgGEI1lIaaJb1WStCf5RLiWA8RewLYwIb+jq"
        "64IDt9DAxGBP2cX0P5S6chv6ViDgyYur5O3MmOtTtIcxuh/AXnS8MvbfsvaU3CShBg649t9Qpn4TuwOxXoAuUUjZD+PyZE5/2WBh"
        "+oMCBBz8AbOed/OiL0SQlmk8N4aCKtOHhBWOxnSOJST5GNLogWWwaVgfVsNqWXe4t4G/UGYilxz6x5gkqaBZrvhkluwZhlzDaIGX"
        "lP1XcmrPZn/lGXJvHDAIOt+kwAYI0g3jMn3uhM9TTrlxsSbgUMg7+Qt3FrfsbMPW0/eS8kw7lha94lWo2SV+smxAZZRHwBrJ5bn/"
        "L1ri6/X7QlG5jhQcF2DAlGNW5A4aYzIoSO9f/YU5cw5JWlfeJadGuh04ajhbcMw4wjqkcUJ/Y4Xi6VpRMvvkJZB7MpibRmm5wfsO"
        "cBZ0BKva+aFb+QrzCn/I2vQJGTJJ/SueaTnFPXG1DJToUnLpWZsSy4+3ipGstTj/CtH0/56TwS6MX3TddZNeYH0v8uXfPfRnUgsG"
        "+UPihSsvGrnBf+t9dMiAWe/J13eHVwltT3lVm7aLKbXh+BU28AXrVT94Wx71wFdv21kuRjIji5QHslPEbVJD3h7wCrxYE++oh2+o"
        "Rz5VPa5dZx9eBSrCpGX0s6F9mhSIuHV0/RBR3TWW2KkvkRHf866XqmdX3i7cMF+x5BKpToWKws5E0pJ80yiTwYaS8ti4wqta2DGf"
        "2uQ/tF8yfiu/BtqZgGlPiHbhT+cNQ3v8i3A7OTKR+pJtF4/oV94q4fzhmmi7ePk5RNJAFf2TU5kXgC2O9HNbZ81IeSB/vXMgEVsj"
        "I6FGJaaVClFwoM7iYvFRTjn8b6ecyGkCF4xFmupQW1o8LxkpyRqkR2bqLuXYFEKpG7MC0uOrNQOdneisIO+asQZCpl1364VAJjrR"
        "oO7oB9vlkteywkQAXw7tgN24bXk1o6XZrQrBBK54zA896ibSeC3pXckIHm+dI6180clKyd2DzjbA1N04SVq5sMFou377lX5di9Vq"
        "+v/aApoLW4VaqJDItA27+X0wFuBAqbYPqTkV0gPq0V7J2AD2COpj9mi79tNl3syxBSN2a3052G5ILW0EXs7RMGk6hu1SuPQWcPRM"
        "Z5HxmVnb/PBKqxZg5o+9L/871C5b3C05P/9qtKqGJNVBZyu9y4fMPvkrFAMX4X9+tpaTubvXTQPAuQMClTtia75wrQP6WavPYplI"
        "N0V5KGAGd2RP4Od3KuF8Bp9w/Cd+4Mi6slp9k6OuLls9j/tTvwufpTeUr/YYPF11ogqM3kwEY1yRt8grbBfIEpJXMqBZ4kJjmcrr"
        "z9uOSVCQFdYuclsfyyOMODBhtcfcdSjLKVxNS7Hhu6WUlOQ4t+H33/h+Zja6psAtmu/Dii4syiC4A+n/Zw1QIb1EocxnKsUZNKmE"
        "lfb3X9ZlnGsc67K//nJPk3hn0kTKfHeVil4KFRqsclQjTx6PiIoS2j239EbUYORYOaYPhF8BAqbv/H818ojq3i0dnvF5h0T/PQoZ"
        "BrvUuWCaJWeIaUXVTipHufNIagHIII87KymaDU2xlO89pCigPqLrloBVuH+FjvElGKkUsRaIi4AIXuONEoTmRjo2uISBbuD/dqgv"
        "9fbR/gpgyq/vO2cC+A2Nfclvz/SvB6b8kUYgPXnCCHm/lwKRpYopBQUR5uFCkMPIquBm2NktLzcb4dis+vTJIzM6OoshkubQoqXM"
        "/LE5aFbI3i9LIwHZiZ3svrHI9VglVokZBOEHgZowSFDglXHrjh3v8Y4DsWCIIqW2BglAIDDlx8uiy8aAKT82FD0ELE/ph6JXRg+W"
        "DCatTBoC7G79Bzy52EeZ4y4SZFNlUloO4yg0U7n7/qX9/OysQ5N32T/U73xDFP8N6JddTh87+eAVx5780T+GLOZKywB987UXY39/"
        "PnT6lwB9c2QEas/gT8XYmy95fEz1d3X/ubuOAH+Mvg365tc29sQ+ZOLNVwPnC+q5hd+M0LILEJAxP2BN+0GI/QBaiVGG19XWtnPi"
        "49s4tSUzuanY99cjawXdt+BXQj0JtAVrw2sB7cXMh2Fjy9K7f7tlunDSmUJhGpPDZmX9/Zd1qdGwkXXJ33dZmbv4IC44VBlszvbe"
        "/tc9qxKgVePVZ6y8iwwZysBASoW8OHi3iC1mT7GzICPAlJ+P2O72TgRKnBoambkyESuzoaPI+X8gU1/i76XZvCUXw5GUOU9PcXOh"
        "4mNGScHbhTyl8KI0N+awu2T1mKVpT08L7xR6ijhDsnB722LXF98HGltft5h1RZl4tiiXEhXFzF5/HJKhHhLzCBsPSNEc9BZ5zjyi"
        "Mzk5YpPQU+DRLwu2F5RRf/zsZwGFFNbP6z8NHhFPHx4jQGKqnwJeDyEClyp+aAFHLi/k8kPIVUAAxA/1wOkhsKWTfCFfdDgoP/dw"
        "cIAoQCifyAZfllbOVod7rRDWx6yQ+nGzzmcJh6zgz4esjJ+NxJl1/qcH8bdVD2/hItuNCKNGhNP/Ut0ESC+zvAWyZVf/RWZUA0R7"
        "pg9UnFqOg6/mfEoQtm7t7WMkZvVzC9f5llouONrevavBcv2S8ZZWTiEe0ZdLZ+kCuoAha46TeJdbfOnw0LCTkB0NEo8jDtf9qjhq"
        "7PABjJhCIwjvtW8jpY4++lmK7CQsqKmPKZe4cgib5DQZYSOXUy7R8FJdSCSKBoxHCLVdewb9U9fMxfgr+Sr+mQJaIf80X+mvmotZ"
        "o+nzPXVS0QDk49aM4KDgZCLY5IIs51/kKrnK/sj0zG4xW2heegiYAYNHSJsgLWNAzVXwFP6X57ciwxy2cVyKA0MTqqOchB+dZNWR"
        "SSFFAS5sh61gM7z/7nq2uiTGU7gjLCNoDVd/2L3KLNTcNLKUd8pH7iMbC69I0gdJZFJ55PVGWmnQCbFULD0eYrrnsjzbC412KfO0"
        "kFmqOGVVlRkUsNkFWe53kavkKAciM/yy7HvG/pYnyVwLxFF5LiIXpa1AIOfZpxRLsuXlWQUwWvYBv0sG0b4Cp2FoheuB9UcL8cIs"
        "7NhTvuMAaTK3INTvf3yCX8OWbv8RjHLHj0hdqFU7cgyUjwpggc634uKwnieTHH+7gU8VjBgOFnn3Gxtvco8WgDIn0Af+fhx48+/X"
        "+nX/gLd/VH25vX7w+ijAXLw/63eiHff80D1f/FjiXaa3BJYfS25dfvzNW9z516HetPC/oPnyKc4PpmOKLVEnXX9I3LtxNJrhwkHT"
        "U0KdyuCv4ki8Oglcnxxzd/hvZrsERg8C+YFQMGaAOlLvKGJwXn7x2B8viRmKEcN4oXevkdEmVvQvJY4/SVup9cB+UE1GVYgvBCoD"
        "lLORq8pmIi9wKVFxR7wYoAyEqGTUBBtjfhMqzKUtW1MqCAkpE+Q6uS0MFf6waLLLAoNDVgUKb/9/EnC9Qyvns4WxluZtet+F2RWc"
        "8CBtEUnCTrVMsJ8+UmwDuP8nYviOL4scVawUeE6VdwjPIA2oPTE44lucOsTcsUNQoRDzsjTRfZwMRJBtOvHMrVIS8cGdc7FoP594"
        "4tKSk8jJIPevWbduwCszaadHTQ2/TCT2y8yM3s5OhAXZZjn/+WcXIEsFC2Y4LS4403vLo8drKQq6xjwnW4goQjcYq27/8VGgKuDz"
        "c0R1YHCvthdUDfsuQH+7fNsnDRfADsdOTmBXxTYbGqu9R83NN3pH5w/FssMAqmN/D+YA9sBwT4dtpu/eqgnMQdzBkYmq0QnMTuTO"
        "dRN7gYlfuZKt0/kmUR2jfr2BOua5ntVAMdzAO5srtZ3MtVv+Jdsa1eN74FIrsLmHcovUWLJjHSUDvaFPB0Z0WQDmpnOD3FVvlziZ"
        "6s/XpHJA6pLtPzOQUyAFEH6JMAbu8SVm65eYvJrDZL2GtCAeiCvQOmuWnkXRNrQN1HirWWok0i/s7fv0BKcomKeigtaiYxRLJ81d"
        "qHBnKYl4842+QkjrCsza4c609qhTS8klMnkBXe4eZmds7MywHKnflYe72u2cg3AiE+mE4GtXIx3ZfCEQBtJdV1y9t5T0lX5XSgkb"
        "q/uuZtouw7v083zgAicAPbj+8bPn8RcWn27dWVQFN/gaYgEZERa0FmUEU7GGFWubzvLbsmH80Aqf+lB6jYnU1ML0/a95XL1WOyqv"
        "SAFjYSK5UBZyroJRITsnVAjlR8NN91yR5zBMkaQMDoY97lEkj01lAu67Ee1tYPni476/TCMIAEW2rBfV8UsskpW6w0ud7tOVmjGh"
        "nXgKQFLad1GTIyp52Q2bzoywZdToFs9fnnpok56CiMO9mjjjjUlr0kznxc7579/Fkr3cNRistWtsoCGGu9VTpOOmpu72OzAvHMo2"
        "nR9Ys8dk43DNqJGMBA3fs5e7P0hnBnp+uxNZWG+ucjGSAeXvI1q9mcEszlzN3jChr+GG/gAob2BLQ2s4p/TeG83VcY2RjlUf/op2"
        "8qaFI1PtG6cOIpDuk6eeM5pmFoOlTIEHzweWz+PBcniKN0wgBjpdtw64mTZ2zvRo3DrdZJnyzsCEdDUqB0gjh3Z0Vxoq23a0DRmG"
        "AMNFAx62v/JT/s/hFrGSWCy8TKeT2lGFUdgThNWfRK9pPEdnnGg0ZsTRfRGtFNmH1Drw8uWIWHWM5iNYUwC6vzV1bETM/pdAB1HX"
        "/qn7c7vu8d/dFZCRMK6EK+UeBcVFoJhzjCvlSUfCK0C3MRCe0xvoxCYXFwPZPyqTOE1PYNtHVP/cYGA9bJuOS66E4Aq3LWtpdRGq"
        "bLcr9jw3u00Ic8Up4MXtOx2jOrcJxGe1DuMO0Q5jDmXaMqChDjAO6rQ8ofp09Gk1pevqe0zMRoakfnELF4LkmmzjCueOy2rvFZJh"
        "6Ncydv8cXZXU9120NY3YDaS7m/ZDMlwv0WPWC91rn5MqgPyAlY3i4YXw1pMiTsZsjp1/6cEoviIsSQ3bvL+C/8w32S/1ZFVr80JZ"
        "YDI/3uf9NH4YEkk6TpY7S9ZExcZWqZmMEPKp6OEE+i1eqHdxYEhYhSKOpaCeBWhDE9gHijm/c5MHl21LP1CV+2omx96/4UiJb4wo"
        "yf8z5EH7+cvWWn2dt3L5gM22nHHtVk7C2rk8/yhpivCbN1g7HO64QAkOWx2fQJPCTvVvhxKdgg5CE/qgSRtvDkOSna/7RUQWBoaI"
        "MtwUhKkApm0d8L3F1T2XnNYxLxiSRd0id5r7W3BHmEmVe34/ZVPSAZ5tFA4/ce5rv5Yd8bi/0FewLyTbCGIMeVpb9+wzF6ZfX/TT"
        "c9gI8tWMOCrVtVUFOK9ti1TVbZKa8sZnMIFLSRaz95M7orMY3by8xfGC8x1ahzRriPNN3TmdQfdz3Y4Une/fnmXv37tcu7rD6c5N"
        "RqwCW9ctL75576SiuTGqDHYDnuD1Efb59z+CkCxV86/ovIG2tKXOLMaOExBPPD2OyZD8DNVDWn4+k8BnpTa9D2IIylXUykeslljj"
        "Qo/+339r9dBISsk3O0/7W1hq94OWjysVR0USgWQmrMgYYgxhcXLZdtovmSg5ptkAkdivTIYpqE/DWt6Yiccmf8jsG/mvS57lRf2T"
        "soprrpqslKabOpjOoJtcf4E3DbBAxK24eKznYCLpl6fEdFE382dYkokxZIsCD/gAa7/vUMlSyWB5atM7V+doOkKXTljB5rij4rTB"
        "tJ3/wzILeNw1TLf1XF4xYImveVH/Qvs7YsfunxRH/Xx0NpMawRCo1CS/uyVS91DEJbcyNmAKgGCYbi15cCFNd7bPN7VHIYrnB+zK"
        "e5GuyLy6RtkzmAzj/GSjYNymQ+Wy+MnHJSo6z2QifMAPRBYsvx4985nVm1WyPpDj1aOReuTUyJdlt1QfH9DCA92Drwqk6+sz3bMF"
        "FfKbKfJ95zDbWv31/qlPH1iALrz0jCymqPoRJ8uuYccO2OYpQIBol6DhrGqFAnfXYnPdXngcJZ4ZoEcZKV+VIPQEnrdPjFk8/VTk"
        "4nJpzmKLlQXw+OP7i69K3r/EbO/q6e7ZCbz23crG20GvL6qRrgL8r6+neJqbymVsnBDBzLGz4QkY2GM+tNg4Fd+BGeQ0dpigBv4z"
        "DtrLWuCDnOwhoODwHFdKVWZAEXr8aOmhFZGlkoRzBjUdEF1C3fp9fPrd3AecPgBWfEhgFnA4a5jMteiFh90YhbO2lsFcJ1dFAL2P"
        "RCfJ5w+qsDSaAmsYJsrpdKLikEGBL/3TqfAHF0iKdBra/uXjZCQq9MniZ8ruw5MnYShUyuILU8CKfvW58hp3a+cj1j3vrZGl0T26"
        "PuSX92XfP8EGwX3XjLu8spnQXHZE6euBxu5NKFhwNMvnZyJFGHY0j94rjsw5C24My/TKIOf1IblyGV85mwxRHrfvBD7iGDncjz3Y"
        "+iKGrczOfsFNEhaXsRDjUWsw1FCUMXXMkV2U9eoiQPvDd2ixP4ScjSck2HvbviYHvY2s+zJmhDcnHDJ7udkaXn9u4OuhZ0t7BzcM"
        "Pt15yY5ZyOOuZTJzyCSkMxN5vCuYObvvJoOLC9lSp5VkcjZVgr+DQG1VyKxcMgf8Vm/0Hy4CyyW+Q4WDIeRcIjEe420Lhgadjax1"
        "q2bUp4ccMnt52dG8gVwhGP2HVCESlZOIUSLPChKp0ksUTSwq4srHf1TW2TiMBo+LwuCyACnq6Pq4yck44JBtVx9fbogHVMSDJiCb"
        "WqVW7yO7u6vuReYihGZ5DnO5uYdRKJUcxYUAtgDZJ4mjzM6gCiUxKV4dbZ5qj3Cv4RCqgrzKh5fB8A/MJkduX3nnnE2s59P/cmx8"
        "9bwcayvbLM99Kr8+YfNu5Xut16OXBP3WeSyOf1zxhmtOl35Z1zO4WwDiM+rr37N+nrmJdnPE0k3O4rftfZqdZ3FbfEX7u7a/N0f3"
        "TP36h9vdc1Lus6NGdmjfffF29x3V++2KY9fdnl+xQ82Sszfbd8AZo0XmoPJpHje1BQmYkRYti2drATxU8ptWncZokroXMcIkPhSF"
        "WsOOUsmMRgkzlVriIpHMNJmpN8sPZgaSuImxwywIWovoOExQFWivkjRNNDeEhSsV8pa0JuGa3lKlO+HcsjvdZZaSi440bjUyTkWo"
        "sMbZ5h9mc5AmDi6jh94mnTbNNb9JSfnaJ9gyRSVHjPGGubQMXVMtLW8Y4FVGq3ZEiRTYRQolyeKa6KYVEK+OIKUxjmsaFdZLsGLX"
        "0IcCBjZlOlgyrvUpmzJN+ivgpXBNQhjdyIwtjFZNRZgWeESAVjBiu+QmIpohNbUuYjRTGwmLyswlSe3iCVV86yqI5bRqAJvFkZ2K"
        "63NG2AGlSqnE1TjYHyyJI5o0Fsah+P13JtEFcTsUoSnqhDxY0jYz2QKmG9oazHdGysjsKeCxWo0yJo21ChtLJQaFrgXDxeI/NTG7"
        "2zp8V7EOj5IlsgZ/uapxbIKRcOqQ8R/nWbLrkrmXVogwSgbSm9/2Io7YHX26iF88OIwbyc9PNN1sfs++F5JS+K79HxwOlujdZinS"
        "/oMxda5zDHpHi+toKKlqVQs0CjnUD8plrznjnbDnhrNGOvNz7tSdauRs3DX1CXeG8Qrljct+Nq0b1cBal7+0h0P6iGwORIKMzUw5"
        "udH6kEZKut/4io2svKvVxkMDY/bwYpBcInnyw0Sx4zbreEo28wKitoM7QTi1sXMubUs78tor//fDg2yjDV5+UeJdHZMobaIJigzN"
        "cZl/Mgc5XNsPeJin480011PT8MsrwRnc09znLt1h6uEeNwaZrDQMAez60dotv2XckCXb5rAiYojEYC+kM9ptvO7MPPU2Xv/gaS31"
        "/AxLT6GdxYGUkdfPfDrU+plfTWuKq41UAyN0rISYv7xhl7vByuTMDLa+HYRPjXLtVw/5+r21Ofvqhw+oXVM7m34B+onHrgQmgfx8"
        "oafO80+uVD3ll5Fte6Tnva4iKUhWnlSxJyL5cUl2Afk9K6VZomOVSig5+jnlF5nplydWKZMgKWx2PrY4ayuQDyqFMaLNlYqjk9EK"
        "9zkR0pOVP638jDYB+d5C77yGr1ABMri64UENrFbRhYoUKIs9EHB0frLytCoFYGWZ3r/MLl3mlirZDJDfu0JAwC+OQhlUdvIqNgTJ"
        "YXPZdcVZaiUJNnvJiN1sqagKiMXGvKh82VvVzi+jBPIXVqQ7KQCd8DsPquQgiOioLDpZIQR/Xhvn9F/OKaHrinnAu+jyYPGUdtir"
        "WITe0nzAzL6gOFGitI7NpaUFh/YW9+c32NJoAF9ChdnjOtPfQL6vWukK0fWKd2Lv7F/pmyD6oVjfJ4D8EuQ2V9l2qPmm0sTDxqdo"
        "R6+C5FMlpM+HdxeLFJbmYcN7Sh6qJll5RAmdiESMKObhsPpJeLfncLEYCEhGszEBHm7cE7+IYWkeNtJqbmRp5ri7vpwyrRyxeA8J"
        "ZY7ti4gl+/xv3IH8VQpkD+FObDj0SewTzR0PN9cqmJg74SlGd6FoPefm1X/Dr42lpjsgVJDc+ooef6p4N69H5h/fiNrdln7eHB17"
        "7fObY60kCpvzm9lxtDRvLec/UhJ3sbtMHzz+a7wxcu+4IC9sqmd+hL2qL3tujM/2yGLsq80LsLy+OTeSiYfNe0UdH9ysgTXwBH+u"
        "pXW8gePqlzAp+GvTjr+4CX03auuOTPxbKQ//Nzf/ljb7ZZhm/42347MkYjltuXp5gXwd3RxrzL599qHxmdwN409MNPNfe6TokS3c"
        "Yu4oLlrxi2M28lvHqo9pFaP4/eNXt1F9op5b87byz07uNbe3d9cx9/XA6Z4SOA4e5xtDb4O+fbbobPXZFv/L4RuHdzZmK0CFrurV"
        "t557X8O6hl0NxxuEm846f9n5m86/+vyXGw83nm+8feQdO1ykiyxeOOvCZRduuvDqCxvi/eLT4us7/rPjut+H58Mr4Y0IEoKB4CEk"
        "iHBEIiIPUYGoR+xHTCKOI4lIOpKLXECeR95ELiKfIT+ijFC2KAyKjPJEBaBUKA0q3Y5nJ7ELt0u0y7Urt6uzh9oj7En2DHsf+33o"
        "YHQsOhNdgr6Cvof+Hf0Kk4opxKzGNGPaMYOYUcwRzHPMJ6wJdjkWhx3BzmHP4qJwqbhC3GpcE64N14sbxk3jEXgnPAu/Ed+NHyJg"
        "CGSCJyGAoCJoCOmEYkINoYXQSRggTBLOEf4k+hGVRD4NpWP2jvl+0kC68OKrLn527OeTZ+Zewkwo+YxLd5wyP7N2+dPjD4+/Nv7h"
        "qcDsVyZcP/V/UxZTDbXJ1dOuXnT1+quvuPqWq++duHbironHJl7igXlv6q6pR6f+P/XSsfw8rPO6pYf6AgictJLJyNEwgiWme3nr"
        "x8SF1jcyvxOUBjxXIc/bbgRuu7+qx6FrozvLV7N+7kkAnFsVnmN72FBzaIE2y+n9PJnL8bJ5IFaR7GI0vhFB0QqC05xmnveNoYbD"
        "U/Rur28o5C3qG4QcbY+7g7M5SolabgtABgOCca9tdpi+xMWFYr3wFSVJ09QoAlk90nKLPIshZN9kNxXqFrI9jhXTaWDZm6MaU7zJ"
        "9HpLFGdwXCGwOhMIREvQbeDRyzAsN+gEUfSickMQElKoY6V0vhI95lVySTQUWgegKgjGbXu3FCt0o9tVxgVR8wPLKUZ93Yx4rf4S"
        "hp0wsNeQL7JJaowIqXVCHAzD8KEf/OClOpWvV3odhxX2cVaSIEgrFyihnN8zb+yt1c0jqWbYzZ5b7YecIGu678sCh0G64LR1TBlY"
        "SpWd35IzOEHYuOBajAsGsmoE8SlSuWVaEprCZkgqpA4Q/J/khHG3chAax1WCRQCHynGTD2v8MlmEcKNXbfZXRYnFmRmGYJyEPbHd"
        "CRScXByhzZJobhBJXpa6rl2Ylu0FjbDHQXWOE1OpikQ96J/OTmjw0yhUG8uHZGBJjs7yueUQxnacqHAABzYBUkbkVh51G7/ZVfpX"
        "IHKHGMiCrHJ7968nsAKaubZpU/Gag2NTjKLu3fLMcjLsn6Y1fR4rhi4yDElQr6mRRsAYZ4j4ozgFZXyZk+obCF5omabVYPGcrW8y"
        "+cVYgLcTOI7O+LmnOsdKJuwAgBVcH+q1mNJLN534PIEu2xgSN5lwgqIDBWJ1eBIMG+2uUn1Zbw+GJqQy5hPiKDztD8TSBcXvYD6Q"
        "gQjs9nCdpt0ABaSQLwtMKhb7/x/On/74H6CHbx7Ehrei3UqymXpmJ36JQKFHTUAOyc0pcgvs+93JM74M/V4oInJ5PLj3suzkcjx4"
        "DxajxZwG3xN7vftqQtoVc92ahtIzTjMeB0fYPeGNtNxKVy22J3rjuwwna60sDkhOUtTCjcQzCCBzPjF26ZnRXcC0L4nUROM/z9sY"
        "HINtoi3BVEl0zu+uCZph2R4VbMhkSJbxecCxg1DmBKTubzUH2iUIDAHsoXASkCohj6v/cIS28uagXN3U4rPLuqxwL1NltapRF0+Q"
        "uWp5IdioWCcpoD+QzFFQIIyRCkAJniMatbqJRjptYie6KR4XTFECQ9F0S9qNQ2zoNSAKrZxcJKyEMGGmXfCbJ67T3boXdXRw59/l"
        "eI7Vgg2A/9sELS+EP/vUG3cefHXFQ6tDZqI47tt/fOJVBaSzE2+bUBfG1x9eOjjx2xdZeyf2On3Xzt3n75647mNEHyzAE3m6suHG"
        "tRqVq5d783Evq1FL1CHNc05KTST9CALyRljlDtp1mJZyBHbV663UuBRQLpl9jv3A8prXdiaUcCx6vdOmlKu6IDv1VicKhw1kf74e"
        "L4mSDe3qvMiYUOoFPcD5qhWgB9osPwugvct58/9f+O87FyzzSC5QkD40k9DZFRT41LDlg3d09R+e1WzeQ6Gm4GQdiQRbN31jCgYK"
        "omRbmfPqWW/43XPhDZnD7Ts3QCgwQgZHxOiTF0y/YQ2O/P1go/ED+aNn16BvGbjWPgqBwGn/qJcTWo8W/ca7Ku7v2/TnfH4X9oWm"
        "g27d1uHPX+WtOd62mvEPMBFz5jo/EF/1X77T5Avaj+uLsqYFZIF4exXKTjvj2d/X7yXf4AJda+o5DWtgkzL4QYwrKTW7HqxgERC0"
        "KKsabFUWaQIp4BQ2dk2RxBcYVxeopKtUcHeGKh30Olm8d3oj67c/KnewM+t31wXdCKp/x2IlARivOoAwaWrss353YPw/bWgV7woW"
        "PrfopY1ahdhaI+2J5jnrWHO4Irbs7pB7o98xBLxgplJNhoU4HjCMhCfYctQapmnYjt9PreGt5YTgBOxP/IFAOBKJ5pSes9yMh1Oc"
        "YVmGKMHQycA2/NJs6mAwfPE+gFaOTbr9fkvAKrEvXxeDMLLILZGVRKvRid8wu8ATWIWd3LI6BGqCvyh2SCbmoZc7kxycY+2SXqLv"
        "DiPExB8jHiIgkrb96Gt+7cyn1iM4rRqS6Y96b/K/FVKrEY7pKlWXBSieAp1hDcLwiAunmu0J+Zyv8+v3bm2KaJqD5D4ZW4qhE35Q"
        "NwyTpBO1A2o0A18o34dcEFIme1Ue9choWy0S9DRhsK/RCJo9Z6zzJPGfHvMTfyBRhEVnJaBJM1yEtWj9TAzu2q8xeTK3+2vy/ybT"
        "ZDOFJ+eBdPu6pkqZplPn5t0MptN5s0Rf1MMp32p9k1KcFhXuqKDohll8U8ORGXtVbq4Ek1P0fieN8bmTNu9mTdO9sJtO40r0radK"
        "VRyj9WBQq/XOrVmTXSXu8TxRkRB7VD9ULcmw2xMUipj826XPKpo/MMobFvVW8qTiRv2Bmq77nioXYDqY0CC/IYVRZHBoXtJOZ1ax"
        "00yPUAnoLKiyzrP1nuzyrpHRanbnN2Cx3HSnPy2hZ1qeIrUxSmkCjJk0njMaDPapgmKoYqk9BxVScRuniFBuv8+EtqkvVb/2P1RQ"
        "5jJP0kwzQSHkeEp9AWPn56em4Ee+KCz3gNzcuG/r9I23Fc9/dl5AF67AF3w92/TD5wxDRFLEzCaU8DKMZaKJzhHVHMGdkS0IAALD"
        "pjDvwMI7W7jobSA5OOAMYiABA5vx8mee7Qwm15nDoDNlyuXanzHq00ZMrajAcMX5BwMTGtMbS6bfl0kgVDUz22FinYDRILQebO9A"
        "WzFT1/zYRkX1lA/1D7iNZPB+7nj+i2FDyCOmfHNRDYaX06NoZPh4ysfQ6Kr4/5n7YP8Z0vgkVIbHnzmaZZQ7BsZJj9ktP4fJxyy4"
        "4KInTqwtV1e3BgxgOLX/+3rTo/P7+L53g7Um6D+0Vamx9NOaci/F/7aMvNEf+UNDUAd1LzpPelq4pHXT09yDHABt+PUwq/BfMQQb"
        "6qpKRf2eQFrG3VRNCP158MKVI+VQB2EtrPVscMefG43A9+tBqxtX66N+bGpfpot8s85qY642HI9DK1i+xYUbWZLgY6vf0DvFHfTd"
        "H+mV1AyGaQvGVjyHN7psF136QBZVisL9/m5IMhI3lQiOypG5Valm6MhUJfoe/h+ozCqWb2pu0IlHMb8Rn1t65uNKjYEKrW3sYEWC"
        "og7+9S9Kq0CllwczkSq8FUH7qFJEjmEvC3Ua6rc6Wkz4CDnOszxdbeN4sUHB4QN2NJ64v2rK9NvtdiMozu77w12GCgjjA0glKNiO"
        "fVhpmzaBdaRyDRqFch5SQkijyVZzpYBWOV06imuBRm37Lo6n8SWrOKtq6jPmTZl+RB5UQpXp6P+q0jIfFXvLJ9bZA73QGp2pfo+i"
        "WMkfkIASdE3TBQrNZWRJZijhMa4Y2mDCRmjuaMmdbmAmK4rl06mK+A3IDwAtYirVSicU5TKH5sHGjVpjBzkzgS6Yi2c9Irp5KV/N"
        "bS+hxeQsX0ETgPsEtW4k6trxGlHXDqXW4oKLMyXCBoaFE2lfBdign0DzBzTVZAHidb1VeBw3EEKRqLBaG89eAqjyvNaKx8SUB+mQ"
        "ruzdKU4cVO4Uv86iX8YeVeRbUoGqUN+J0ezwbQ/N18ouuf/3f845LAxahpBhgUZ3QBpBCp14cO/QMYk30WGmteqq+sGxiXksNLpJ"
        "2UCdPzdPVSRBJIu58nHc75IZTOQlWTWc1PVidz5v0y6qXTnndaZBAb21zsdZxGZZOuyBQrB0MokXF6N6h3RCfQmfzajyBYqh2MND"
        "5RNp7FigNIsJL63U6U7qmqIZXdXXkTPB8wJDokUVdlc01+49L302xcXOAIj4rfR7ldGEhzcok/pFFTRMQiIennHNqAo18GoZFd5a"
        "wVL0Uc7todayFRxScMfZLEBojDFGpKgrlGFwSIjWoqY5UOphN2KtqSpWhnEXka5rYBKJJeRytMpdFdOI3TLPr4NgEA+LOeUOQMEA"
        "nXvXesbYVpml+9FCIuQY7IKdymBRnjA0gSgUwXinKYrM4eA1qD9O8H7/bbWM+zbG0Mwn4TBuYZAroBsqJTA1YyflWBu3LcKz0NvG"
        "ylmHjEVt46nlsNv84bFDBHDiCehXzITZ9m/LTqXRrIGw13wtqlbnuvAHTPJ+Alce7lEcN39xuD5K6IQ3caHpRAZ+aab8PyuBEcrF"
        "Nw2TD/+hmZbj1vUqjsIQvJSo+dEulWbobneObdcjW8MqNtZ7CBwG0VrdO1At4xbRCp2AzHXnDn+SqgweCOVksw91Pxws8KAsiitJ"
        "8WY57I0W7JcPFUNnv0wQuAiAUOVEoFiB4WLc7Cb7KVaqhnck67X7nSV6AIEQqG95BTvFLFWcCG2Rtky218VK0zCORMH0mq3aENjM"
        "31GwuYYPP3RsdIrreTqT5+ENkepxRGgCIBX5AXSMd/9RGVrXNZhM9EsSReBAZ999hqaIotGIur0UyNWOBE5R4GIsmocJxZwW/W2m"
        "xiUAqJDsBT3QYOV/eeRrv7p9LdBafkWQh0RzAYCEIcEQbzkVBRF1z/H+m7vMDyb7/ccUvq0puDsh7WEKXhcQbda5paub6fHfv8jT"
        "TP7/76vsLTm5EAAj0OZddslAXrfYTNvr3taBMRvDWjsZ9vrD32dSyWSxqoejvSt2EaDBPI/Yo2Z4BhViTHWk+bw2GKgEgcm439Yr"
        "S3vqaxQ+9/BOf8nxfDptllTk0yXnlcZYcLwuHmZfZAkI/4MofboKDHBdhSk36icELjHAcrc9/jW9pOXX0Fx3SeWZ8B1PE1kM6ufV"
        "XHIpAip3J7TyQpLheElSarbf6SfdJEXhJ6VsKh5jvEweYvjpeq7yeUfDueLsbMFJ9NludW3CAUbxCJGJlxGwvUAcBCT9GaEu7mSu"
        "tTZL26Y6Z6o1n8DRbnSWTv/LHpo8hMBnnzw+OnWe54twBFfl+6OZL2FgQBb3G5rHfLtu0DUF9AQuWKs/4KvVTNtzHacexeGjAAKL"
        "GhrO61cjli/jmjctnOgUPs4DRCSu18JMRaZRrApoipHoH6j1/UbY5h4T5VSwD/f1M76sN9IY883ReDxq8uDj2T3pWaYft7K9SAoe"
        "K4pU0FtjpdJpUyyF42sa4ZS3gsbDcbLcq5HULIHmS8OeElO6UBAOgBivIMYqKJDwL6NK/G6VKbQsCLG/BaXmYKbLdIi83a3herDS"
        "CKwDefKoDSOg4+ImCEGcbyPZA7Q8wkQIjy42+6tcmmuawAAEZ7A+bLPHjnx6fTp93eCP8ay7qXlqjXxAzJbHUrkQPP7PXYAIP3/9"
        "fA8BGs89GrE46Gw1NHI9z7XupS9utqKkxYHupBQ49RQREFpk5qNllnnKLyPw/9ckGqzzree/+0DOS5mJf/2TP4DrRxm1O4mV34qy"
        "1hOFIWBpdOTwROZX8OYYfxumi4OzZ6t/GykS74xMBU1PZArFt7ZGCjA4FK8NgslxbMZK4AFltoWL+cUNjLV3nND0s4Lb3OcIFEaI"
        "+ralVbPjWlTKsRpFnrc1FtlRz5DttiswitkbTXOBNZd8+GEpl8irnV4o/VH232UYJbVgvUKwIhS0wjIbVzCKgxcHZIYZLHkQPN2Q"
        "WSwT/ZyolEF4tt4DVwiKRCtwCVhMN34gN6DVHYMsaVcLsHCGwJWqiZLMkQigeUE7maUq/GlgONvodKTzNoWkko38uqWrkiTbfkSS"
        "C/07T1WSncSslTWF58FnoUf+LnNST8obrtyqNY5h0mkGgHSFjfL08qvfe8hux0Mi0on43ubufiXmuhEnGebY8pztZv8uN7d/UnmE"
        "ZBvrWHlDoq4phIo8w4mKyRZFM4VINFI306ewkGYWkkjrLj9RQlAUk4YiUL5eP1zAE7y82ni1I/GFlslm3Eo+u+y3UyQ50VjnKBRh"
        "+5dUghrWeunrWbPOPAjmCZWcFr3uaGNirO6mI9+f695WwTjVnWiwtXo0Aj2xkW6YtsXixLBBmXEayZIcoUyLno0UCVvvaE1TksAq"
        "aS4WpnPotiFz3nOf+9jTQHfudOSlxZlRhdpjY9JrwYl/et7oRHDNBNe9sw7Del4ieOsWjN9x22Z/eOk3QAc6tPexkVrg/OrIhsDu"
        "mgdOgg94VmjDbzW2StJC8++/GQvf1uAZ+2x1br9Ii7VRsQkgornGNKLoY+mUvSsdj5xns9rWtjZFfLnUmgfquTGn4RpFkwTx03Fv"
        "6qw/Fq3tUPpjksAoQqCniAihwFlEAlXwoCfZinQH0yDb8fCP5+wAHYHV/3IsJ7a1pAbwEaCvNe4cw6TQtq8Ps0Lr1UOwrS5HEcgI"
        "JuxX+Yf+s/vi/Ge+F7t8h8w6ZDuaPMi+gn1NltZj4sKH02ryuqfTJ/hfSK/Lw9fXkpWKbcfPd2ya6ctWUIQTwI3xRUA87d+O/xnd"
        "Qv4RflYpxn/t3Pdbt1eJohfteP4nfvWYasTePJzjCyFkVSjewRqcV0StsfGgr02e5UUeyyZi0fD6UtBEcpLBAKlyCKXvGbbczD0V"
        "6r//HjBZN+jb3xLF7XY4+m6p3scKTmrVyPGivomAmhDEt8wa1X0dhHX3qyjnIpd2zdFCxsALz7/7nntHIlmC2WEtvsRcznG7wVCC"
        "KG8ueRg5wFkJgmTM3AbO7HXuFf42I2je3kreSJ4zcnvsZtwkS7chmvVFTrOoPJn2RP2oVoQg5qWRPH4Hxa87iQsCoK0v5BIb/I0G"
        "ZmfKC4JZ39GS7fyjmRnTXfHZrXqPvzFet3AH3caeJAHpb54RlKC73zYtuxG6b02Sbhh2QFkvCmtcrAMcgTzXryAUT0COlvJ7VR4r"
        "1C12Don/Qeg1DeoINZHGtdvoYpYlIAhH0d2wLOmNtmrVVC7bOExJqN0wrIQ/XHJvCRydQYG0X4Qyo1dd6EERiVgwZq6M+mOEJKmo"
        "QhdwdxqlKMXpDmyigApwTmJAw+ImYTTp4QKUTYQIyYC42XTd074aOAoIjt8h4bgynCAagHefrFsqWqHtzlbh3Kh/e+JUaopV78zS"
        "DM3QOJKLhxhQRLlGlERYoMfy4wBaun+/uf6V/3946RK3hIXc0Q/h0gqbXpOkz94GAr3t1G/dMIV/ZoikihSg1yL4p+W7EQO0QvNj"
        "81R7zHV9hfx/W9cotDDk9U7reZ7rnLJ2axia21rN6KimaSrPCJ0tPT1DdbS3f3KnGlOopkshEG1NO7dWXN9ttQyFAU/9W/k/z+9W"
        "mx3lnDd+DbJbzIXA5dvHOqOlYFsVzlT3nPE8r1e0Lwwv7ApS6FRyIeAJBPz+C6GGHaHVG1mGwUSBIQfKDcuNZAGud7y7hAlREo0A"
        "FIR8EM5nlkPcdes5e1tTNB1nDuGNS4dJTBhXMYygz1wxU9fKBGN/uTVYdR2KoNC7g/caf43ArWYaUww+VgHtL7OKpirn4bNlicYS"
        "8xtKzEr/9G2iCAzFyeSvcdpttMpwoldXDeDzb1ntcuVCZ6M2vfzdKpT9vwlP1H1XdcpwyXL+yeCgY7Mbx23fUXiZFyWOQGY3LZUD"
        "n8aJg9fdRmsXNp22XROwlt/qGjUFN7NqUi7nUstxxBhSgbCsUaiZhm+mzwiGixjJ3ihqqZGRld80/8QMICNyKha91o7pedxZ6IKu"
        "1Wd/phFYcovjWFUcDrfPrrTazk9Uw/HXuJ5rjlVVu+edq8I+W1Gq9UZFvKo9KoI4w1bPMVFALH9Xaau6LR/jO6MVM9h01ilGVGqs"
        "TWuczvVjx7gFt1EPdW9IxMN+K44jlUkzB5PpMB6avN/SvtLQtC5rNiWyqOHFdq0xzLmupctob4yYboe8NEYtjAG0cHyMR+kBPsMw"
        "rZYZLBD7+DybVbM7/5SSc8aOZ0Heshq91KY1QCjBx8w8a/In3GbMqMfrNH3Q9k+CZ5quLJ7IBAJ03nFH/obna2+6qbgbNmuKaX6Z"
        "GG83mqJQ5gbHFUpJ02O3xSrrbf7hNOu1ls1DtjGgzW4Xbs27LMu6kMs8IJ8RXIokUmmXeeY1qzNcVsrl767XkGo2Gptd+pEKC9eh"
        "Im0LT37yZaulMaWb+OxrIlEsACsRAtChSmlqGmvMGlNoSaaqJP8228GG2AIclEEVadElgl1dLL/ZkjZDoiEmXEoAwdU34Fmj19Ay"
        "QBFsO6DdKkwwoDAY9omVvT0mwDjnCmAImzQLTPCzU28DBfFePouumkEX6Xqh9/5rVnjF/cnS63+h7CIKs553J/WpsD6SwAibwua1"
        "E/6rYuJJTpDUWgr/HyV7FUkXBVGSdfnWmO/hWYH79wBBn94ryANSineH/xLdcsp22BPoBHsXhM4xRwCqUvqZxzyz9RrUOaFvhEQh"
        "TmpxMdx4u+vqXNmKadZUHs6KZXccAVzd5zziXgi9lCtn1mM9k70uR6jdYtWIoBq6QdnYJDEM5wzXDzqZAwvpqcknxufRCk47E8bQ"
        "XsArhm0znOU2OpgsiePN/iI7Ex11LnSrX6qFzihRBR0lVavX9QWDwO8DCoYjkoG3uzjGH87GlzJJP+w/HwInnrxncsHHdhX2HouO"
        "dXmB+INjsgmMZ+4gEJIgyatd+9fvnICNZZqGpfbm1+95J/25a/Cf2WdOtsN1z/c9ncFRqjQ5itQgpIh7U1NwIZy1CbkQgb+m97LV"
        "aXXk+/oml5xzkzg+Z2jKzz2T7XQZAMMItvRLtSPhJ+4kIOjEs9R+e95Xsway4TUyZ2tgR8LvJOUIM2pgfMNxNvFLLgkWMXHwWAXG"
        "lsLrK/8V4P7oqQ4jI0zSZbFRwo+OKp2LxqsTcFsQBP4V6v3ps9kLHi9WeX/XD/ed7kJAo/6xYgxWFE2gsaKC5rcCAJE1VczW40BV"
        "GKL/c7Hwm+CkaAE5pgxWZt4+yurf5VvQnxm3oZ9lChWcICmYxHHebuabaNm2/0JkQKIkpPfjcmeJohjhry0XizSHmorWZA4kowSm"
        "pV9Zf6DOu6cbsgBQTowEYx4+4XDFvS6XXavRUKwr7D2mNv4YUJHDv0pvesF6nLRR0dn5G367SMiGI+cNTXVuD4dJsinmQYyQHGf4"
        "rW7AteeVwJ3AWboq1Aam+nakoi8nCL+MtAzFalyfC3B48qHYUSls55Da4Sj4AW03zc9LwBKAJjJ8q94IJjc08+Rjr92qLt/64neC"
        "RFnpHkQHcxkH45eyD2OPxmKQu/7u/7h5a8/uHHeEuyxOmUvmM7SGD85vcbSb/pAaWA4uwyugsAisn2zDjoD9CRRCSIFkfWnRGINp"
        "9RpyX7ODX+XJEv0/QekcReHJRGpdiZA5QViK60cMyIUV/oueiYyQtHp9xWtGx/NaeUKbcKPh2Uuq6F2EG/5VrmBSI9pbXTVCGZEZ"
        "qGK0qF99CDD4+xvn+7sbgFx49bpHLn2wjlASBOcGsUxJTHtw36BNlfQYLzSsLbjaK6Gxa2NUjvnYRwA9vnsun5OH7mSxuUPIwaFJ"
        "+jJK9MXG/HNHaNoD+jiFx4x+EXlQWCyUY9CNi8O8BL1OIbH8gHuQbzhyVdzPgdpI6lfOYCDlXFdYuAdZiCrMdl8kFDu2tHtSkS7n"
        "v5pRv+kQwJFS90RgqjH/hM8ELEKLZmrwc910Q9UUqLL5x8726pC+UZMZEpIUVMMJi2kZRGFQaa3lX3c8CY4zha3igt+pygT55Nkt"
        "y7Nfa7acYPbfseCAQO9VkbIpZ7Dkv9xppd6O1aRWGx17Nui0VNqUdtH+rU7OsbhCNL4A89axqhucOuRQMBGdSaW2ftBdgDNhjWEz"
        "I50q5XTCuqdjFbus+kOmGuoqVoaAkoJ/FEswLfTMRDKRTCrDhmp4hdD9JlUEBo9NwrsErYMtXDL8lcIKTIU0qeKV4TC5heOCtXfU"
        "ZE0glNcPnfQWz1ULeea6Cr8vnrq+g7WQfJgfzrvvFS/vOMwCv2e9yazL+Dl+l6UVW72AQmf7Uo/GMA1RkmRVM2z/dOBHEUe1QAX3"
        "ew6nP3FyTc+48Rn6z9A5p4V8nQrwFeYx4vEKyVy2WgtG/h0LpbT2MlSY2tTn92TN2LOWoamSvAOBS3FVoVZ9qU+3+ovloVhuS8u6"
        "k4WV5pM706DQrddEdlkhN6Tz59vHU6m5aRClvSlF4oValymSqh7DRnDkms6OvFDAG5JUu5h7CQ+nuXx7koAyqfOiJUqqfjiVKdnB"
        "5mzgzzp3g2mgZmyyGboz5G0OTwKxr4xxFrmlm15oeem6dlzl0Yp1XTq6yC2Jr4hWnegjwOapXkOIn9zxb3DmEoxQQr77V3FbEhR3"
        "ZRtwvtgRXP83FX2g9PhQgOUna2nsfSasq65rDtb/ZBi2tRUA6uMsytPoB/5CaIGtzL/jDz4EWF3a/cy2TmjIYnx3m1X3S3lqCgHC"
        "5Y9svfw3cu/4zgX1zJ62CB6/gmLZ924rpornzz89Dy58Lw6u2pvgr8O/SLu94AtXeKgCmSjz1bY3nx8X4zsLP+A0dXf9v6olq6Xs"
        "vj/w5CohK4pF09SxEpq+wAzGD7y+eA6uj9Raw9ObhvUvJUWapg28BkUhCKo2o6jdRlGa5Vks838K0FCCs5JNE/cHP4ZHxZrb6BVW"
        "YtT3ZLCNfq9ZDzKmxM09uBUt5R7hONQ5p+kCTSCovlLmMs3ACaYmUGVYJ2mDp2kilUz+GnswbKPSrIliO3A6MCK4NN6GDLcbP9xa"
        "MRWcssODUrflM5ksVDX6CCOagBBss778mWe7QpmyNaw0B+u6AoIOR37DqwdhF8BoXQxWVP1Wp9dzvGQwJdgSzrfIOQ5U4RGnVIVa"
        "S4xYApwtY04XjDCZRkD4s25NkQTWfj04tj9cgGEwG9k6NdPHy4q2FhIn/ZXTffa90X8x8BBukj5l3TZSV7/fNoG8vIfPs2e4yT44"
        "SnE85CJF+/gI7QyqvoCF96KNEU+J69ViL5QeHRqjv2Xbc8Yq6cr+4wWxIALxUB+eoWcWgzv1qwKPxm/XQrepCzObTduBsOU5LhgS"
        "2kE5Br92OMu7ouRNLJSjH0Oh4BpEVx+qpgWKlR7P7E+KUteVTBnlIFrHICojYUxmV7tB136HCMilCqS2ozHHW6taSY9cs07bkg5P"
        "GTQE64pmU99fliCRWgdYNF7MEDk0D4ic4sgcdmq+gNSexQRIQWilYsPVwZOFqAvwX/qks7yRSj9uDIMkvtSWt1mq0K7n4Mjwff+0"
        "DwkMwZj+xEnQtx/CABrIG3wiB3Eo/+CpHHufpWipovyaHqpkiDtdjGi01jCPKNxh4beFdDlZUm8UMWEQL/bTqYTrZhLY/Q+ZrpSx"
        "tB+u84d5Kqct1daevYJlQBLuTLAxwk7zAYuaWoojt1Xgfy3ETbW7N/Zlo1Wwh7IOTGszIIqzqo9GNQgutHMEeN0IgeidzGCZ27os"
        "Qov1U0PG3uBHMm25i1Zza12qyigasH0OVRJswrAX/veRzoJV6QQzTMZFAR9JpznsEyGdiu0puAjNH69ImoB41msohRL2kaVbWMKV"
        "RYbNzhlKrVavJ2aFvXIS47oerFjcxzkbLhg76HSWZI7L/9fp8k4dQmRpNP/V/08VuNDAW9ALbKz8KbpfwUFpMAEpVsqMgGWIBdI6"
        "IAK73/7T1jz/y9VJ0r17dWaTgPJpjV9EUYKEKZLkzcZKwPIyvJKsWEFvlcHzSRJvAsiwv1KllF6EVqjQdvOt8SKGlrjFMLxYpEV6"
        "yFqN3X2Es5jRfE8SyETBbtg8cXuTwLMMzXRfhgBbLDd6fosv9G1MHaP0oDFONBo+x7KaYYQh8pAK59kmZ2z69yqG8UpFf8OzWDGs"
        "liDzduhURd6KhwtYMCDsf6TvkYql1mp4LH0A0Dk/tJFbn/QHBM05KUYcd9Udc0xd0xXdsIK9q1HlDvOyruOkZrpN7y2TKCqqgnpH"
        "wgQTJYocMNGarpKgbodnpZxWhasFgqM30EORxVEYtBv0vTc3ojBs+SokOAcO9pwf1eHHqv6AID0nqpuDAlwEg+WNSV/vjx6yIO42"
        "IEBOFtDtuz4Doiy5oxpnCYa3ys8cnabUdCEX9zD1+qHsEzZtgC1nqUSadeRgZ7n6P8OcoSnmNbglG+4ALt9gL0mcuVZRJdBCFyXZ"
        "7tSNqWB6u4louslNfxqWkGUJXoxFs2BFQl12g4NcmtjZJED6YpdJva8ukb02Fxz3IZYWVEKlfmSHNoHM4BkQOF64FTjrrPKByNp4"
        "JBJkaJoPJIrxQ2I8OcMKnmmNs2lE/NencmFVL5GwcnGlOINQL2xxl3gaUN+TSLSpuY4xTiblnAdQL3ZzpgDS8xerDFGF2iYXg7vJ"
        "Lhvu2OVUvv339wto/ZMXoGqU4bIgkTdrwNIvEBONgTNVaMqSjrHW0y9ltwwI/VQDur7ySc7KC96wjkCAiqhlxcznUDlg1NCklL8K"
        "WIec0cgiwDkNlSP3DPlgwtxlVDVmxa2TH01PaUvoKbOEXdkUCxxneqks7Qyrqt4ntv7lwSfViNBYpw/KklhP+g5L+jlpMACbMoQa"
        "OwpTYDusuHpdhdoLyzfDB7kNf9psUZiN+McGK4LPXl0B7HrI6dBZpC4CVoK9D3AYNxUBI4dy8X/aCIpqx1ZFjqJpEs4L3cwa83Df"
        "ruvgwyb90g3bwly/WF/5N2bfr7fvcDamcpfLlUoZS9ayG/g/9F2yagzMCdR/+pw6A0ktCCHtOUHkaV2n0yz9H7XcejsLtXH5qni1"
        "xJHo3zOyZjc2YE0y3Lht8dtUJu1rpazFC0scP4JYEauvqDk/ztxWr4xS7fz0SP+OeMhg0PfceQo2U/AUYGaRd16VJSECnFlTsMg3"
        "fw/TKJ5Pu5m1mK9sgm4/rqXACe/lejPVN/n7+omQ/cd/Bw5v6Yv/MdzesVZZyhwFbdne2hB5gR1Dd9QT+k1L7TVUtaSBxuNtucEy"
        "3/yeU4cThDbcBGgNt7KKTSKVQk8Dot2tMCTAp28BpLVfxQ4QpvGnfpwfksc21g9vn7/UfEasgCPXX4LKRwBrrFJU0vpNY2PVMi6H"
        "XLF4htAN6fxDyBOHY4bSOy2cP++x2k/yW5sJvhdMQRSV2LXO9TpICZDFRDY8sS5gBO6w18V+Ai9tOn+RPx7LZMj9BlDoIhCEharT"
        "QFYg57NOx9Ze7jAPGELVl37wQ2P1oaHqhgg1wplNXX0KfIxbcFvrc/aCQ6+2qsJDL0dRABFyr5CkVAoiWiaO67inESQCGlB/PPG/"
        "lxK5LG3WIVyfYDxKCD/3Zl08kxSAze+YbMKTYAtCqquZE9HMrxl7JEKzaIUqWq1oRnnkaO1751gdksTeEGTJyXSK/gwptRk4zvlB"
        "cTmCB3rZSr8ugv7EyubyxcK81xeG5UI5reDbS3JhfJ44yhgrBmqlkSPy1Ri4kzh7Gar0+oICdU09aEBN7U79wMG6TCbllNs58j6Y"
        "d/M8Q2IAvodmLJFhqEw6TYqGjV898a9m0HiRmbyS7BnY7A8Lv9rV1GbVhUtmsNnA0DRj9cPRBqyC0zwP+OPi4kFeEVlct3UWVw8H"
        "S8wXoTjlfiYuSWNwCBL+F7sIVXyqYuUAyov+Ze0bjlI3fLUHlo7L3A8XtbDqunXBeDmyLgOrnjnvLAhsacVOPjVSF/L/+2YK1Zz0"
        "xlpvP//5iVRoFDgTE/j/rh1p1lqYvfPMawqLt4j/9AtjvOBXQwU6wNoobtpFgUk3VtZvbXVSdg2/CHLOe2euREY/szuZHGHqC0Fb"
        "6q2Vco567kI8iitn55dHSmCTxn14ASGLlFdDHqvN63u6VPb4Js6ONmWOQoBJUxUon0kuIeZLKMvW3JCaWShb2xytKUzWR+EGFXSy"
        "ed1taT0GLoAgPOWCM9zspvdUknPeomS3WI1ieUFIRzNwkpdkDVGWRO7XhEAgbdgmLnmbKiyNAjHFtFcDBoRHzxUzg1T1T4C7YNs/"
        "DOt+fy+ZdKV5JPwxBR4MDFZnKKKM+L9zLAcYrs2VBnQvNSJWjZuoGla9p2WoXFonv+42Qsn3544pcT9Ycv0Ao7nn/fZgXwvYJsp4"
        "q2ClShwt0Q/aoM0xciaRM/IpFOTY9Jm0xmx4mYsFE9wKPzQxf81VVXfDiWK+DNSgvVzssUCWES+CEzgb5w/W6e2xjCjsYKQ+HNYK"
        "6zjh9palYVrhuNYJJyPsDlirve6IVIzPhjfToeNujHUnKWVmq+O4RmdwFuGFTsClQ8UoF1tp4OZw/rwqDxsAVCgWIvr0g0s1icHy"
        "Ja90mbFbJOtur4xrtFg7qqUQ2gXAimpAxP9VLZ0RZMnC4hKSwxPiwmR8L3c3JsXN3Ysvk8qVwWrEYJVCJooEAX6UgEChlNUmmGfN"
        "MEwbw3BvxuSVI/jQUN+OOBdqy9XKgmOhpVImACbqP7wB5w/JsWaz1c7xHl/Q7+F/2TVRda3b/05/VtwbJUJ5j3/kPd6EqbHL+G+E"
        "XXIeRtSW6azOsH4P9g/bevK6gfBsJnN+Wnm6Q31fKEozyaD/CXbfflnjXAo0h0KQKn/cT6ef2VKhRH/3cw99NPEpvfLdE93nVCiv"
        "4OdfGmN7yPzSHA2NxQi/gWdfA2pki0ZcM/WaTNgBXuA9rQ1/v5EqLnOa69gcGBVEEXSHos+ZGslzmkXD5R3PqBLOoTBYyMdwA9Lf"
        "1x3LNgogsX1K12SeIXESas6Q0rFoELnF5+L59VSCstIFmCovIGlOELacDgbALZ5KajAF9W5x1z4G/LXO/FX/t9fplqmul9NuNK/J"
        "0l6x7azQEf7naBWP5q6Yfq5nSs6Y1/sjOJFDv4pAkxWKg6tg1Tf0nnrQYObr3TowhCf2/vXh1JqV0T8Ublpe0GoTysKz1UqV4/9k"
        "Z3GnjV8TkZjwgrfXK5CfpXhjkURl2HNLjLmwq4OuBBxsFQMcCqXW8rkwbGnsZ2KDf/HjwYsX0jGwkM1mkvEShJFINjnvtltomLNs"
        "Lq5Gmv8EafravoLm9kIZH5L6Fae1RC1xQ7uM0ElWJFW9k/8lOLy3EP41YPvE0lTK0dddnDSgfWBkos+V0+usft6RLJhMLe0UyF6k"
        "cJUkN1gpeowweaTOz+TuHRCVFFopqbUxOdcrWGpdREurPGVSMmqfnRN4LBQ3vdaAzvdWIzr8f9oBHI93gIPBznn20h9JZ8AyVMqW"
        "tXZq0P1wyo2XkGD4UK1X1USaYWji977rOgM1euogmH19gRs8pyYQ9FyGIWHAljWeJM+Y/skVMDVf+QQfzho5sgAAU6O+tmnE/F7M"
        "KlvkAaOUBGL8GgHneoE6z5IKyMUdfU6/zOwza0sBQIcsR9FeAKwGyq2V4ieNbaNWm/f7lHYLfqvp2xaHWo0oelv11c3Nn4M075HM"
        "Ckaubwc4otDWPfMZN7IWROvXR264GqPYYsoAssJY/ZFiSLKkXPhl0SJx3XF0Yi4lCOmhZ5QUXgXVWqiOZ8Z2KUFNppm+w05wWKnA"
        "nKLqhq4qBDincgTo1TkVL2slldba9fwKYCQh0oQ4eCQrhnOiVte245H1FvW3nJM0w+O/drMRiJCUWdgX/wj/rFUcO1neEtUL7zv1"
        "DKSwIZCBbPDhagJzqd6Q8Z5iLCOXX5bYiDNKcBFUhW7tNjFvY6cbmyKad5KxkjqnKi+3uu2JNFEqj1MOpLNI5zPxRByVPDoKx1EE"
        "rpqpiIQ/gmH0Mx5WmXShmEugEhYB01UFtPF+FrbvFxgX0rjYGCW4fbAUFlsG21UihyT/6tNLkWM4Z7D+ipyUgrNbpj+YbGBw8qY5"
        "vDHvtunX+fALCo9FTeqdU2k23NWprJvZUq/M2WBMbFbWUDhZNN7CJCXQot7l4HuTrGOqVvdf+3HjMM36FIAtYPDsge+xfzkCbLbK"
        "9kPHbm9PT3YnTz1e3qf9v5JVGE6QNk+wvUZId1Qm11/VFKlc+s+/CfXEc5klj6s6WsQHjTI4AnErewh7XGEsgK5X5pU6TV0otCuy"
        "W4pxpyuQzuSL8MhRsZkvXrNWIR/iJQ0W2AYHEL6R7m1d80jarr513ab/9VMup3895WxNfmvMeWXqk4UiuHBvwxeCTgzHVemItMmd"
        "A+WbPMZYUHqFlrfGB+l0nvH1fZmrbNHQt2Lj2Oyrty+xXgpGj6cvmVePHRm7YZRETVNiQC1oeCCNPyoZjTAZ8RwrKZqmyxLLpVPs"
        "LSvoL7CCrEKRBQ7Jte2arhKq1+x2PxmJcb8Xx3uagLHv9Hl/hJip2ASsKDCmoYosUmYpw3CVVMZzHLcfUZPF4FCweF3haBJzCkGx"
        "imHVm+0Oj9du1i2jNttQC9TP2ROvEKQkYA0elAn2yPIYGAyxm10IJO9iH1wKlFYTwZGT3hpZ45X1GtRhofhbl7pXon9sBD4OO8HF"
        "DnzWgUf2tY3exhtMCUzSZ60rkLqu25BJf0f4jJGMcea5sKUMZrZz2YbZcBQ6bQQqh/d1zkY6nRxdoXSmcx0tkC71MonAPmKGOjn8"
        "R7sW8f0X377yP47TGeQf0yCgZfk7z99hxrj/P6RpAz7+5xUHMoCfT8jP/de0+EYpb6cDOuyAgI/fV/IvdAjlIwlrD/GoRpHsc65l"
        "VIFdZp2Qaasx6XzueV208s2oFGwzJb4yvZdk+7hWW4zRuyIp/1M1oTRum2nuJAaR0C2YMGiFPLV2xTVV1Jc5kgK1K50za8flMsHZ"
        "WyhDxUoFcr60Ml+GfJCzGVEJwQtuFkrGZ2Wil+iS+zOt1QpuvjkDyirlroA+yeyOBM1lc80aVSrP5wtlIGK58aHb1JoW7iDJDL42"
        "BmKnUzYFJM7G25gs/MqP8Za1xbgWboDPqRMeF+nj8P8vr+Xmjy7i0JNYinfG/wF3sf2kLWmhSuOCbaNi/8uv6ZJErRefBNzann+0"
        "v5iA0sp0HLgW114XnsmJeQe8PVsom3SGU3bhbEw5LOK2cmrHmHLJR5dya0bJpLBJ+E4X0IsDKnhjUWXKAVUtSe9Vru+yKviJqlQ1"
        "eEtlrxFt7cRUR9BJddWVqRFR6aqnzV+N8hqpMWUoNS7IbyeW18HTfW24Yg7I2bK377cz1kowAxYGrXt1bex36BoKZ17YK36Fu55K"
        "GEHnrvlKei0VdtjRcr1KLbmW4qW31mcT83L+2gXssr7RH8QbdbvKXCXL5KNpJmJfttbuc44Azdw0rJ1m9r49yMTVSmTtup2PWbPT"
        "ai+YOL+kdTHxD0Oj0diKi4uFXLy0Znehw68Pj2fVL2euRdGVmt24MXEjvRjHNLXr1oPZF822phNB17Wr09rcTzds+t4Xmbfpo190"
        "9Ny6fztmTcYOV+vaCtt1O63d+q5NK/Ott1bCEm23E+58PT3UqY8Z/kAwFI60Z+OXs9OZbL74gvT/DcMJiuZ4QZRUTS9X640X6swg"
        "gZG5T3KrRw7UoNxmdzj7t4Rdbo/XB4ZA65uBI5CohtZhsDg8gUgiV7NPpdEZTLW+bxqbw+Wlpx1QF2hoamkLRTq6YomefotWGWaq"
        "GIPASpDWgVCYJT8CiUJjGrgaDk8gksgUKo2urKKa5lRdQ5Ohxez33tPWYXMyMu7A4+vq6VsxMDQyNjE1M7dqLctvt3y7+4013kST"
        "vdGTZprzl+S/UWAPZduOXXv2IdZANWnWorVRbdp16NSlW49effoNUFBSUdPQwujoGRiZSIf7z7+nSOVfGN79R5bT9vBH0feviJF9"
        "1+e7Blkt568qaOVvUdbz2rAvizpb6Fuf6Pv596lFFF9d6beLuv8R2RxIOw4Y3/q0jA9QGd2sW3YW7ezPkPn1VVoKFZ5xdNC3tviT"
        "ww/V8fgP7bTv0ROE9RfPjjhSiTw9IkF+Bzkbl1IdJcXpJphT1r8tQy+eOU6P6ew94MBxrgle9Vby3n5tIdu9W4+X15Y40lK8kZ7j"
        "p3ute6CydN0WE1JJ9o3JeaFYLSgPXkk9mlKlWlbPGareZ/ZGE+qZt6BvmP5p9M5Y//ABvaHgXvFjlQYqN+tnVbVrq73TgukvmWWz"
        "65mZNm3eRqdk9zlsZpMdscnmrnA1j3vwyScfPu+KHvroi77WxwADMcBQDeWQhnyICSZigimfajPMMFdzOac5zdUcc6zxtdga1vgG"
        "NrAZ2wz0x/ruMo/uxO8YSTG/K/v60W81H4xiQpFoMh5i0eMHM040rOMXdmLasuDw8LAPe3d/j4TD0fOHnU2GM/NVPPalcbaWOTk+"
        "pCzpcTgExYAzkdAifHKL36NGH22NvHJ9v5wiShPk1LcTEUC0hYVKknBpHUajKADLhEIIZ7AYxSlBSUoV02c7CEEwAAA="
    ),
}


PAGE_READY = (PAGE.replace("__NETMON_VERSION__", __version__)
              .replace("<!--FONTS-->", "<style>" + FONT_CSS + "</style>", 1)
              .replace("__NETMON_ICON__", "data:image/svg+xml," + _quote(FAVICON_SVG))
              .replace("__NETMON_LOGO__", LOGO_SVG.replace("<svg ", '<svg aria-hidden="true" focusable="false" ', 1)))
PAGES = {lang: PAGE_READY.replace('<html lang="it">', f'<html lang="{lang}">', 1)
         .replace("</title>", "</title>\n" + page_script(lang), 1) for lang in LANGS}


def systemd_socket():
    """Socket passato da systemd (netmon-config.socket), oppure None se avviata a mano."""
    if os.getenv("LISTEN_PID") == str(os.getpid()) and int(os.getenv("LISTEN_FDS", "0")) >= 1:
        return socket.socket(fileno=3)
    return None


def stop_when_idle(server):
    """Chiude la pagina dopo IDLE_MINUTES senza richieste; systemd la riavvia alla prossima visita."""
    while True:
        time.sleep(30)
        with _activity_lock:
            idle = time.monotonic() - ACTIVITY["last"]
            busy = ACTIVITY["busy"]
        if not busy and idle > IDLE_MINUTES * 60:
            log.info("Nessuna richiesta da %g minuti: chiudo la pagina (si riapre alla prossima visita)",
                     IDLE_MINUTES)
            server.shutdown()
            return


def main():
    sock = systemd_socket()
    if sock is not None:
        server = ThreadingHTTPServer(sock.getsockname()[:2], Handler, bind_and_activate=False)
        server.socket.close()
        server.socket = sock
        threading.Thread(target=stop_when_idle, args=(server,), daemon=True).start()
    else:
        server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.daemon_threads = True
    log.info("Pagina di configurazione su http://<ip-della-sonda>:%d%s",
             PORT, " (con password)" if PASSWORD else "")
    server.serve_forever()


if __name__ == "__main__":
    main()
