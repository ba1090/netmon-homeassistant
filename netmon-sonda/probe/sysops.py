"""Operazioni di sistema della sonda: riavvio, aggiornamento dei pacchetti e di netmon.

La sonda gira come utente senza privilegi: i tre comandi sono consentiti da
/etc/sudoers.d/netprobe e da nient'altro. Gli aggiornamenti partono in un'unità systemd
separata (systemd-run), così non vengono interrotti se il servizio della sonda si riavvia.

Aggiornamento di netmon: la sonda scarica dal server (con il suo token) i propri programmi
nella versione del server, ne controlla le impronte e la FIRMA (chiave pubblica ricevuta
all'installazione, in UPDATE_KEY) e li prepara in STATE_DIR/update; poi
/usr/local/sbin/netprobe-selfupdate (root) li ricontrolla con la stessa chiave, li installa in
/opt/netprobe, riavvia la sonda e, se non riparte, rimette i file precedenti.

Aggiornamento completo (update_from_server): se il server offre il pacchetto netmon.zip firmato
da root sulla VM, la sonda verifica firma, impronta e versione, lo prepara in STATE_DIR/upload e
/usr/local/sbin/netprobe-zipupdate (root) lo ricontrolla (firma compresa) e lo installa come
installa-sonda.sh --aggiorna. Con un server vecchio si usa l'aggiornamento dei soli programmi.

Log e stato degli aggiornamenti li scrive root in SYS_DIR (cartella di root, qui solo letta):
nella cartella della sonda, scrivibile dal servizio, root non scrive più nulla.
"""
__version__ = "1.1.20261028-154150"
import base64
import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
import time

STATE_DIR = os.getenv("PROBE_STATE_DIR", "/var/lib/netprobe")
SYS_DIR = os.getenv("PROBE_SYS_DIR", "/var/lib/netprobe-sys")     # di root: log e stato degli aggiornamenti
UPDATE_KEY = os.getenv("PROBE_UPDATE_KEY", "/usr/local/share/netmon/update-key.pub")
MAX_RESPONSE = 8 * 1024 * 1024        # risposte del server lette al massimo fino a qui

# Sonda gestita da un altro sistema (per esempio un'app che la contiene e la avvia): ne dice il nome
# in NETMON_MANAGED_BY. Lì riavvio, aggiornamenti, reti Wi-Fi e disinstallazione li fa quel sistema:
# le funzioni qui sotto lo dicono, invece di consigliare sudo e installa-sonda.sh.
MANAGED_BY = re.sub(r"[^\w .()+-]", "", os.getenv("NETMON_MANAGED_BY", ""))[:40].strip()
MANAGED_TEXT = {
    "reboot": lambda n: f"La sonda è gestita da {n}: si riavvia da lì.",
    "upgrade": lambda n: f"La sonda è gestita da {n}: il sistema si aggiorna da lì.",
    "update": lambda n: f"La sonda è gestita da {n}: netmon si aggiorna da lì.",
    "wifi": lambda n: f"La sonda è gestita da {n}: le reti Wi-Fi si gestiscono da lì.",
    "uninstall": lambda n: f"La sonda è gestita da {n}: si disinstalla da lì.",
}


def managed(kind: str) -> str:
    return MANAGED_TEXT[kind](MANAGED_BY)


def _sys_path(name):
    """File scritto da root: nella cartella di root; se non c'è ancora (script di sistema non
    aggiornati), nella cartella della sonda come nelle versioni precedenti."""
    new = os.path.join(SYS_DIR, name)
    old = os.path.join(STATE_DIR, name)
    if os.path.exists(new) or not os.path.exists(old):
        return new
    return old


UPGRADE_STATUS = "upgrade.status"
UPGRADE_LOG = "upgrade.log"

REBOOT_CMD = ["/usr/bin/systemctl", "reboot"]
UPGRADE_CMD = ["/usr/bin/systemd-run", "--unit=netprobe-upgrade", "--collect", "--quiet",
               "/usr/local/sbin/netprobe-upgrade"]

SELFUPDATE_CMD = ["/usr/bin/systemd-run", "--unit=netprobe-selfupdate", "--collect", "--quiet",
                  "/usr/local/sbin/netprobe-selfupdate"]
SELF_FILES = ("probe.py", "pinger.py", "config_web.py", "sysops.py")
STAGE_DIR = os.path.join(STATE_DIR, "update")
SELF_STATUS = "selfupdate.status"
SELF_LOG = "selfupdate.log"

ZIPUPDATE_SCRIPT = "/usr/local/sbin/netprobe-zipupdate"
ZIPUPDATE_CMD = ["/usr/bin/systemd-run", "--unit=netprobe-zipupdate", "--collect", "--quiet", ZIPUPDATE_SCRIPT]
ZIP_STATUS = "zipupdate.status"
ZIP_LOG = "zipupdate.log"
PKGCHECK = "/usr/local/lib/netmon/pkgcheck.py"
UPLOAD_ZIP = os.path.join(STATE_DIR, "upload", "netmon.zip")

UNINSTALL_SCRIPT = "/usr/local/sbin/netprobe-uninstall"
UNINSTALL_CMD = ["/usr/bin/systemd-run", "--unit=netprobe-uninstall", "--collect", "--quiet",
                 UNINSTALL_SCRIPT, "--conferma"]

SUDOERS_HINT = ("Permesso mancante: installa il file /etc/sudoers.d/netprobe come descritto "
                "nella guida (sezione Riavvio e aggiornamento).")


def can_sudo(cmd) -> bool:
    """True se l'utente attuale può eseguire esattamente questo comando con sudo, senza password."""
    try:
        r = subprocess.run(["sudo", "-n", "-l", *cmd], capture_output=True, text=True, timeout=10)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def reboot(delay: float = 3.0) -> tuple[bool, str]:
    """Riavvia la sonda dopo `delay` secondi (il tempo di rispondere o di inviare l'esito)."""
    if MANAGED_BY:
        return False, managed("reboot")
    if not can_sudo(REBOOT_CMD):
        return False, SUDOERS_HINT

    def later():
        time.sleep(delay)
        subprocess.run(["sudo", "-n", *REBOOT_CMD], capture_output=True, timeout=30)

    threading.Thread(target=later, daemon=True, name="riavvio").start()
    return True, "Riavvio avviato."


def uninstall(delay: float = 2.0) -> tuple[bool, str]:
    """Toglie netmon dalla sonda, in un'unità systemd separata: ferma anche questa pagina, quindi
    parte dopo `delay` secondi, il tempo di rispondere al browser."""
    if MANAGED_BY:
        return False, managed("uninstall")
    if not (os.path.exists(UNINSTALL_SCRIPT) and can_sudo(UNINSTALL_CMD)):
        return False, ("Funzione non ancora installata: aggiorna la sonda una volta con "
                       "sudo bash installa-sonda.sh --aggiorna, oppure disinstalla da lì con --disinstalla.")

    def later():
        time.sleep(delay)
        subprocess.run(["sudo", "-n", *UNINSTALL_CMD], capture_output=True, timeout=30)

    threading.Thread(target=later, daemon=True, name="disinstallazione").start()
    return True, "Disinstallazione avviata."


def upgrade_status() -> dict:
    """Stato dell'ultimo aggiornamento: state (none|running|ok|error), orari, riavvio richiesto."""
    try:
        with open(_sys_path(UPGRADE_STATUS), encoding="utf-8") as f:
            st = json.load(f)
    except (OSError, ValueError):
        st = {"state": "none"}
    # Se lo stato dice "in corso" ma l'unità non esiste più, l'aggiornamento è stato interrotto
    if st.get("state") == "running" and not _unit_active():
        if time.time() - (st.get("started") or 0) > 60:
            st["state"] = "error"
            st["note"] = "interrotto"
    st["reboot_required"] = os.path.exists("/var/run/reboot-required")
    return st


def _unit_active(unit="netprobe-upgrade") -> bool:
    try:
        r = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=5)
        return r.stdout.strip() in ("active", "activating")
    except (OSError, subprocess.TimeoutExpired):
        return False


def upgrade_log(max_chars: int = 4000, path: str = UPGRADE_LOG) -> str:
    try:
        with open(_sys_path(path), encoding="utf-8", errors="replace") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_chars))
            text = f.read()
        return text if size <= max_chars else "…" + text[text.find("\n") + 1:]
    except OSError:
        return ""


def start_upgrade() -> tuple[bool, str]:
    """Avvia apt update && apt upgrade in background. Non attende la fine."""
    if MANAGED_BY:
        return False, managed("upgrade")
    if upgrade_status().get("state") == "running":
        return False, "Un aggiornamento è già in corso."
    if not can_sudo(UPGRADE_CMD):
        return False, SUDOERS_HINT
    try:
        r = subprocess.run(["sudo", "-n", *UPGRADE_CMD], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Avvio non riuscito: {exc}"
    if r.returncode != 0:
        return False, "Avvio non riuscito: " + (r.stderr.strip() or f"codice {r.returncode}")[:300]
    return True, "Aggiornamento avviato."


# ------------------------------------------------------------------ aggiornamento di netmon dal server
def server_base(server_url: str) -> str:
    return (server_url or "").rsplit("/api/report", 1)[0].rstrip("/")


def _urlopen(req, timeout: float):
    """urlopen senza redirect: urllib li seguirebbe ripetendo il token anche verso un altro host."""
    import urllib.request

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    return opener.open(req, timeout=timeout)


def _get_json(url: str, token: str = "", timeout: float = 30):
    """GET JSON con urllib (usato raramente: niente client permanente)."""
    import urllib.request
    import urllib.error
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "netmon-probe",
                                               **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with _urlopen(req, timeout) as r:
            raw = r.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise RuntimeError("risposta del server troppo grande")
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("detail")
        except Exception:
            detail = None
        raise RuntimeError(detail or f"errore HTTP {exc.code}") from None
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"server non raggiungibile ({exc})") from None


_server_version_cache = [0.0, "", None]


def server_version(server_url: str, timeout: float = 5):
    """Versione della sonda disponibile sul server (da /health), oppure None. Cache di un minuto."""
    now = time.monotonic()
    if _server_version_cache[1] == server_url and now - _server_version_cache[0] < 60:
        return _server_version_cache[2]
    try:
        h = _get_json(server_base(server_url) + "/health", timeout=timeout) or {}
        version = h.get("probe_version")
    except RuntimeError:
        version = None
    _server_version_cache[:] = [now, server_url, version]
    return version


def version_key(v: str):
    """Versione confrontabile: 2.0.20261008-000000 → (2, 0, 20261008, 0)."""
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


# Versione scritta nei file (pattern scritto apposta senza la sequenza «__version__ = "»)
VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.M)


def verify_signature(manifest: bytes, signature: bytes, key_path: str = UPDATE_KEY) -> bool:
    """Firma Ed25519 del manifesto, verificata con openssl e la chiave pubblica del server."""
    with tempfile.TemporaryDirectory(prefix="netmon-verify-") as d:
        mpath, spath = os.path.join(d, "manifest"), os.path.join(d, "manifest.sig")
        with open(mpath, "wb") as f:
            f.write(manifest)
        with open(spath, "wb") as f:
            f.write(signature)
        try:
            r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", key_path, "-rawin",
                                "-in", mpath, "-sigfile", spath], capture_output=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            return False
        return r.returncode == 0


def fetch_and_stage(server_url: str, token: str) -> str:
    """Scarica i programmi dal server, controlla impronte e firma e li prepara in STAGE_DIR.
    Restituisce la versione preparata; solleva RuntimeError con un messaggio leggibile."""
    bundle = _get_json(server_base(server_url) + "/api/probe-update", token, timeout=60)
    files = bundle.get("files") if isinstance(bundle, dict) else None
    version = str(bundle.get("version") or "")[:40] if isinstance(bundle, dict) else ""
    if not isinstance(files, dict) or set(files) != set(SELF_FILES):
        raise RuntimeError("risposta del server non valida (file mancanti o in più)")
    if not version or any(c not in "0123456789.-" for c in version):
        raise RuntimeError("risposta del server non valida (versione)")
    # niente ritorni a versioni precedenti (una versione vecchia, anche firmata, può avere difetti già corretti)
    current = __version__                        # tutti i file della sonda hanno la stessa versione
    if version_key(version) < version_key(current):
        raise RuntimeError(f"il server offre la versione {version}, precedente a quella installata "
                           f"({current}): aggiornamento rifiutato")
    blobs, manifest = {}, []
    for name in SELF_FILES:
        entry = files[name] if isinstance(files[name], dict) else {}
        data = str(entry.get("content", "")).encode("utf-8")
        digest = hashlib.sha256(data).hexdigest()
        if not data or digest != entry.get("sha256"):
            raise RuntimeError(f"impronta di {name} non corrispondente: scaricamento danneggiato")
        m = VERSION_RE.search(data.decode("utf-8", "replace"))
        if not m or m.group(1) != version:
            raise RuntimeError(f"{name} non è della versione {version}")
        blobs[name] = data
        manifest.append(f"{digest}  {name}")
    manifest_bytes = ("\n".join(manifest) + "\n").encode("utf-8")
    signature = b""
    if os.path.exists(UPDATE_KEY):
        try:
            signature = base64.b64decode(str(bundle.get("signature") or ""), validate=True)
        except ValueError:
            signature = b""
        if not signature:
            raise RuntimeError("aggiornamento non firmato dal server: sulla VM lancia "
                               "installa-server.sh --aggiorna")
        if not verify_signature(manifest_bytes, signature):
            raise RuntimeError("firma dell'aggiornamento non valida: aggiornamento rifiutato. Se hai "
                               "reinstallato il server, aggiorna la sonda con installa-sonda.sh --aggiorna")
    tmp = STAGE_DIR + ".tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, mode=0o755)
    for name, data in blobs.items():
        with open(os.path.join(tmp, name), "wb") as f:
            f.write(data)
    with open(os.path.join(tmp, "manifest"), "wb") as f:
        f.write(manifest_bytes)
    if signature:
        with open(os.path.join(tmp, "manifest.sig"), "wb") as f:
            f.write(signature)
    with open(os.path.join(tmp, "VERSION"), "w", encoding="utf-8") as f:
        f.write(version + "\n")
    shutil.rmtree(STAGE_DIR, ignore_errors=True)
    os.replace(tmp, STAGE_DIR)
    return version


def selfupdate_status() -> dict:
    """Stato dell'ultimo aggiornamento di netmon: state (none|running|ok|error), orari, versione."""
    try:
        with open(_sys_path(SELF_STATUS), encoding="utf-8") as f:
            st = json.load(f)
    except (OSError, ValueError):
        st = {"state": "none"}
    if st.get("state") == "running" and not _unit_active("netprobe-selfupdate"):
        if time.time() - (st.get("started") or 0) > 120:
            st["state"] = "error"
            st["note"] = "interrotto"
    return st


def selfupdate_log(max_chars: int = 4000) -> str:
    return upgrade_log(max_chars, SELF_LOG)


def self_update(server_url: str, token: str) -> tuple[bool, str]:
    """Scarica e installa la versione di netmon del server. Non attende la fine: la sonda si
    riavvia durante l'installazione."""
    if selfupdate_status().get("state") == "running":
        return False, "Un aggiornamento di netmon è già in corso."
    if not os.path.exists("/usr/local/sbin/netprobe-selfupdate") or not can_sudo(SELFUPDATE_CMD):
        return False, ("Permesso mancante: aggiorna la sonda una volta a mano con "
                       "sudo bash installa-sonda.sh --aggiorna (installa il programma di aggiornamento).")
    try:
        version = fetch_and_stage(server_url, token)
    except (RuntimeError, OSError) as exc:
        return False, f"Scaricamento non riuscito: {exc}"
    try:
        r = subprocess.run(["sudo", "-n", *SELFUPDATE_CMD], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Avvio non riuscito: {exc}"
    if r.returncode != 0:
        return False, "Avvio non riuscito: " + (r.stderr.strip() or f"codice {r.returncode}")[:300]
    return True, f"Aggiornamento alla versione {version} avviato: la sonda si riavvierà tra pochi secondi."


# ------------------------------------------------------------------ aggiornamento completo da pacchetto
def can_zipupdate() -> bool:
    return os.path.exists(ZIPUPDATE_SCRIPT) and os.path.exists(PKGCHECK) and can_sudo(ZIPUPDATE_CMD)


def zipupdate_status() -> dict:
    try:
        with open(os.path.join(SYS_DIR, ZIP_STATUS), encoding="utf-8") as f:
            st = json.load(f)
    except (OSError, ValueError):
        st = {"state": "none"}
    if st.get("state") == "running" and not _unit_active("netprobe-zipupdate"):
        if time.time() - (st.get("started") or 0) > 900:
            st["state"] = "error"
            st["note"] = "interrotto"
    return st


def zipupdate_log(max_chars: int = 6000) -> str:
    return upgrade_log(max_chars, ZIP_LOG)


UPLOAD_MANIFEST = os.path.join(STATE_DIR, "upload", "package.manifest")
UPLOAD_SIG = os.path.join(STATE_DIR, "upload", "package.sig")
MAX_PACKAGE = 10 * 1024 * 1024
PACKAGE_MANIFEST_RE = re.compile(r"([0-9a-f]{64})  netmon\.zip\nversion (\d+\.\d+\.\d{8}-\d{6})\n")


class NoPackage(Exception):
    """Il server non offre il pacchetto completo (server vecchio o pacchetto non firmato)."""


class AlreadyCurrent(Exception):
    """La sonda ha già la versione del server (o una più recente): non c'è niente da installare."""


def _get_bytes(url: str, token: str, limit: int, timeout: float = 120) -> bytes:
    import urllib.request
    import urllib.error
    req = urllib.request.Request(url, headers={"User-Agent": "netmon-probe", "Authorization": f"Bearer {token}"})
    try:
        with _urlopen(req, timeout) as r:
            raw = r.read(limit + 1)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"errore HTTP {exc.code}") from None
    except OSError as exc:
        raise RuntimeError(f"server non raggiungibile ({exc})") from None
    if len(raw) > limit:
        raise RuntimeError("pacchetto troppo grande")
    return raw


def fetch_package(server_url: str, token: str) -> str:
    """Scarica il pacchetto completo netmon.zip dal server e lo prepara per netprobe-zipupdate,
    insieme al manifesto firmato da root sulla VM. Controlla firma, impronta e versione.
    Solleva NoPackage se il server non lo offre, RuntimeError per gli altri problemi."""
    base = server_base(server_url)
    try:
        info = _get_json(base + "/api/probe-package/info", token, timeout=30)
    except RuntimeError as exc:
        if "404" in str(exc) or "non disponibile" in str(exc):
            raise NoPackage(str(exc)) from None
        raise
    if not isinstance(info, dict):
        raise RuntimeError("risposta del server non valida")
    manifest = str(info.get("manifest") or "")
    m = PACKAGE_MANIFEST_RE.fullmatch(manifest)
    if not m:
        raise RuntimeError("risposta del server non valida (manifesto del pacchetto)")
    digest, version = m.group(1), m.group(2)
    try:
        signature = base64.b64decode(str(info.get("signature") or ""), validate=True)
    except ValueError:
        signature = b""
    if not signature or not verify_signature(manifest.encode("utf-8"), signature):
        raise RuntimeError("firma del pacchetto non valida: aggiornamento rifiutato. Se hai reinstallato il "
                           "server, aggiorna la sonda con installa-sonda.sh --aggiorna")
    if version_key(version) <= version_key(__version__):
        raise AlreadyCurrent(f"La sonda ha già la versione {__version__} (sul server c'è la {version}): "
                             "niente da aggiornare.")
    data = _get_bytes(base + "/api/probe-package", token, MAX_PACKAGE)
    if hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError("impronta del pacchetto non corrispondente: scaricamento danneggiato")
    folder = os.path.dirname(UPLOAD_ZIP)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    for path, blob in ((UPLOAD_ZIP, data), (UPLOAD_MANIFEST, manifest.encode("utf-8")), (UPLOAD_SIG, signature)):
        fd, tmp = tempfile.mkstemp(dir=folder, prefix=".scaricato-")
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
        os.replace(tmp, path)
    return version


def update_from_server(server_url: str, token: str) -> tuple[bool, str, str]:
    """Aggiornamento di netmon dal server: completo (pacchetto netmon.zip firmato dalla VM, come
    installa-sonda.sh --aggiorna) se sonda e server lo permettono, altrimenti solo i programmi.
    Restituisce (esito, messaggio, modo) con modo "zip" oppure "py"."""
    if MANAGED_BY:
        return False, managed("update"), "py"
    if not (can_zipupdate() and os.path.exists(UPDATE_KEY)):
        ok, message = self_update(server_url, token)
        return ok, message, "py"
    if any(st().get("state") == "running" for st in (zipupdate_status, selfupdate_status, upgrade_status)):
        return False, "C'è già un aggiornamento in corso.", "zip"
    try:
        version = fetch_package(server_url, token)
    except NoPackage:
        ok, message = self_update(server_url, token)     # server senza pacchetto completo
        return ok, message, "py"
    except AlreadyCurrent as exc:
        return True, str(exc), "same"                    # già aggiornata: è un esito riuscito
    except (RuntimeError, OSError) as exc:
        return False, f"Scaricamento non riuscito: {exc}", "zip"
    ok, message = start_zipupdate()
    if ok:
        message = f"Aggiornamento completo alla versione {version} avviato: la sonda si riavvierà tra poco."
    return ok, message, "zip"


def start_zipupdate() -> tuple[bool, str]:
    running = (zipupdate_status().get("state") == "running" or selfupdate_status().get("state") == "running"
               or upgrade_status().get("state") == "running")
    if running:
        return False, "C'è già un aggiornamento in corso."
    if not can_zipupdate():
        return False, ("Funzione non ancora installata: aggiorna la sonda una volta a mano con "
                       "sudo bash installa-sonda.sh --aggiorna.")
    try:
        r = subprocess.run(["sudo", "-n", *ZIPUPDATE_CMD], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"Avvio non riuscito: {exc}"
    if r.returncode != 0:
        return False, "Avvio non riuscito: " + (r.stderr.strip() or f"codice {r.returncode}")[:300]
    return True, "Aggiornamento avviato: la sonda si riavvierà tra poco."


# ------------------------------------------------------------------ reti Wi-Fi (NetworkManager)
# Le aggiunge o le toglie /usr/local/sbin/netprobe-wifi (root), avviato con systemd-run come gli
# aggiornamenti. La richiesta (con la password della rete) passa da un file leggibile solo dalla
# sonda, che lo script cancella appena letto; l'esito torna in SYS_DIR/wifi.status.
WIFI_SCRIPT = "/usr/local/sbin/netprobe-wifi"
WIFI_CMD = ["/usr/bin/systemd-run", "--unit=netprobe-wifi", "--collect", "--quiet", WIFI_SCRIPT]
WIFI_REQUEST = os.path.join(STATE_DIR, "wifi", "request.json")
WIFI_STATUS = "wifi.status"
WIFI_LOG = "wifi.log"
_wifi_cap = {}
WIFI_RECHECK = 600        # secondi: un "no" si ricontrolla (un si' resta valido finche' la sonda gira)


def wifi_problem() -> str:
    """Perche' la sonda non puo' gestire le reti Wi-Fi ("" se puo'): gestita da un altro sistema,
    script, nmcli, permesso sudo."""
    if MANAGED_BY:
        return "managed"
    if not os.path.exists(WIFI_SCRIPT):
        return "script"
    if not shutil.which("nmcli"):
        return "nmcli"
    if not can_sudo(WIFI_CMD):
        return "sudo"
    return ""


def can_wifi() -> bool:
    now = time.monotonic()
    if _wifi_cap.get("problem") != "" and now - _wifi_cap.get("at", -1e9) > WIFI_RECHECK:
        _wifi_cap.update(problem=wifi_problem(), at=now)
    return _wifi_cap["problem"] == ""


def wifi_status() -> dict:
    try:
        with open(os.path.join(SYS_DIR, WIFI_STATUS), encoding="utf-8") as f:
            st = json.load(f)
    except (OSError, ValueError):
        st = {"state": "none"}
    if st.get("state") == "running" and not _unit_active("netprobe-wifi"):
        if time.time() - (st.get("started") or 0) > 300:
            st["state"] = "error"
            st["message"] = "interrotto"
    return st


def start_wifi(request: dict) -> tuple[bool, str]:
    """Scrive la richiesta (solo per la sonda) e avvia lo script di root. Non attende la fine."""
    if MANAGED_BY:
        return False, managed("wifi")
    if wifi_status().get("state") == "running":
        return False, "C'è già un'operazione sulle reti Wi-Fi in corso."
    if not can_wifi():
        return False, "Funzione non disponibile: serve NetworkManager e la versione aggiornata di netmon sulla sonda."
    os.makedirs(os.path.dirname(WIFI_REQUEST), mode=0o700, exist_ok=True)
    try:
        os.remove(WIFI_REQUEST)
    except OSError:
        pass
    fd = os.open(WIFI_REQUEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(request, f)
    try:
        r = subprocess.run(["sudo", "-n", *WIFI_CMD], capture_output=True, text=True, timeout=30)
        rc, err = r.returncode, r.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        rc, err = 1, str(exc)
    if rc != 0:
        try:
            os.remove(WIFI_REQUEST)                    # la password non resta su disco
        except OSError:
            pass
        return False, "Avvio non riuscito: " + (err or f"codice {rc}")[:300]
    return True, "Operazione sulle reti Wi-Fi avviata."


def _nm_fields(line):
    out, cur, i = [], "", 0
    while i < len(line):
        if line[i] == "\\" and i + 1 < len(line):
            cur += line[i + 1]
            i += 2
            continue
        if line[i] == ":":
            out.append(cur)
            cur = ""
        else:
            cur += line[i]
        i += 1
    out.append(cur)
    return out


def wifi_networks() -> dict:
    """Reti Wi-Fi salvate (SSID), lette senza privilegi. nm=False se NetworkManager non c'è."""
    nmcli = shutil.which("nmcli")
    if not nmcli:
        return {"nm": False, "known": []}
    try:
        r = subprocess.run([nmcli, "-t", "-f", "UUID,TYPE", "connection", "show"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return {"nm": False, "known": []}
        known = []
        for line in r.stdout.splitlines():
            f = _nm_fields(line)
            if len(f) >= 2 and f[1] == "802-11-wireless":
                s = subprocess.run([nmcli, "-g", "802-11-wireless.ssid", "connection", "show", "uuid", f[0]],
                                   capture_output=True, text=True, timeout=10).stdout.rstrip("\n")
                ssid = _nm_fields(s)[0] if s else ""
                if ssid and ssid not in known:
                    known.append(ssid)
        return {"nm": True, "known": known[:10]}
    except (OSError, subprocess.TimeoutExpired):
        return {"nm": False, "known": []}
