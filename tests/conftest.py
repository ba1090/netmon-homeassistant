"""Strumenti comuni delle prove dell'add-on: server NetMon finto, add-on avviato come nel container
(addon.py con i programmi della sonda nella stessa cartella, dati in una /data temporanea) e
richieste alla pagina locale con la sola libreria standard."""
import base64
import http.client
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
ADDON = ROOT / "netmon-sonda"
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True

from fakeserver import FakeServer  # noqa: E402


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_until(cond, timeout=20.0, step=0.1):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = cond()
        if value:
            return value
        time.sleep(step)
    return cond()


def rss_kb(pid):
    try:
        with open(f"/proc/{pid}/status", encoding="ascii") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        return 0
    return 0


def children(pid):
    """Pid dei processi figli (programmi avviati da addon.py)."""
    out = []
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                with open(f"/proc/{d}/stat", encoding="ascii") as f:
                    if int(f.read().rsplit(")", 1)[1].split()[1]) == pid:
                        out.append(int(d))
            except (OSError, ValueError, IndexError):
                pass
    return out


def cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\0", b" ").decode(errors="replace")
    except OSError:
        return ""


class Addon:
    """L'add-on avviato come nel container: /opt/netprobe con addon.py e i programmi della sonda."""

    def __init__(self, tmp, options, idle_minutes=None):
        self.app = tmp / "opt"
        self.data = tmp / "data"
        shutil.copytree(ADDON / "probe", self.app)
        shutil.copy(ADDON / "addon.py", self.app / "addon.py")
        self.data.mkdir()
        self.port = options.setdefault("web_port", free_port())
        (self.data / "options.json").write_text(json.dumps(options))
        self.log_path = tmp / "addon.log"
        self.env = {**os.environ, "ADDON_DATA": str(self.data), "ADDON_PID": str(tmp / "probe.pid"),
                    "PYTHONDONTWRITEBYTECODE": "1"}
        if idle_minutes is not None:
            self.env["ADDON_IDLE_MINUTES"] = str(idle_minutes)
        self.proc = None

    def start(self):
        self.log = open(self.log_path, "w")
        self.proc = subprocess.Popen([sys.executable, str(self.app / "addon.py")], env=self.env,
                                     stdout=self.log, stderr=subprocess.STDOUT)
        return self

    def stop(self, timeout=25):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if getattr(self, "log", None):
            self.log.close()

    def logtext(self):
        return self.log_path.read_text(errors="replace")

    def password(self):
        try:
            text = (self.data / "web.env").read_text()
        except FileNotFoundError:
            return None
        for line in text.splitlines():
            if line.startswith("WEB_PASSWORD="):
                return line.split("=", 1)[1]
        return None

    def page_pid(self):
        return next((c for c in children(self.proc.pid) if "config_web" in cmdline(c)), None)

    def probe_pid(self):
        return next((c for c in children(self.proc.pid) if "probe.py" in cmdline(c)), None)

    def request(self, method="GET", path="/", password=None, body=None, headers=None, host=None, timeout=10):
        """Richiesta alla pagina locale; restituisce (stato, intestazioni, corpo)."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if password is not None:
            h["Authorization"] = "Basic " + base64.b64encode(f"admin:{password}".encode()).decode()
        if body is not None:
            body = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
            h.setdefault("Origin", f"http://{h['Host']}")
        h.update(headers or {})
        try:
            conn.request(method, path, body=body, headers=h)
            r = conn.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        finally:
            conn.close()


@pytest.fixture
def server():
    with FakeServer() as srv:
        yield srv


@pytest.fixture
def make_addon(tmp_path):
    started = []

    def make(options, idle_minutes=None, start=True):
        a = Addon(tmp_path / f"a{len(started)}", options, idle_minutes)
        started.append(a)
        return a.start() if start else a

    yield make
    for a in started:
        a.stop()


@pytest.fixture
def addon_module(tmp_path, monkeypatch):
    """addon.py importato come modulo, con /data in una cartella temporanea."""
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("ADDON_DATA", str(data))
    sys.modules.pop("addon", None)
    monkeypatch.syspath_prepend(str(ADDON))
    import addon
    for name, file in (("OPTIONS", "options.json"), ("CONFIG", "config.yaml"), ("WEB_ENV", "web.env"),
                       ("APPLIED", "options-applied.json")):
        monkeypatch.setattr(addon, name, str(data / file))
    yield addon
    sys.modules.pop("addon", None)
