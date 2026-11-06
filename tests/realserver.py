"""Server NetMon vero per le prove facoltative: si usa quando NETMON_REPO indica una copia di
https://github.com/ba1090/NetMon e NETMON_PYTHON un Python con le sue dipendenze (server/requirements.txt).
Gira come sulla VM (uvicorn, UMask 0077); account e sonde si creano con le stesse API della pagina."""
import http.cookies
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from conftest import free_port

PASSWORD = "Password-Prova-123!"


def config():
    repo, py = os.getenv("NETMON_REPO"), os.getenv("NETMON_PYTHON")
    if not repo or not py or not (Path(repo) / "server" / "app.py").exists():
        pytest.skip("server NetMon vero non configurato (NETMON_REPO e NETMON_PYTHON)")
    return Path(repo), py


def call(base, method, path, body=None, cookie=None, token=None):
    req = urllib.request.Request(base + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Content-Type", "application/json")
    if cookie:
        req.add_header("Cookie", f"netmon_session={cookie}")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"null"), r.headers
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            data = json.loads(raw or b"null")
        except ValueError:
            data = raw.decode(errors="replace")
        return exc.code, data, exc.headers


class RealServer:
    def __init__(self):
        self.repo, self.python = config()
        self.data = Path(tempfile.mkdtemp(prefix="netmon-ha-"))
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.api_token = "chiave-" + secrets.token_urlsafe(16)
        self.env = {**os.environ, "API_TOKEN": self.api_token, "DATA_DIR": str(self.data), "COOKIE_SECURE": "0",
                    "VM_ID": "", "ROLE": "", "GATEWAY_SECRET": "", "SMTP_HOST": "", "TELEGRAM_BOT_TOKEN": "",
                    "MIN_FREE_MB": "1", "SCRYPT_SLOTS": "3", "MALLOC_ARENA_MAX": "2", "NEW_USER_PLAN": "basso",
                    "PUBLIC_URL": self.base}
        self.first = True

    def __enter__(self):
        self.log = open(self.data / "server.log", "ab")
        self.proc = subprocess.Popen(
            [self.python, "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", str(self.port),
             "--no-access-log", "--ws", "none"], cwd=self.repo / "server", env=self.env,
            stdout=self.log, stderr=subprocess.STDOUT, preexec_fn=lambda: os.umask(0o077))
        end = time.time() + 40
        while time.time() < end:
            try:
                if call(self.base, "GET", "/health")[0] < 500:
                    return self
            except OSError:
                pass
            if self.proc.poll() is not None:
                raise RuntimeError("il server non parte: " + (self.data / "server.log").read_text()[-3000:])
            time.sleep(0.2)
        raise RuntimeError("il server non risponde")

    def __exit__(self, *exc):
        self.proc.terminate()
        try:
            self.proc.wait(20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()

    def authdb(self):
        sys.path.insert(0, str(self.repo / "server"))
        import auth  # noqa: PLC0415 — solo libreria standard
        return auth.AuthDB(self.data / "auth.db")

    def account(self, email, probes=1):
        """Nuovo account con `probes` sonde; restituisce (cookie, {chiave sonda: token})."""
        db = self.authdb()
        code = self.api_token if self.first else db.create_invite("prova", email=email)
        self.first = False
        status, data, headers = call(self.base, "POST", "/api/auth/register",
                                     {"token": code, "email": email, "password": PASSWORD})
        assert status == 200, data
        cookie = http.cookies.SimpleCookie(headers.get("Set-Cookie"))["netmon_session"].value
        with db._conn() as c:
            uid = c.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()[0]
        db.set_limits(uid, 10, 5, 100, "personalizzato")
        tokens = {}
        for i in range(probes):
            status, data, _ = call(self.base, "POST", "/api/probes/new", {"name": f"sonda {i}"}, cookie=cookie)
            assert status == 200, data
            tokens[data["key"]] = data["token"]
        return cookie, tokens
