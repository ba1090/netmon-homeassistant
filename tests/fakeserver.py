"""Server NetMon finto per le prove: riceve i report delle sonde e risponde alle API che usa
l'integrazione, con più account separati. Niente dipendenze oltre alla libreria standard.

- POST /api/report e GET /api/probe-config con «Authorization: Bearer <token della sonda>»;
- POST /api/auth/login con email e password, che danno il cookie netmon_session;
- GET /api/status con il cookie: solo le sonde dell'account della sessione.
"""
import json
import secrets
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

COOKIE = "netmon_session"


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.accounts = {}          # email -> {"password", "probes": {chiave: token}}
        self.tokens = {}            # token -> (email, chiave sonda)
        self.sessions = {}          # cookie -> email
        self.reports = []           # (chiave sonda, corpo del report)
        self.last = {}              # chiave sonda -> ultimo report
        self.status_override = None  # corpo di /api/status al posto di quello vero (dati malformati)
        self.requests = 0
        self.conns = set()          # connessioni aperte: chiuse anche loro quando il server «cade»

    def add_account(self, email, password, probes=("p_test",)):
        with self.lock:
            acc = self.accounts.setdefault(email, {"password": password, "probes": {}})
            for key in probes:
                tok = "sonda_" + secrets.token_urlsafe(24)
                acc["probes"][key] = tok
                self.tokens[tok] = (email, key)
            return {k: acc["probes"][k] for k in probes}

    def status_for(self, email):
        out = []
        for key in self.accounts[email]["probes"]:
            rep = self.last.get(key) or {}
            devices = [{"name": n, "host": d.get("host"), "state": "ok" if d.get("ok") else "bad",
                        "rtt": d.get("rtt"), "text": ""} for n, d in (rep.get("devices") or {}).items()]
            out.append({"name": key, "label": rep.get("probe") and key, "state": "ok" if rep else "bad",
                        "system": rep.get("system") or {}, "fritz": rep.get("fritz") or {},
                        "devices": devices, "seen": 1})
        return {"probes": out, "server": {"version": "finto"}}


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def setup(self):
            super().setup()
            with state.lock:
                state.conns.add(self.connection)

        def finish(self):
            with state.lock:
                state.conns.discard(self.connection)
            super().finish()

        def _send(self, status, body, headers=()):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for k, v in headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            try:
                return json.loads(raw or b"{}")
            except ValueError:
                return None

        def _probe(self):
            tok = (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
            return state.tokens.get(tok)

        def _session(self):
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == COOKIE:
                    return state.sessions.get(v)
            return None

        def do_GET(self):
            state.requests += 1
            path = urlsplit(self.path).path
            if path == "/health":
                return self._send(200, {"ok": True})
            if path == "/api/probe-config":
                if not self._probe():
                    return self._send(401, {"detail": "token non valido"})
                return self._send(200, {"config_rev": 0, "has_config": False})
            if path == "/api/status":
                email = self._session()
                if not email:
                    return self._send(401, {"detail": "accesso richiesto"})
                with state.lock:
                    body = state.status_override if state.status_override is not None else state.status_for(email)
                return self._send(200, body)
            return self._send(404, {"detail": "non trovato"})

        def do_POST(self):
            state.requests += 1
            path = urlsplit(self.path).path
            body = self._body()
            if path in ("/api/report", "/api/backfill"):
                who = self._probe()
                if not who:
                    return self._send(401, {"detail": "token non valido"})
                if not isinstance(body, dict):
                    return self._send(422, {"detail": "corpo non valido"})
                with state.lock:
                    reports = body.get("reports") if isinstance(body.get("reports"), list) else [body]
                    for rep in reports:
                        state.reports.append((who[1], rep))
                        state.last[who[1]] = rep
                    del state.reports[:-2000]
                return self._send(200, {"ok": True, "alerts": 0, "config_rev": 0, "has_config": False})
            if path == "/api/auth/login":
                acc = state.accounts.get(str((body or {}).get("email") or "").lower())
                if not acc or acc["password"] != (body or {}).get("password"):
                    return self._send(401, {"detail": "Email o password errate."})
                cookie = secrets.token_urlsafe(24)
                with state.lock:
                    state.sessions[cookie] = body["email"].lower()
                return self._send(200, {"ok": True}, [("Set-Cookie", f"{COOKIE}={cookie}; Path=/; HttpOnly")])
            return self._send(404, {"detail": "non trovato"})

    return Handler


class FakeServer:
    """port e state permettono di far «tornare» lo stesso server dopo una caduta."""

    def __init__(self, port=0, state=None):
        self.state = state or State()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(self.state))
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        with self.state.lock:
            conns = list(self.state.conns)
        for c in conns:                       # anche le connessioni tenute aperte (keep-alive)
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
