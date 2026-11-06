"""L'add-on in funzione, come nel container: la sonda manda i report, la pagina locale parte solo
quando la si apre e si chiude da sola, la password vale anche dopo una ripartenza della pagina, i
dati restano leggibili solo dall'add-on e l'arresto ferma tutto."""
import os
import signal
import socket
import stat
import time

from conftest import options, wait_until


def test_probe_reports_and_says_managed(server, token, make_addon):
    addon = make_addon(options(server, token))
    rep = wait_until(lambda: server.state.last.get("p_test"), timeout=30)
    assert rep, addon.logtext()
    system = rep.get("system") or {}
    assert system.get("managed_by") == "Home Assistant"
    assert system.get("os") == "Home Assistant"
    # la password della pagina non arriva alla sonda (né al server)
    pw = addon.password()
    assert pw and pw not in repr(server.state.reports)
    probe = addon.probe_pid()
    with open(f"/proc/{probe}/environ", "rb") as f:
        assert b"WEB_PASSWORD" not in f.read()


def test_wrong_token_not_accepted(server, make_addon):
    server.state.add_account("a@example.test", "Password-A-123")
    addon = make_addon(options(server, "sonda_falso"))
    time.sleep(6)
    assert not server.state.last
    assert addon.proc.poll() is None            # la sonda riprova, l'add-on resta acceso


def test_page_starts_on_demand_and_stops_when_idle(server, token, make_addon):
    addon = make_addon(options(server, token), idle_minutes=0.05)     # 3 secondi
    addon.wait_page_ready()
    assert addon.page_pid() is None              # nessuno l'ha aperta: non gira
    status, _, _ = addon.request("GET", "/", password=addon.password())
    assert status == 200
    assert addon.page_pid()                      # avviata dalla visita, con la porta dell'add-on
    # chiusa da sola dopo il tempo senza richieste (controllo ogni 30 s nella pagina)
    assert wait_until(lambda: addon.page_pid() is None, timeout=60)
    assert "pagina locale: terminata" not in addon.logtext()      # uscita regolare, nessun messaggio
    # e riparte alla visita successiva
    assert addon.request("GET", "/", password=addon.password())[0] == 200


def test_password_changed_from_page_survives_page_restart(server, token, make_addon):
    addon = make_addon(options(server, token))
    old = addon.wait_page_ready()
    new = "Nuova-Password-Pagina-42"
    status, _, body = addon.request("POST", "/api/password", password=old,
                                    body={"password": new, "repeat": new})
    assert status == 200, body
    assert addon.password() == new
    assert stat.S_IMODE(os.stat(addon.data / "web.env").st_mode) == 0o600
    # la pagina si ferma (per inattività o per un errore): alla ripartenza vale la password nuova
    os.kill(addon.page_pid(), signal.SIGKILL)
    wait_until(lambda: addon.page_pid() is None)
    time.sleep(1.5)
    status = None
    for _ in range(30):                          # dopo un errore la pagina riparte entro 10 s
        try:
            status = addon.request("GET", "/", password=new)[0]
            break
        except OSError:
            time.sleep(0.5)
    assert status == 200
    assert addon.request("GET", "/", password=old)[0] == 401


def test_page_requires_password_host_and_origin(server, token, make_addon):
    addon = make_addon(options(server, token))
    pw = addon.wait_page_ready()
    assert addon.request("GET", "/")[0] == 401
    assert addon.request("GET", "/api/config", password="sbagliata-sbagliata")[0] == 401
    # DNS rebinding: un nome di Internet nel Host non apre la pagina nemmeno con la password
    assert addon.request("GET", "/", password=pw, host="evil.example")[0] in (400, 403, 421)
    # CSRF: un POST da un'altra origine viene rifiutato
    status, _, _ = addon.request("POST", "/api/password", password=pw,
                                 body={"password": "X" * 16, "repeat": "X" * 16},
                                 headers={"Origin": "http://evil.example"})
    assert status == 403
    assert addon.password() == pw


def test_secrets_masked_on_page(server, token, make_addon):
    addon = make_addon(options(server, token))
    pw = addon.wait_page_ready()
    status, headers, body = addon.request("GET", "/api/config", password=pw)
    assert status == 200
    assert token.encode() not in body
    assert headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors 'none'" in headers.get("Content-Security-Policy", "")


def test_data_files_private(server, token, make_addon):
    """Tutto quello che l'add-on e la sonda scrivono in /data è leggibile solo da loro."""
    addon = make_addon(options(server, token))
    wait_until(lambda: server.state.last.get("p_test"), timeout=30)
    time.sleep(2)
    bad = []
    for root, dirs, files in os.walk(addon.data):
        for name in files:
            path = os.path.join(root, name)
            if name == "options.json":           # lo scrive Home Assistant, non l'add-on
                continue
            mode = stat.S_IMODE(os.stat(path).st_mode)
            if mode & 0o077:
                bad.append((path, oct(mode)))
    assert not bad, bad


def test_sigterm_stops_everything(server, token, make_addon):
    addon = make_addon(options(server, token))
    wait_until(lambda: server.state.last.get("p_test"), timeout=30)
    addon.request("GET", "/", password=addon.password())
    kids = [addon.probe_pid(), wait_until(addon.page_pid)]
    assert all(kids)
    t = time.monotonic()
    addon.stop()
    assert addon.proc.returncode == 0 and time.monotonic() - t < 15
    assert all(not os.path.exists(f"/proc/{k}") or "zombie" in open(f"/proc/{k}/status").read().lower()
               for k in kids)


def test_busy_port_does_not_stop_probe(server, token, make_addon):
    blocker = socket.socket()
    blocker.bind(("0.0.0.0", 0))
    blocker.listen()
    try:
        addon = make_addon(options(server, token, web_port=blocker.getsockname()[1]))
        assert wait_until(lambda: server.state.last.get("p_test"), timeout=30)
        assert wait_until(lambda: "non disponibile" in addon.logtext())
        assert addon.proc.poll() is None
    finally:
        blocker.close()


def test_crashing_probe_restarted(server, token, make_addon):
    addon = make_addon(options(server, token))
    first = wait_until(addon.probe_pid)
    os.kill(first, signal.SIGKILL)
    second = wait_until(lambda: (p := addon.probe_pid()) and p != first and p, timeout=20)
    assert second
    assert "sonda: terminata" in addon.logtext()
