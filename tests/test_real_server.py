"""Add-on contro il server NetMon vero (facoltativa: NETMON_REPO e NETMON_PYTHON, vedi LEGGIMI.md):
la sonda dell'add-on scrive solo nel suo account, il server la riconosce come gestita da Home
Assistant e rifiuta i comandi che qui non hanno senso; un altro account non vede niente."""
import time

import pytest

from conftest import wait_until
from realserver import RealServer, call


@pytest.fixture
def real():
    with RealServer() as srv:
        yield srv


def probes_of(srv, cookie):
    status, data, _ = call(srv.base, "GET", "/api/status", cookie=cookie)
    assert status == 200, data
    return {p["name"]: p for p in data["probes"]}


def test_addon_on_real_server_isolated(real, make_addon):
    cookie_a, tok_a = real.account("a@example.test")
    cookie_b, tok_b = real.account("b@example.test")
    key_a, key_b = next(iter(tok_a)), next(iter(tok_b))
    make_addon({"server": real.base, "token": tok_a[key_a], "name": "Casa A"})
    assert wait_until(lambda: (probes_of(real, cookie_a).get(key_a) or {}).get("system"), timeout=60)
    mine = probes_of(real, cookie_a)[key_a]
    assert mine["system"]["managed_by"] == "Home Assistant"
    # l'altro account non vede la sonda né i suoi dispositivi
    other = probes_of(real, cookie_b)
    assert key_a not in other and "Casa A" not in repr(other)
    # comandi che nell'add-on non hanno senso: rifiutati dal server con il motivo
    for cmd in ("reboot", "update"):
        status, data, _ = call(real.base, "POST", "/api/probe-command", {"probe": key_a, "command": cmd},
                               cookie=cookie_a)
        assert status == 409 and "Home Assistant" in str(data), (cmd, status, data)
    # B non può comandare la sonda di A
    status, _, _ = call(real.base, "POST", "/api/probe-command", {"probe": key_a, "command": "reboot"},
                        cookie=cookie_b)
    assert status in (403, 404)


def test_token_of_other_account_cannot_write(real):
    _, tok_a = real.account("a@example.test")
    cookie_b, tok_b = real.account("b@example.test")
    key_a, key_b = next(iter(tok_a)), next(iter(tok_b))
    # il token di B non scrive nella sonda di A, nemmeno dichiarando la chiave di A
    body = {"probe": key_a, "interval": 60, "devices": {"Intruso": {"ok": True, "host": "10.0.0.1", "rtt": 1}}}
    call(real.base, "POST", "/api/report", body, token=tok_b[key_b])
    time.sleep(0.5)
    _, data, _ = call(real.base, "GET", "/api/status", cookie=cookie_b)
    assert all(p["name"] != key_a for p in data["probes"])
    status, _, _ = call(real.base, "POST", "/api/report", body, token="sonda_inventato")
    assert status == 401
