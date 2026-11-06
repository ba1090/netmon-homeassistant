"""Integrazione HACS dentro un Home Assistant vero (il pacchetto homeassistant), contro il server
NetMon finto: configurazione, isolamento tra account, dati malformati, sessione scaduta, password
sbagliata senza tentativi ripetuti, eliminazione dei dispositivi tolti e credenziali su disco.

Servono homeassistant, pytest e pytest-asyncio (vedi tests/LEGGIMI.md)."""
import asyncio
import os
import stat
import sys
from pathlib import Path

import aiohttp
import pytest

pytest.importorskip("homeassistant")

from homeassistant import config_entries, loader  # noqa: E402
from homeassistant.core import HomeAssistant  # noqa: E402
from homeassistant.helpers import aiohttp_client, frame  # noqa: E402
from homeassistant.helpers import (area_registry, category_registry, device_registry as dr,  # noqa: E402
                                   entity_registry as er, floor_registry, issue_registry, label_registry)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from fakeserver import FakeServer  # noqa: E402

PW_A, PW_B = "Password-A-123!", "Password-B-456!"


def report(srv, key, devices, **extra):
    srv.state.last[key] = {"probe": key, "devices": devices, **extra}


@pytest.fixture
def server():
    with FakeServer() as srv:
        srv.state.add_account("a@example.test", PW_A, probes=("p_casa",))
        srv.state.add_account("b@example.test", PW_B, probes=("p_altrui",))
        report(srv, "p_casa", {"Router": {"ok": True, "host": "192.168.1.1", "rtt": 1.5},
                               "NAS": {"ok": False, "host": "192.168.1.10"}},
               system={"version": "1.1", "managed_by": "Home Assistant", "load1": 0.2})
        report(srv, "p_altrui", {"Segreto": {"ok": True, "host": "10.0.0.9", "rtt": 3}})
        yield srv


class Resolver(aiohttp.ThreadedResolver):
    """DNS senza zeroconf (che in queste prove non si avvia): solo nomi normali e indirizzi."""

    async def real_close(self):
        await self.close()


@pytest.fixture
async def hass(tmp_path, monkeypatch):
    monkeypatch.setattr(aiohttp_client, "_async_make_resolver", lambda hass: Resolver())
    cfg = tmp_path / "config"
    (cfg / "custom_components").mkdir(parents=True)
    os.symlink(ROOT / "custom_components" / "netmon", cfg / "custom_components" / "netmon")
    sys.path.insert(0, str(cfg))           # custom_components.netmon importabile anche dalle prove
    hass = HomeAssistant(str(cfg))
    frame.async_setup(hass)               # come fa bootstrap: ogni prova ha il suo Home Assistant
    loader.async_setup(hass)
    await asyncio.gather(dr.async_load(hass), er.async_load(hass), issue_registry.async_load(hass),
                         area_registry.async_load(hass), floor_registry.async_load(hass),
                         label_registry.async_load(hass), category_registry.async_load(hass))
    hass.config_entries = config_entries.ConfigEntries(hass, {})
    await hass.config_entries.async_initialize()
    await hass.async_start()
    yield hass
    await hass.async_block_till_done()
    for entry in hass.config_entries.async_entries("netmon"):
        if entry.state is config_entries.ConfigEntryState.LOADED:
            await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_stop(force=True)


async def configure(hass, url, email, password):
    r = await hass.config_entries.flow.async_init("netmon", context={"source": "user"})
    return await hass.config_entries.flow.async_configure(
        r["flow_id"], {"url": url, "email": email, "password": password, "verify_ssl": True})


def logins(srv):
    return srv.state.requests


async def test_setup_and_account_isolation(hass, server):
    r = await configure(hass, server.base, "A@Example.test ", PW_A)
    assert r["type"] == "create_entry", r
    await hass.async_block_till_done()
    ids = [s.entity_id for s in hass.states.async_all()]
    assert any("router" in i for i in ids) and any("nas" in i for i in ids)
    # le sonde e i dispositivi di un altro account non arrivano mai
    assert not any("segreto" in i or "altrui" in i for i in ids)
    devs = [d.name for d in dr.async_get(hass).devices.values()]
    assert "Segreto" not in devs
    nas = next(s for s in hass.states.async_all() if "nas" in s.entity_id and s.domain == "binary_sensor")
    assert nas.state == "off"
    # nessuna credenziale negli attributi delle entità
    blob = repr([dict(s.attributes) for s in hass.states.async_all()])
    assert PW_A not in blob and "sonda_" not in blob


async def test_two_accounts_two_entries_separate(hass, server):
    assert (await configure(hass, server.base, "a@example.test", PW_A))["type"] == "create_entry"
    assert (await configure(hass, server.base, "b@example.test", PW_B))["type"] == "create_entry"
    await hass.async_block_till_done()
    ea, eb = hass.config_entries.async_entries("netmon")
    assert set(ea.runtime_data.data["probes"]) == {"p_casa"}
    assert set(eb.runtime_data.data["probes"]) == {"p_altrui"}
    # stesso account due volte: rifiutato
    assert (await configure(hass, server.base, "a@example.test", PW_A))["reason"] == "already_configured"


async def test_wrong_password_not_retried(hass, server):
    r = await configure(hass, server.base, "a@example.test", "sbagliata-sbagliata")
    assert r["errors"] == {"base": "invalid_auth"}
    assert not hass.config_entries.async_entries("netmon")
    # dopo un rifiuto il client non riprova da solo: ogni tentativo sbagliato conta per il blocco
    # del server, che fermerebbe anche il browser dalla stessa rete
    from custom_components.netmon.api import NetMonAuthError, NetMonClient
    async with aiohttp.ClientSession() as session:
        client = NetMonClient(session, server.base, "a@example.test", "sbagliata-sbagliata")
        before = server.state.requests
        for _ in range(5):
            with pytest.raises(NetMonAuthError):
                await client.status()
        assert server.state.requests - before == 1


async def test_session_expired_relogin_and_password_changed_reauth(hass, server):
    assert (await configure(hass, server.base, "a@example.test", PW_A))["type"] == "create_entry"
    await hass.async_block_till_done()
    entry = hass.config_entries.async_entries("netmon")[0]
    coord = entry.runtime_data
    server.state.sessions.clear()                            # sessione scaduta sul server
    await coord.async_refresh()
    assert coord.last_update_success
    server.state.accounts["a@example.test"]["password"] = "Cambiata-123456"
    server.state.sessions.clear()
    before = server.state.requests
    for _ in range(4):
        await coord.async_refresh()
    await hass.async_block_till_done()
    # un solo tentativo di accesso con la password vecchia, poi la richiesta di nuova autenticazione
    assert server.state.requests - before <= 3
    flows = [f for f in hass.config_entries.flow.async_progress() if f["context"]["source"] == "reauth"]
    assert flows
    f = await hass.config_entries.flow.async_configure(flows[0]["flow_id"], {"password": "Cambiata-123456"})
    assert f["reason"] == "reauth_successful"


async def test_malformed_status_does_not_break(hass, server):
    assert (await configure(hass, server.base, "a@example.test", PW_A))["type"] == "create_entry"
    await hass.async_block_till_done()
    coord = hass.config_entries.async_entries("netmon")[0].runtime_data
    server.state.status_override = {"probes": [
        None, "testo", {"label": "senza nome"}, {"name": "p_casa", "devices": [None, {"host": "x"},
                                                                               {"name": "Router", "state": "ok"}]},
        {"name": "p_senza_stato"}], "server": "non un dizionario"}
    await coord.async_refresh()
    await hass.async_block_till_done()
    assert coord.last_update_success
    assert set(coord.data["probes"]) == {"p_casa", "p_senza_stato"}
    online = [s for s in hass.states.async_all() if "p_senza_stato" in s.entity_id]
    assert online                                          # entità creata, nessun KeyError


async def test_removed_device_can_be_deleted(hass, server):
    from custom_components.netmon import async_remove_config_entry_device
    assert (await configure(hass, server.base, "a@example.test", PW_A))["type"] == "create_entry"
    await hass.async_block_till_done()
    entry = hass.config_entries.async_entries("netmon")[0]
    reg = dr.async_get(hass)
    nas = next(d for d in reg.devices.values() if d.name == "NAS")
    router = next(d for d in reg.devices.values() if d.name == "Router")
    assert await async_remove_config_entry_device(hass, entry, nas) is False     # ancora sul server
    report(server, "p_casa", {"Router": {"ok": True, "host": "192.168.1.1", "rtt": 1.5}})
    await entry.runtime_data.async_refresh()
    assert await async_remove_config_entry_device(hass, entry, nas) is True      # tolto da NetMon
    assert await async_remove_config_entry_device(hass, entry, router) is False


async def test_move_to_http_refused(hass, monkeypatch):
    """Da https non si segue un indirizzo http: email e password viaggerebbero in chiaro."""
    from custom_components.netmon import config_flow
    from custom_components.netmon.api import NetMonMoved
    tried = []

    class Client:
        def __init__(self, session, url, email, password):
            tried.append(url)

        async def status(self):
            raise NetMonMoved("http://vm2.example.test")

    monkeypatch.setattr(config_flow, "NetMonClient", Client)
    r = await configure(hass, "vm1.example.test", "a@example.test", PW_A)
    assert r["errors"] == {"base": "cannot_connect"}
    assert tried == ["https://vm1.example.test"]


async def test_new_entities_created_once(hass, server):
    """Le entità nuove nascono una volta sola, anche dopo molti aggiornamenti."""
    assert (await configure(hass, server.base, "a@example.test", PW_A))["type"] == "create_entry"
    await hass.async_block_till_done()
    coord = hass.config_entries.async_entries("netmon")[0].runtime_data
    n = len(er.async_get(hass).entities)
    for _ in range(5):
        await coord.async_refresh()
    report(server, "p_casa", {"Router": {"ok": True, "host": "192.168.1.1", "rtt": 1.5},
                              "NAS": {"ok": True, "host": "192.168.1.10", "rtt": 2},
                              "Stampante": {"ok": True, "host": "192.168.1.30", "rtt": 4}},
           system={"version": "1.1"})
    await coord.async_refresh()
    await hass.async_block_till_done()
    assert len(er.async_get(hass).entities) == n + 2          # online e tempo di risposta della stampante


async def test_password_only_in_config_entry(hass, server, caplog):
    """La password resta solo nella voce di configurazione di Home Assistant (core.config_entries,
    dove Home Assistant tiene le credenziali di tutte le integrazioni): non nei registri, non negli
    altri file di .storage, non negli attributi."""
    caplog.set_level("DEBUG")
    assert (await configure(hass, server.base, "a@example.test", PW_A))["type"] == "create_entry"
    await hass.async_block_till_done()
    coord = hass.config_entries.async_entries("netmon")[0].runtime_data
    server.state.sessions.clear()
    await coord.async_refresh()
    await hass.async_stop(force=True)
    assert PW_A not in caplog.text
    storage = Path(hass.config.path(".storage"))
    holders = [p.name for p in storage.iterdir() if p.is_file() and PW_A in p.read_text(errors="replace")]
    assert holders == ["core.config_entries"]


async def test_real_server_isolation(hass):
    """Con il server NetMon vero (facoltativa, NETMON_REPO e NETMON_PYTHON): ogni account vede solo
    le sue sonde anche dall'integrazione."""
    from realserver import PASSWORD, RealServer, call
    with RealServer() as real:
        _, tok_a = real.account("a@example.test")
        _, tok_b = real.account("b@example.test")
        key_a, key_b = next(iter(tok_a)), next(iter(tok_b))
        for key, tok, dev in ((key_a, tok_a[key_a], "TV-di-A"), (key_b, tok_b[key_b], "Segreto-di-B")):
            body = {"probe": key, "interval": 60, "devices": {dev: {"ok": True, "host": "192.168.1.5", "rtt": 2}}}
            status, data, _ = call(real.base, "POST", "/api/report", body, token=tok)
            assert status == 200, data
        r = await configure(hass, real.base, "a@example.test", PASSWORD)
        assert r["type"] == "create_entry", r
        await hass.async_block_till_done()
        coord = hass.config_entries.async_entries("netmon")[0].runtime_data
        assert set(coord.data["probes"]) == {key_a}
        names = repr([s.entity_id for s in hass.states.async_all()]).lower()
        assert "tv_di_a" in names and "segreto" not in names
        for entry in hass.config_entries.async_entries("netmon"):
            await hass.config_entries.async_unload(entry.entry_id)


@pytest.mark.stress
async def test_stress_many_updates_with_failures(hass, server):
    """Molti aggiornamenti di fila (STRESS_MINUTES) con sessioni scadute, server che risponde male e
    dispositivi che cambiano: nessuna eccezione non gestita, memoria che non cresce, entità create
    una volta sola."""
    import time
    import tracemalloc
    minutes = float(os.getenv("STRESS_MINUTES", "2"))
    assert (await configure(hass, server.base, "a@example.test", PW_A))["type"] == "create_entry"
    await hass.async_block_till_done()
    coord = hass.config_entries.async_entries("netmon")[0].runtime_data
    tracemalloc.start()
    for _ in range(50):
        await coord.async_refresh()
    base = tracemalloc.get_traced_memory()[0]
    n, fails = 0, 0
    end = time.monotonic() + minutes * 60
    while time.monotonic() < end:
        n += 1
        if n % 13 == 0:
            server.state.sessions.clear()                     # sessione scaduta: nuovo accesso
        if n % 17 == 0:
            server.state.status_override = {"probes": "rotto"}  # risposta malformata
        elif n % 17 == 1:
            server.state.status_override = None
        devices = {f"D{i}": {"ok": (i + n) % 5 != 0, "host": f"192.168.1.{i}", "rtt": i} for i in range(40)}
        report(server, "p_casa", devices, system={"version": "1.1"})
        await coord.async_refresh()
        await hass.async_block_till_done()
        fails += not coord.last_update_success
    grown = tracemalloc.get_traced_memory()[0] - base
    tracemalloc.stop()
    entities = len(er.async_get(hass).entities)
    print(f"\naggiornamenti {n}, falliti {fails}, memoria +{grown / 1024:.0f} kB, entità {entities}")
    assert n > 200
    assert grown < 5 * 1024 * 1024
    assert entities <= 2 * 42 + 10
