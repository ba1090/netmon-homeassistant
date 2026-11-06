"""Stress e durata dell'add-on (lente: pytest -m stress; STRESS_MINUTES per la durata, 2 di base).

- funzionamento continuo: memoria di addon.py e della sonda che non cresce, report regolari;
- pagina locale sotto carico da più client: nessun errore, memoria limitata, chiusura da inattiva;
- pagina aperta e chiusa molte volte (avvio su richiesta): nessun descrittore o processo perso;
- server che cade e torna: le misure arrivano tutte dopo, il buffer resta limitato;
- sonda che si blocca di continuo: l'add-on la riavvia senza consumare risorse.
"""
import os
import signal
import threading
import time

import pytest
import yaml

from conftest import children, rss_kb, wait_until

pytestmark = pytest.mark.stress
MINUTES = float(os.getenv("STRESS_MINUTES", "2"))


def fast_config(addon, server_url, token, interval=10):
    """config.yaml già pronto con un intervallo breve: più report nello stesso tempo."""
    cfg = {"server_url": server_url + "/api/report", "token": token, "probe_name": "Stress",
           "interval": interval, "devices": {"locale": "127.0.0.1", "gateway": "192.0.2.1"}}
    (addon.data / "config.yaml").write_text(yaml.safe_dump(cfg))
    (addon.data / "options-applied.json").write_text(
        '{"server_url": "%s/api/report", "token": "%s", "probe_name": "Stress"}' % (server_url, token))


def fds(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return 0


def test_long_run_memory_and_reports(server, make_addon):
    tok = server.state.add_account("a@example.test", "Password-A-123")["p_test"]
    addon = make_addon({"server": server.base, "token": tok, "name": "Stress"}, start=False)
    fast_config(addon, server.base, tok)
    addon.start()
    assert wait_until(lambda: server.state.last.get("p_test"), timeout=60), addon.logtext()
    time.sleep(15)                                     # assestamento dopo i primi cicli
    probe = addon.probe_pid()
    start_rss = (rss_kb(addon.proc.pid), rss_kb(probe))
    start_reports = len(server.state.reports)
    samples = []
    end = time.monotonic() + MINUTES * 60
    while time.monotonic() < end:
        time.sleep(10)
        samples.append((rss_kb(addon.proc.pid), rss_kb(probe), fds(addon.proc.pid)))
    assert addon.probe_pid() == probe, "la sonda è ripartita durante la prova: " + addon.logtext()[-2000:]
    got = len(server.state.reports) - start_reports
    assert got >= int(MINUTES * 60 / 10) - 2, (got, addon.logtext()[-2000:])
    end_rss = samples[-1][:2]
    print(f"\naddon.py {start_rss[0]}→{end_rss[0]} kB, sonda {start_rss[1]}→{end_rss[1]} kB, report {got}")
    assert end_rss[0] - start_rss[0] < 2048                    # addon.py: meno di 2 MB in più
    assert end_rss[1] - start_rss[1] < 8192                    # sonda: meno di 8 MB in più
    assert len({s[2] for s in samples}) <= 2                   # descrittori di addon.py stabili


def test_local_page_under_load(server, make_addon):
    tok = server.state.add_account("a@example.test", "Password-A-123")["p_test"]
    addon = make_addon({"server": server.base, "token": tok, "name": "Stress"}, idle_minutes=0.05)
    pw = wait_until(addon.password)
    wait_until(lambda: "parte alla prima visita" in addon.logtext())
    errors, counts, lock = [], {"ok": 0}, threading.Lock()
    stop_at = time.monotonic() + MINUTES * 60
    paths = ["/", "/api/config", "/api/system", "/favicon.ico"]

    def worker(i):
        n = i
        while time.monotonic() < stop_at:
            n += 1
            try:
                status, _, _ = addon.request("GET", paths[n % len(paths)], password=pw, timeout=20)
            except OSError as exc:
                with lock:
                    errors.append(repr(exc))
                continue
            with lock:
                if status == 200:
                    counts["ok"] += 1
                else:
                    errors.append(status)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    peak = 0
    for t in threads:
        t.start()
    while any(t.is_alive() for t in threads):
        time.sleep(2)
        pid = addon.page_pid()
        if pid:
            peak = max(peak, rss_kb(pid))
    print(f"\nrichieste riuscite {counts['ok']}, errori {len(errors)}, memoria massima della pagina {peak} kB")
    assert counts["ok"] > 100
    assert not errors, errors[:10]
    assert peak < 80 * 1024
    # finito il carico la pagina si chiude da sola e la memoria torna libera
    assert wait_until(lambda: addon.page_pid() is None, timeout=90)


def test_local_page_brute_force_blocked(server, make_addon):
    """Molte password sbagliate di fila: la pagina blocca i tentativi (429) prima che si possa
    indovinare; durante il blocco non entra nessuno, nemmeno con la password giusta."""
    tok = server.state.add_account("a@example.test", "Password-A-123")["p_test"]
    addon = make_addon({"server": server.base, "token": tok, "name": "Stress"})
    pw = wait_until(addon.password)
    wait_until(lambda: "parte alla prima visita" in addon.logtext())
    statuses = [addon.request("GET", "/api/config", password=f"tentativo-{i:06d}")[0] for i in range(60)]
    assert statuses.count(401) <= 20 and 429 in statuses
    assert addon.request("GET", "/api/config", password=pw)[0] == 429


def test_on_demand_cycles_leak_nothing(server, make_addon):
    tok = server.state.add_account("a@example.test", "Password-A-123")["p_test"]
    addon = make_addon({"server": server.base, "token": tok, "name": "Stress"}, idle_minutes=0.01)
    pw = wait_until(addon.password)
    wait_until(lambda: "parte alla prima visita" in addon.logtext())
    base_fds = fds(addon.proc.pid)
    cycles = 0
    end = time.monotonic() + MINUTES * 60
    while time.monotonic() < end:
        assert addon.request("GET", "/api/system", password=pw)[0] == 200
        pid = addon.page_pid()
        os.kill(pid, signal.SIGTERM)                   # come una chiusura (più veloce dei 30 s di controllo)
        wait_until(lambda: addon.page_pid() is None, timeout=20)
        cycles += 1
        time.sleep(11)                                 # dopo un'uscita con errore riparte entro 10 s
    kids = [c for c in children(addon.proc.pid)]
    print(f"\ncicli {cycles}, descrittori {base_fds}→{fds(addon.proc.pid)}, figli {len(kids)}")
    assert cycles >= 3
    assert fds(addon.proc.pid) <= base_fds + 2
    assert len(kids) <= 2                              # solo la sonda (e al massimo una pagina)


def test_server_outage_buffer_and_resend(make_addon, tmp_path):
    from fakeserver import FakeServer
    srv = FakeServer().__enter__()
    tok = srv.state.add_account("a@example.test", "Password-A-123")["p_test"]
    port = srv.port
    addon = make_addon({"server": srv.base, "token": tok, "name": "Stress"}, start=False)
    fast_config(addon, srv.base, tok, interval=10)
    addon.start()
    assert wait_until(lambda: srv.state.last.get("p_test"), timeout=60)
    outage = max(40, MINUTES * 60 / 2)
    srv.__exit__(None, None, None)                      # il server cade
    t0 = time.time()
    time.sleep(outage)
    buf = addon.data / "buffer.jsonl"
    assert buf.exists() and buf.stat().st_size > 0, addon.logtext()[-3000:]
    # il server torna sulla stessa porta, con lo stesso token
    import fakeserver
    srv2 = fakeserver.FakeServer.__new__(fakeserver.FakeServer)
    srv2.state = srv.state
    srv2.state.reports.clear()
    srv2.httpd = fakeserver.ThreadingHTTPServer(("127.0.0.1", port), fakeserver.make_handler(srv2.state))
    srv2.httpd.daemon_threads = True
    srv2.thread = threading.Thread(target=srv2.httpd.serve_forever, daemon=True)
    srv2.__enter__()
    try:
        def resent():
            ts = [r.get("ts") or r.get("time") for _, r in srv2.state.reports]
            return len(srv2.state.reports) >= int(outage / 10) - 1 and ts
        assert wait_until(resent, timeout=120), (len(srv2.state.reports), addon.logtext()[-2000:])
        assert wait_until(lambda: not buf.exists() or buf.stat().st_size == 0, timeout=60)
        print(f"\ncaduta {time.time() - t0:.0f} s, report rimandati {len(srv2.state.reports)}")
    finally:
        srv2.__exit__(None, None, None)


def test_probe_crash_loop(server, make_addon):
    tok = server.state.add_account("a@example.test", "Password-A-123")["p_test"]
    addon = make_addon({"server": server.base, "token": tok, "name": "Stress"})
    wait_until(addon.probe_pid)
    base_fds, base_rss = fds(addon.proc.pid), rss_kb(addon.proc.pid)
    kills = 0
    end = time.monotonic() + MINUTES * 60
    while time.monotonic() < end:
        pid = wait_until(addon.probe_pid, timeout=20)
        if pid:
            os.kill(pid, signal.SIGKILL)
            kills += 1
        time.sleep(11)
    assert wait_until(addon.probe_pid, timeout=20)
    print(f"\nsonda fermata {kills} volte, descrittori {base_fds}→{fds(addon.proc.pid)}, "
          f"memoria addon.py {base_rss}→{rss_kb(addon.proc.pid)} kB")
    assert kills >= 3
    assert fds(addon.proc.pid) <= base_fds + 2
    assert rss_kb(addon.proc.pid) - base_rss < 2048
    assert addon.logtext().count("sonda: terminata") >= kills
