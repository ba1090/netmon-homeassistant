"""Opzioni dell'add-on → config.yaml e web.env: indirizzi accettati, valori scritti senza
iniezioni, file leggibili solo dall'add-on, config.yaml danneggiato recuperato."""
import json
import os
import stat

import pytest
import yaml


def opts(**kw):
    return {"server": "vm1.netmonhome.net", "token": "sonda_abc", "name": "Casa", **kw}


@pytest.mark.parametrize("given,url", [
    ("vm1.netmonhome.net", "https://vm1.netmonhome.net/api/report"),
    ("https://vm1.netmonhome.net/", "https://vm1.netmonhome.net/api/report"),
    ("https://vm1.netmonhome.net/api/report", "https://vm1.netmonhome.net/api/report"),
    ("  vm1.netmonhome.net:8443 ", "https://vm1.netmonhome.net:8443/api/report"),
    ("http://192.168.1.20:8000", "http://192.168.1.20:8000/api/report"),
    ("", ""),
])
def test_report_url(addon_module, given, url):
    assert addon_module.report_url(given) == url


@pytest.mark.parametrize("url,ok", [
    ("https://vm1.netmonhome.net/api/report", True),
    ("http://192.168.1.20/api/report", True),
    ("http://nas.local/api/report", True),
    ("http://nas.fritz.box/api/report", True),
    ("http://vm1.netmonhome.net/api/report", False),       # token in chiaro su Internet
    ("http://8.8.8.8/api/report", False),
    ("https://user:pw@vm1.netmonhome.net/api/report", False),
    ("ftp://vm1.netmonhome.net/api/report", False),
    ("https:///api/report", False),
])
def test_server_url_ok(addon_module, url, ok):
    assert addon_module.server_url_ok(url) is ok


def test_http_internet_server_refused(addon_module):
    assert addon_module.prepare_config(opts(server="http://vm1.netmonhome.net")) is False
    assert not os.path.exists(addon_module.CONFIG)


def test_missing_token_waits(addon_module):
    assert addon_module.prepare_config(opts(token="")) is False


def test_config_written_private_and_parsable(addon_module):
    assert addon_module.prepare_config(opts()) is True
    mode = stat.S_IMODE(os.stat(addon_module.CONFIG).st_mode)
    assert mode == 0o600
    cfg = yaml.safe_load(open(addon_module.CONFIG))
    assert cfg["server_url"] == "https://vm1.netmonhome.net/api/report"
    assert cfg["token"] == "sonda_abc" and cfg["probe_name"] == "Casa"
    assert cfg["devices"]                      # almeno il router: la sonda non parte senza


def test_yaml_injection_in_options_stays_a_value(addon_module):
    """Nome e token con a capo, due punti e tag YAML restano testo: nessuna chiave in più."""
    evil = "x\nserver_url: https://evil.example/api/report\n!!python/object:os.system"
    assert addon_module.prepare_config(opts(name=evil, token=evil)) is True
    cfg = yaml.safe_load(open(addon_module.CONFIG))
    assert cfg["server_url"] == "https://vm1.netmonhome.net/api/report"
    assert cfg["probe_name"] == evil and cfg["token"] == evil


def test_options_win_only_when_changed(addon_module):
    """Un nome cambiato dalla pagina di stato (scritto dalla sonda) resta finché non cambia l'opzione."""
    addon_module.prepare_config(opts())
    cfg = yaml.safe_load(open(addon_module.CONFIG))
    cfg["probe_name"] = "Rinominata dal server"
    open(addon_module.CONFIG, "w").write(yaml.safe_dump(cfg))
    addon_module.prepare_config(opts())
    assert yaml.safe_load(open(addon_module.CONFIG))["probe_name"] == "Rinominata dal server"
    addon_module.prepare_config(opts(name="Nuovo nome"))
    assert yaml.safe_load(open(addon_module.CONFIG))["probe_name"] == "Nuovo nome"


@pytest.mark.parametrize("content", ["devices: [unclosed\n", "- solo\n- una lista\n", "\x00\x01binario"])
def test_damaged_config_recovered(addon_module, content):
    with open(addon_module.CONFIG, "w") as f:
        f.write(content)
    assert addon_module.prepare_config(opts()) is True
    assert yaml.safe_load(open(addon_module.CONFIG))["token"] == "sonda_abc"
    aside = [n for n in os.listdir(os.path.dirname(addon_module.CONFIG)) if ".danneggiato-" in n]
    assert len(aside) == 1


def test_generated_password_private(addon_module):
    env = addon_module.prepare_web_password({})
    pw = env["WEB_PASSWORD"]
    assert len(pw) >= 16
    assert stat.S_IMODE(os.stat(addon_module.WEB_ENV).st_mode) == 0o600
    # la seconda volta resta la stessa (non se ne crea una nuova a ogni avvio)
    assert addon_module.prepare_web_password({})["WEB_PASSWORD"] == pw


@pytest.mark.parametrize("bad", ["corta", "con spazio dentro!", "a\nWEB_ALLOWED_HOSTS=evil.example",
                                 "virgo'lettaxxxxxxx", "dollaro$HOMExxxxx", "back`tick`xxxxxxxx"])
def test_bad_option_password_refused(addon_module, bad):
    first = addon_module.prepare_web_password({})["WEB_PASSWORD"]
    env = addon_module.prepare_web_password({"web_password": bad})
    assert env["WEB_PASSWORD"] == first
    text = open(addon_module.WEB_ENV).read()
    assert "evil.example" not in text and len(text.splitlines()) == 1


def test_option_password_wins(addon_module):
    addon_module.prepare_web_password({})
    assert addon_module.prepare_web_password({"web_password": "Una-Password-Lunga-1"})["WEB_PASSWORD"] == \
        "Una-Password-Lunga-1"


def test_options_file_never_rewritten(addon_module):
    """options.json è di Home Assistant: l'add-on lo legge e basta."""
    with open(addon_module.OPTIONS, "w") as f:
        json.dump(opts(), f)
    before = os.stat(addon_module.OPTIONS).st_mtime_ns
    addon_module.prepare_config(opts())
    addon_module.prepare_web_password(opts())
    assert os.stat(addon_module.OPTIONS).st_mtime_ns == before
