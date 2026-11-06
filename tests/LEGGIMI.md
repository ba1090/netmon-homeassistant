# Prove dell'add-on e dell'integrazione

Le prove avviano l'add-on come nel container di Home Assistant: `addon.py` e i programmi della
sonda in una cartella, i dati in una `/data` temporanea, un server NetMon finto (`fakeserver.py`)
che riceve i report e risponde alle API dell'integrazione con più account separati. Non serve
Docker e non serve un Home Assistant installato: per l'integrazione basta il pacchetto Python
`homeassistant`.

| File | Cosa prova |
|---|---|
| `test_addon_options.py` | opzioni → `config.yaml` e `web.env`: indirizzi accettati (`http://` solo nella rete di casa), nessuna iniezione di righe o chiavi YAML, file leggibili solo dall'add-on, `config.yaml` danneggiato recuperato |
| `test_addon_runtime.py` | add-on in funzione: report al server, «gestita da Home Assistant», pagina locale avviata alla visita e chiusa da inattiva, password che resta dopo una ripartenza della pagina, accesso solo con password, Host della rete di casa e stessa origine (DNS rebinding e CSRF), segreti nascosti, permessi dei file in `/data`, arresto pulito, porta occupata, sonda che si blocca |
| `test_real_server.py` | (facoltativa) add-on contro il server NetMon vero: la sonda scrive solo nel suo account, un altro account non la vede e non la comanda, i comandi che nell'add-on non hanno senso sono rifiutati |
| `integration/test_integration.py` | integrazione dentro Home Assistant: configurazione, account separati, password sbagliata senza tentativi ripetuti, sessione scaduta e nuova autenticazione, dati malformati, eliminazione dei dispositivi tolti, niente passaggio da https a http, password solo nella configurazione di Home Assistant |
| `stress/test_stress_addon.py` | (lente, `-m stress`) funzionamento continuo con memoria e descrittori stabili, pagina locale sotto carico da 8 client, blocco dei tentativi di password, pagina aperta e chiusa molte volte, server che cade e torna (misure messe da parte e rimandate), sonda che si blocca di continuo |

## Come si lanciano

Add-on (servono `pytest` e `pyyaml`; `fritzconnection` è facoltativa):

```sh
python3 -m venv /tmp/venv-addon && /tmp/venv-addon/bin/pip install pytest pyyaml
/tmp/venv-addon/bin/python -m pytest tests --ignore=tests/integration
```

Integrazione (servono `homeassistant`, `pytest` e `pytest-asyncio`, con il Python richiesto da
Home Assistant):

```sh
python3 -m venv /tmp/venv-ha && /tmp/venv-ha/bin/pip install homeassistant pytest pytest-asyncio
/tmp/venv-ha/bin/python -m pytest tests/integration
```

Stress e durata (escluse di base): `-m stress`, durata di ogni prova in minuti con
`STRESS_MINUTES` (2 se non indicata), per esempio `STRESS_MINUTES=30 ... -m stress tests/stress`.

Con il server NetMon vero: `NETMON_REPO` è una copia di https://github.com/ba1090/NetMon e
`NETMON_PYTHON` un Python con le dipendenze di `server/requirements.txt`. Senza queste due
variabili le prove relative vengono saltate.

Le prove che misurano processi e permessi leggono `/proc`: girano su Linux.
