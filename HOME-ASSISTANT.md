# NetMon in Home Assistant (HACS)

L'integrazione `custom_components/netmon` porta in Home Assistant lo stato che vedi nella pagina di
NetMon: ogni sonda diventa un dispositivo, e ogni dispositivo che la sonda controlla un dispositivo
«collegato tramite» la sonda. Così puoi usarli in automazioni, dashboard e notifiche di Home Assistant.

Non sostituisce niente: sonda e server restano come sono. L'integrazione legge dal server le stesse
informazioni della pagina di stato, con il tuo account (email e password), ogni 30 secondi.

## Cosa compare

| Entità | Per | Valore |
|---|---|---|
| **In linea** (connettività) | ogni sonda | acceso finché il server riceve i report (anche se in ritardo o in pausa); spento quando la sonda è offline |
| **In linea** (connettività) | ogni dispositivo | acceso se risponde (anche con qualche ping fallito), spento se è giù; *sconosciuto* se la sonda è offline, il dispositivo è in pausa o aspetta il primo ping |
| **Tempo di risposta** (ms) | ogni dispositivo | RTT dell'ultimo ping riuscito |
| **Temperatura**, **Carico (1 min)**, **Versione NetMon**, **Acceso da** | sonda (diagnostica) | dallo stato della sonda; *Acceso da* è disattivata all'inizio |
| **Internet (FRITZ!Box)**, **IP pubblico**, **Download/Upload attuale**, **Dispositivi collegati al FRITZ!Box** | sonda con FRITZ!Box | dal riepilogo del FRITZ!Box principale |
| **Speedtest download/upload/ping** | sonda | ultimo speedtest riuscito |

Gli attributi delle entità *In linea* riportano il testo della pagina (per esempio «giù da 5min»),
l'indirizzo del dispositivo, la priorità e se è in pausa. Sonde e dispositivi aggiunti dopo
compaiono da soli al primo aggiornamento.

## Installazione con HACS

1. In Home Assistant apri **HACS** → menu ⋮ in alto a destra → **Repository personalizzati**.
2. Repository: `https://github.com/ba1090/netmon-homeassistant` · Tipo: **Integrazione** → **Aggiungi**.
3. Cerca **NetMon** in HACS → **Scarica**, poi **riavvia Home Assistant**.
4. **Impostazioni → Dispositivi e servizi → Aggiungi integrazione → NetMon** e inserisci:
   - **Indirizzo del server**: quello della pagina di stato, per esempio `https://monitorvm.duckdns.org`;
   - **Email** e **Password** del tuo account NetMon (non quelli di `/admin`).

Con più VM dietro il gateway puoi mettere l'indirizzo del gateway: se l'account vive su un'altra VM,
l'integrazione passa da sola al suo indirizzo, come fa il browser.

HACS la scarica dal repository pubblico [ba1090/netmon-homeassistant](https://github.com/ba1090/netmon-homeassistant), lo stesso dell'add-on
con la sonda.

## Installazione a mano (senza HACS)

Copia la cartella `custom_components/netmon` del [repository](https://github.com/ba1090/netmon-homeassistant) in `/config/custom_components/netmon`
di Home Assistant (con l'add-on *Samba share* o *File editor*, o via SSH), riavvia Home Assistant
e continua dal passo 4 qui sopra. Per aggiornarla ripeti la copia e riavvia.

## Consigli

- **Account**: usa quello che possiede le sonde. Ogni account vede solo le sue sonde, quindi un
  account a parte per Home Assistant non vedrebbe niente.
- **Password sbagliata o cambiata**: dopo un rifiuto l'integrazione **non riprova** da sola (ogni
  tentativo sbagliato conta per il blocco anti-forzatura del server, che fermerebbe anche il tuo
  browser dalla stessa rete). Home Assistant mostra *Riconfigura*: scrivi la password nuova.
- **Frequenza**: *Impostazioni → Dispositivi e servizi → NetMon → Configura* (da 15 a 600 secondi).
- **Certificato**: togli *Verifica il certificato HTTPS* solo se raggiungi il server con un
  certificato non valido (per esempio per IP nella rete di casa).

## Esempio di automazione

```yaml
automation:
  - alias: "Telecamera giù da 5 minuti"
    triggers:
      - trigger: state
        entity_id: binary_sensor.telecamera_in_linea
        to: "off"
        for: "00:05:00"
    actions:
      - action: notify.notify
        data:
          message: "La telecamera non risponde: {{ state_attr('binary_sensor.telecamera_in_linea', 'dettaglio') }}"
```

I nomi delle entità dipendono dai nomi dei dispositivi in NetMon e dalla lingua di Home Assistant:
controllali in *Impostazioni → Entità*.

## Versione

L'integrazione ha la sua versione (`custom_components/netmon/manifest.json`), separata da quella di
VM e sonde, e non entra nello zip del rilascio. Funziona con Home Assistant 2024.11 o più recente e
con server NetMon 1.1.
