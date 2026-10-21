# NetMon sonda

La sonda di netmon dentro Home Assistant, al posto del Raspberry Pi. È lo stesso programma della
sonda (`probe.py` e la pagina locale): fa i ping ai dispositivi di casa, legge il FRITZ!Box, fa gli
speedtest e i controlli delle porte chiesti dalla pagina di stato e manda tutto al tuo server
NetMon. Avvisi, storico e pagina di stato restano sul server come sempre.

## Installazione

1. **Il token.** Nella pagina di stato del server: *Impostazioni → Sonde → Aggiungi una sonda*.
   Copia il token `sonda_…` (si vede una volta sola).
Da Home Assistant 2026.2 gli add-on si chiamano **app**: il menu è *Impostazioni → App*; nelle versioni
precedenti è *Impostazioni → Componenti aggiuntivi* (Add-on). Funziona allo stesso modo.

2. **Il repository.** In Home Assistant: *Impostazioni → App → Archivio delle app* → menu ⋮
   in alto a destra → *Repository* → incolla `https://github.com/ba1090/netmon-homeassistant` → *Aggiungi* e chiudi.
   Se **NetMon sonda** non compare subito, ricarica la pagina (oppure ⋮ → *Controlla aggiornamenti*).
3. **L'add-on.** Nell'archivio compare **NetMon sonda** → *Installa* (la prima volta Home Assistant
   costruisce il programma: qualche minuto).
4. **Configurazione** (scheda *Configurazione*):
   - **Server**: il dominio del server, per esempio `vm1.netmonhome.net`;
   - **Token della sonda**: quello del punto 1;
   - **Nome della sonda**: come comparirà nella pagina di stato.

   Salva, poi nella scheda *Informazioni* → *Avvia*. Lascia attivi *Avvia all'accensione* e
   *Watchdog*.
5. **La password della pagina locale.** Al primo avvio la trovi nella scheda *Registro*, nel
   riquadro «Password della pagina locale della sonda»: **salvala**. In alternativa scegline una
   nelle opzioni (*Password della pagina locale*, almeno 12 caratteri).

Dopo meno di un minuto la sonda è in linea nella pagina di stato.

## Dispositivi da controllare

Al primo avvio la sonda controlla solo il router (il gateway della rete di Home Assistant). Gli
altri dispositivi si aggiungono come per il Raspberry:

- dalla **pagina di stato** del server (*Stato rete › Monitor dispositivi*, pulsante **Modifica ▾** accanto al
  nome della sonda), oppure
- dalla **pagina locale** della sonda: pulsante *Apri interfaccia web* dell'add-on, oppure
  `http://IP-DI-HOME-ASSISTANT:8080` (anche `http://homeassistant.local:8080`). Chiede la password
  del punto 5. Da qui si configura anche il FRITZ!Box.

## Differenze rispetto al Raspberry

- **Aggiornamenti.** Arrivano come aggiornamenti dell'add-on in Home Assistant, non dal tasto
  *Aggiorna netmon* della pagina di stato: la sonda segnala da sola al server che le operazioni da
  remoto qui non ci sono.
- **Riavvio e reti Wi-Fi da remoto**: non disponibili (li gestisce Home Assistant). Anche il tasto
  *Disinstalla* della pagina locale non serve: si disinstalla l'add-on.
- **Server e token** si cambiano nelle opzioni dell'add-on. Il **nome** pure; un *Rinomina* fatto
  dalla pagina di stato resta finché non cambi il nome nelle opzioni.
- **Dati**: configurazione, misure non ancora inviate e password stanno nella cartella dell'add-on
  e restano tra un aggiornamento e l'altro (e nei backup di Home Assistant).

## Porta della pagina locale

La pagina locale usa la porta 8080 di Home Assistant. Se è già occupata da un altro add-on,
scegline un'altra nelle opzioni (*Porta della pagina locale*) e riavvia l'add-on; il pulsante
*Apri interfaccia web* punta sempre alla 8080, quindi apri la pagina a mano con la porta nuova.

## Problemi

- **La sonda non compare in linea**: guarda la scheda *Registro*. «Manca l'indirizzo del server o il
  token» vuol dire opzioni vuote; «Invio al server fallito» con *401* vuol dire token sbagliato (creane
  uno nuovo dalla pagina di stato e incollalo nelle opzioni).
- **Password della pagina locale persa**: scrivine una nuova nelle opzioni e riavvia l'add-on.
