# NetMon sonda

La sonda di netmon come add-on di Home Assistant, al posto del Raspberry Pi: ping ai dispositivi di
casa, FRITZ!Box, speedtest e controlli delle porte, inviati al tuo server NetMon.

Istruzioni nella scheda *Documentazione* dell'add-on ([DOCS.md](DOCS.md)).

Si installa aggiungendo a Home Assistant il repository `https://github.com/ba1090/netmon-homeassistant`.

I programmi in `probe/` sono una copia di quelli della sonda di NetMon (cartella `probe/` del
repository principale), allineata a ogni rilascio da `tools/nuova-versione.py`: non vanno modificati qui.
