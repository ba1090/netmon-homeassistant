"""Costanti dell'integrazione NetMon per Home Assistant."""
DOMAIN = "netmon"

CONF_SCAN_INTERVAL = "scan_interval"
DEFAULT_SCAN_INTERVAL = 30      # secondi: la pagina di stato si aggiorna più o meno così
MIN_SCAN_INTERVAL = 15
MAX_SCAN_INTERVAL = 600
