"""NetMon: sonde e dispositivi del monitoraggio di casa come entità di Home Assistant."""
from __future__ import annotations

import aiohttp

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, CONF_URL, CONF_VERIFY_SSL, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.device_registry import DeviceEntry

from .api import NetMonClient
from .const import DOMAIN
from .entity import device_id
from .coordinator import NetMonCoordinator

PLATFORMS = [Platform.BINARY_SENSOR, Platform.SENSOR]

type NetMonConfigEntry = ConfigEntry[NetMonCoordinator]


async def async_setup_entry(hass: HomeAssistant, entry: NetMonConfigEntry) -> bool:
    # sessione propria senza cookie jar: il cookie di NetMon lo gestisce il client. Home Assistant la
    # stacca da sola quando l'integrazione si scarica.
    session = async_create_clientsession(hass, verify_ssl=entry.data.get(CONF_VERIFY_SSL, True),
                                         cookie_jar=aiohttp.DummyCookieJar())
    client = NetMonClient(session, entry.data[CONF_URL], entry.data[CONF_EMAIL], entry.data[CONF_PASSWORD])
    coordinator = NetMonCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_reload))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: NetMonConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def _reload(hass: HomeAssistant, entry: NetMonConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_remove_config_entry_device(hass: HomeAssistant, entry: NetMonConfigEntry,
                                           device: DeviceEntry) -> bool:
    """Pulsante «Elimina» di un dispositivo: permesso solo per sonde e dispositivi che il server non
    riporta più (tolti da NetMon); quelli ancora presenti ricomparirebbero al primo aggiornamento."""
    data = entry.runtime_data.data or {}
    present = set()
    for key, p in data.get("probes", {}).items():
        present.add(device_id(entry, key))
        present.update(device_id(entry, key, name) for name in p.get("by_name", {}))
    return not any(domain == DOMAIN and ident in present for domain, ident in device.identifiers)
