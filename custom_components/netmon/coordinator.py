"""Aggiornamento periodico dello stato dal server NetMon."""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import NetMonAuthError, NetMonClient, NetMonError
from .const import CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, DOMAIN

_LOGGER = logging.getLogger(__name__)


class NetMonCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """`data` è {"probes": {chiave sonda: sonda}, "server": {...}}; ogni sonda ha anche
    "by_name", i suoi dispositivi per nome."""

    config_entry: ConfigEntry

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, client: NetMonClient) -> None:
        super().__init__(
            hass, _LOGGER, config_entry=entry, name=DOMAIN,
            update_interval=timedelta(seconds=entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)))
        self.client = client

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            raw = await self.client.status()
        except NetMonAuthError as exc:
            raise ConfigEntryAuthFailed(str(exc)) from exc
        except NetMonError as exc:
            raise UpdateFailed(str(exc)) from exc
        probes = {}
        for p in raw.get("probes") or []:
            p["by_name"] = {d["name"]: d for d in p.get("devices") or [] if d.get("name")}
            probes[p["name"]] = p
        return {"probes": probes, "server": raw.get("server") or {}}
