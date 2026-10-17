"""Sonde e dispositivi in linea, e connessione a Internet del FRITZ!Box."""
from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import NetMonConfigEntry
from .entity import NetMonEntity, add_dynamic


async def async_setup_entry(hass: HomeAssistant, entry: NetMonConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    coordinator = entry.runtime_data

    def build(data: dict[str, Any]):
        for key, p in data.get("probes", {}).items():
            yield ProbeOnline(coordinator, key, "online")
            if "connected" in (p.get("fritz") or {}):
                yield FritzInternet(coordinator, key, "fritz_internet")
            for name in p["by_name"]:
                yield DeviceOnline(coordinator, key, "online", name)

    entry.async_on_unload(add_dynamic(coordinator, async_add_entities, build))


class ProbeOnline(NetMonEntity, BinarySensorEntity):
    """In linea finché il server riceve i report: in ritardo o in pausa vale ancora in linea."""
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_translation_key = "probe_online"

    @property
    def is_on(self) -> bool | None:
        return self.probe["state"] != "bad" if self.probe else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        p = self.probe or {}
        return {"stato": p.get("state"), "dettaglio": p.get("text"), "secondi_dall_ultimo_report": p.get("seen"),
                "in_pausa": p.get("paused")}


class DeviceOnline(NetMonEntity, BinarySensorEntity):
    """Raggiungibile (anche con qualche ping fallito) o giù. Con la sonda offline lo stato non si
    conosce; in pausa o in attesa del primo ping non c'è."""
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_translation_key = "device_online"

    @property
    def is_on(self) -> bool | None:
        d, p = self.device, self.probe
        if not d or not p or p.get("state") == "bad" or d.get("state") == "off":
            return None
        return d.get("state") != "bad"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        d = self.device or {}
        return {"stato": d.get("state"), "dettaglio": d.get("text") or None, "host": d.get("host"),
                "priorita": d.get("prio"), "in_pausa": bool(d.get("paused")),
                "in_attesa": bool(d.get("pending"))}


class FritzInternet(NetMonEntity, BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_translation_key = "fritz_internet"

    @property
    def is_on(self) -> bool | None:
        return ((self.probe or {}).get("fritz") or {}).get("connected")
