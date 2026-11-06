"""Base delle entità: una sonda è un dispositivo di Home Assistant, ogni dispositivo che la sonda
controlla è un dispositivo «collegato tramite» la sonda."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import NetMonCoordinator


def device_id(entry: ConfigEntry, probe: str, device: str | None = None) -> str:
    """Identificativo del dispositivo di Home Assistant: la sonda, o un dispositivo che controlla."""
    base = f"{entry.unique_id or entry.entry_id}|{probe}"
    return base if device is None else f"{base}|{device}"


def unique_id(entry: ConfigEntry, probe: str, key: str, device: str | None = None) -> str:
    return f"{device_id(entry, probe, device)}|{key}"


class NetMonEntity(CoordinatorEntity[NetMonCoordinator]):
    _attr_has_entity_name = True

    def __init__(self, coordinator: NetMonCoordinator, probe: str, key: str, device: str | None = None) -> None:
        super().__init__(coordinator)
        self.probe_key = probe
        self.device_name = device
        entry = coordinator.config_entry
        probe_id = device_id(entry, probe)
        self._attr_unique_id = unique_id(entry, probe, key, device)
        p = self.probe or {}
        if device is None:
            system = p.get("system") or {}
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, probe_id)}, name=p.get("label") or probe, manufacturer="NetMon",
                model=system.get("model") or "Sonda", sw_version=system.get("version"),
                configuration_url=coordinator.client.url)
        else:
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, device_id(entry, probe, device))}, name=device, manufacturer="NetMon",
                model="Dispositivo controllato", via_device=(DOMAIN, probe_id))

    @property
    def probe(self) -> dict[str, Any] | None:
        return (self.coordinator.data or {}).get("probes", {}).get(self.probe_key)

    @property
    def device(self) -> dict[str, Any] | None:
        return (self.probe or {}).get("by_name", {}).get(self.device_name)

    @property
    def available(self) -> bool:
        if not super().available or self.probe is None:
            return False
        return self.device_name is None or self.device is not None


def add_dynamic(coordinator: NetMonCoordinator, async_add_entities: AddEntitiesCallback,
                build: Callable[[dict[str, Any]], Iterable[tuple[str, Callable[[], Entity]]]]) -> Callable[[], None]:
    """Aggiunge le entità che lo stato descrive, anche quelle che compaiono dopo (sonde o dispositivi
    nuovi). `build` dà coppie (unique_id, costruttore): l'entità si costruisce solo per gli
    unique_id mai visti, così a ogni aggiornamento non si ricreano tutte. Restituisce la funzione
    per smettere di ascoltare."""
    known: set[str] = set()

    @callback
    def update() -> None:
        new = []
        for uid, make in build(coordinator.data or {}):
            if uid not in known:
                known.add(uid)
                new.append(make())
        if new:
            async_add_entities(new)

    update()
    return coordinator.async_add_listener(update)
