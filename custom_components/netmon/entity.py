"""Base delle entità: una sonda è un dispositivo di Home Assistant, ogni dispositivo che la sonda
controlla è un dispositivo «collegato tramite» la sonda."""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from homeassistant.core import callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import NetMonCoordinator


class NetMonEntity(CoordinatorEntity[NetMonCoordinator]):
    _attr_has_entity_name = True

    def __init__(self, coordinator: NetMonCoordinator, probe: str, key: str, device: str | None = None) -> None:
        super().__init__(coordinator)
        self.probe_key = probe
        self.device_name = device
        base = coordinator.config_entry.unique_id or coordinator.config_entry.entry_id
        probe_id = f"{base}|{probe}"
        self._attr_unique_id = f"{probe_id}|{device}|{key}" if device is not None else f"{probe_id}|{key}"
        p = self.probe or {}
        if device is None:
            system = p.get("system") or {}
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, probe_id)}, name=p.get("label") or probe, manufacturer="NetMon",
                model=system.get("model") or "Sonda", sw_version=system.get("version"),
                configuration_url=coordinator.client.url)
        else:
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, f"{probe_id}|{device}")}, name=device, manufacturer="NetMon",
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
                build: Callable[[dict[str, Any]], Iterable[Entity]]) -> Callable[[], None]:
    """Aggiunge le entità che `build` crea dallo stato, anche quelle che compaiono dopo (sonde o
    dispositivi nuovi). Restituisce la funzione per smettere di ascoltare."""
    known: set[str] = set()

    @callback
    def update() -> None:
        new = [e for e in build(coordinator.data or {}) if e.unique_id not in known]
        known.update(e.unique_id for e in new)
        if new:
            async_add_entities(new)

    update()
    return coordinator.async_add_listener(update)
