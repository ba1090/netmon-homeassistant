"""Misure: tempo di risposta dei dispositivi, stato della sonda, FRITZ!Box e ultimo speedtest."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (SensorDeviceClass, SensorEntity, SensorEntityDescription,
                                             SensorStateClass)
from homeassistant.const import (EntityCategory, UnitOfDataRate, UnitOfTemperature, UnitOfTime)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import NetMonConfigEntry
from .coordinator import NetMonCoordinator
from .entity import NetMonEntity, add_dynamic


@dataclass(frozen=True, kw_only=True)
class ProbeSensorDescription(SensorEntityDescription):
    """`section` è la parte della sonda da cui viene il valore (system, fritz, speedtest), `field`
    il campo: il sensore nasce quando il campo compare."""
    section: str
    field: str


PROBE_SENSORS: tuple[ProbeSensorDescription, ...] = (
    ProbeSensorDescription(key="temperature", translation_key="temperature", section="system", field="temp_c",
                           device_class=SensorDeviceClass.TEMPERATURE, state_class=SensorStateClass.MEASUREMENT,
                           native_unit_of_measurement=UnitOfTemperature.CELSIUS,
                           entity_category=EntityCategory.DIAGNOSTIC),
    ProbeSensorDescription(key="load1", translation_key="load1", section="system", field="load1",
                           state_class=SensorStateClass.MEASUREMENT, entity_category=EntityCategory.DIAGNOSTIC),
    ProbeSensorDescription(key="uptime", translation_key="uptime", section="system", field="uptime",
                           device_class=SensorDeviceClass.DURATION, native_unit_of_measurement=UnitOfTime.SECONDS,
                           suggested_unit_of_measurement=UnitOfTime.DAYS, suggested_display_precision=1,
                           entity_category=EntityCategory.DIAGNOSTIC, entity_registry_enabled_default=False),
    ProbeSensorDescription(key="version", translation_key="version", section="system", field="version",
                           entity_category=EntityCategory.DIAGNOSTIC),
    ProbeSensorDescription(key="fritz_external_ip", translation_key="fritz_external_ip", section="fritz",
                           field="external_ip", entity_category=EntityCategory.DIAGNOSTIC),
    ProbeSensorDescription(key="fritz_rate_down", translation_key="fritz_rate_down", section="fritz",
                           field="rate_down", device_class=SensorDeviceClass.DATA_RATE,
                           state_class=SensorStateClass.MEASUREMENT,
                           native_unit_of_measurement=UnitOfDataRate.BITS_PER_SECOND,
                           suggested_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
                           suggested_display_precision=1),
    ProbeSensorDescription(key="fritz_rate_up", translation_key="fritz_rate_up", section="fritz",
                           field="rate_up", device_class=SensorDeviceClass.DATA_RATE,
                           state_class=SensorStateClass.MEASUREMENT,
                           native_unit_of_measurement=UnitOfDataRate.BITS_PER_SECOND,
                           suggested_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
                           suggested_display_precision=1),
    ProbeSensorDescription(key="fritz_hosts_active", translation_key="fritz_hosts_active", section="fritz",
                           field="hosts_active", state_class=SensorStateClass.MEASUREMENT),
    ProbeSensorDescription(key="speedtest_down", translation_key="speedtest_down", section="speedtest",
                           field="down", device_class=SensorDeviceClass.DATA_RATE,
                           native_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
                           suggested_display_precision=1),
    ProbeSensorDescription(key="speedtest_up", translation_key="speedtest_up", section="speedtest",
                           field="up", device_class=SensorDeviceClass.DATA_RATE,
                           native_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
                           suggested_display_precision=1),
    ProbeSensorDescription(key="speedtest_ping", translation_key="speedtest_ping", section="speedtest",
                           field="ping", device_class=SensorDeviceClass.DURATION,
                           native_unit_of_measurement=UnitOfTime.MILLISECONDS, suggested_display_precision=0),
)


async def async_setup_entry(hass: HomeAssistant, entry: NetMonConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    coordinator = entry.runtime_data

    def build(data: dict[str, Any]):
        for key, p in data.get("probes", {}).items():
            for desc in PROBE_SENSORS:
                if (p.get(desc.section) or {}).get(desc.field) is not None:
                    yield ProbeSensor(coordinator, key, desc)
            for name in p["by_name"]:
                yield DeviceRtt(coordinator, key, "rtt", name)

    entry.async_on_unload(add_dynamic(coordinator, async_add_entities, build))


class ProbeSensor(NetMonEntity, SensorEntity):
    entity_description: ProbeSensorDescription

    def __init__(self, coordinator: NetMonCoordinator, probe: str, desc: ProbeSensorDescription) -> None:
        super().__init__(coordinator, probe, desc.key)
        self.entity_description = desc

    @property
    def native_value(self) -> Any:
        desc = self.entity_description
        return ((self.probe or {}).get(desc.section) or {}).get(desc.field)


class DeviceRtt(NetMonEntity, SensorEntity):
    """Tempo di risposta all'ultimo ping riuscito; vuoto se il dispositivo non risponde."""
    _attr_translation_key = "rtt"
    _attr_device_class = SensorDeviceClass.DURATION
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = UnitOfTime.MILLISECONDS
    _attr_suggested_display_precision = 1

    @property
    def native_value(self) -> float | None:
        return (self.device or {}).get("rtt")
