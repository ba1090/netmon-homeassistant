"""Configurazione dall'interfaccia: indirizzo del server, email e password dell'account NetMon."""
from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import aiohttp
import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, CONF_URL, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.aiohttp_client import async_create_clientsession

from .api import NetMonAuthError, NetMonClient, NetMonError, NetMonMoved, NetMonThrottled
from .const import CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, DOMAIN, MAX_SCAN_INTERVAL, MIN_SCAN_INTERVAL

_LOGGER = logging.getLogger(__name__)


def normalize_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


async def validate(hass: HomeAssistant, data: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Prova l'accesso e una lettura dello stato. Restituisce l'indirizzo da usare (con il gateway
    può essere quello della VM dove vive l'account) e lo stato letto."""
    # sessione staccata alla fine (non chiusa: il connettore è quello condiviso di Home Assistant)
    session = async_create_clientsession(hass, verify_ssl=data.get(CONF_VERIFY_SSL, True), auto_cleanup=False,
                                         cookie_jar=aiohttp.DummyCookieJar())
    url = normalize_url(data[CONF_URL])
    try:
        for _ in range(2):
            client = NetMonClient(session, url, data[CONF_EMAIL], data[CONF_PASSWORD])
            try:
                return url, await client.status()
            except NetMonMoved as moved:
                _LOGGER.info("Account su un altro server NetMon: %s", moved.url)
                url = normalize_url(moved.url)
        raise NetMonError("troppi spostamenti")
    finally:
        session.detach()


def errors_of(exc: Exception) -> str:
    if isinstance(exc, NetMonAuthError):
        return "invalid_auth"
    if isinstance(exc, NetMonThrottled):
        return "too_many_attempts"
    if isinstance(exc, NetMonError):
        return "cannot_connect"
    _LOGGER.exception("Errore inatteso nella configurazione di NetMon")
    return "unknown"


class NetMonConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        placeholders = {"detail": ""}
        if user_input is not None:
            user_input[CONF_EMAIL] = user_input[CONF_EMAIL].strip().lower()
            try:
                url, _ = await validate(self.hass, user_input)
            except Exception as exc:  # noqa: BLE001 — ogni errore diventa un messaggio nel modulo
                errors["base"] = errors_of(exc)
                placeholders["detail"] = str(exc)
            else:
                await self.async_set_unique_id(f"{url.lower()}|{user_input[CONF_EMAIL]}")
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title=f"NetMon ({user_input[CONF_EMAIL]})",
                                               data={**user_input, CONF_URL: url})
        schema = self.add_suggested_values_to_schema(vol.Schema({
            vol.Required(CONF_URL): str,
            vol.Required(CONF_EMAIL): str,
            vol.Required(CONF_PASSWORD): str,
            vol.Optional(CONF_VERIFY_SSL, default=True): bool,
        }), user_input or {})
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors,
                                    description_placeholders=placeholders)

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        placeholders = {"email": entry.data[CONF_EMAIL], "detail": ""}
        if user_input is not None:
            data = {**entry.data, CONF_PASSWORD: user_input[CONF_PASSWORD]}
            try:
                url, _ = await validate(self.hass, data)
            except Exception as exc:  # noqa: BLE001
                errors["base"] = errors_of(exc)
                placeholders["detail"] = str(exc)
            else:
                return self.async_update_reload_and_abort(entry, data={**data, CONF_URL: url})
        return self.async_show_form(step_id="reauth_confirm",
                                    data_schema=vol.Schema({vol.Required(CONF_PASSWORD): str}),
                                    errors=errors, description_placeholders=placeholders)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        return NetMonOptionsFlow()


class NetMonOptionsFlow(OptionsFlow):
    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(data=user_input)
        current = self.config_entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
        return self.async_show_form(step_id="init", data_schema=vol.Schema({
            vol.Required(CONF_SCAN_INTERVAL, default=current):
                vol.All(vol.Coerce(int), vol.Range(min=MIN_SCAN_INTERVAL, max=MAX_SCAN_INTERVAL)),
        }))
