"""Client delle API di un server NetMon: le stesse che usa la pagina di stato.

L'accesso è quello di un utente (email e password, come nel browser): /api/auth/login dà il cookie
di sessione e /api/status lo stato di sonde e dispositivi. Il cookie si tiene qui e si manda a mano,
così vale anche con un server raggiunto per IP o in http (dove il cookie «Secure» non verrebbe
rimandato da un cookie jar).
"""
from __future__ import annotations

import asyncio
from typing import Any

import aiohttp

COOKIE = "netmon_session"
TIMEOUT = aiohttp.ClientTimeout(total=20)


class NetMonError(Exception):
    """Server non raggiungibile o risposta inattesa."""


class NetMonAuthError(NetMonError):
    """Email o password non accettate, account bloccato o scaduto."""


class NetMonThrottled(NetMonError):
    """Il server rifiuta gli accessi per un po' (troppi tentativi sbagliati)."""


class NetMonMoved(NetMonError):
    """L'account vive su un'altra VM (server con il gateway): l'indirizzo giusto è in `url`."""

    def __init__(self, url: str) -> None:
        super().__init__(url)
        self.url = url


def detail_of(data: Any) -> str:
    return str(data.get("detail") or "") if isinstance(data, dict) else ""


class NetMonClient:
    def __init__(self, session: aiohttp.ClientSession, url: str, email: str, password: str) -> None:
        self._session = session
        self.url = url.rstrip("/")
        self._email = email
        self._password = password
        self._cookie: str | None = None
        # Dopo un rifiuto non si riprova: ogni tentativo sbagliato conta per il blocco del server,
        # che fermerebbe anche il browser dalla stessa rete. Si riparte con la password nuova.
        self._refused: NetMonAuthError | None = None
        self._login_lock = asyncio.Lock()

    async def _request(self, method: str, path: str, **kwargs: Any) -> tuple[int, Any, aiohttp.ClientResponse]:
        try:
            async with self._session.request(method, self.url + path, timeout=TIMEOUT,
                                             allow_redirects=False, **kwargs) as resp:
                try:
                    data = await resp.json(content_type=None)
                except ValueError:
                    data = None
                return resp.status, data, resp
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            raise NetMonError(f"server non raggiungibile: {exc}") from exc

    async def login(self) -> None:
        if self._refused is not None:
            raise self._refused
        status, data, resp = await self._request(
            "POST", "/api/auth/login",
            json={"email": self._email, "password": self._password, "remember": True})
        if status == 410 and isinstance(data, dict) and data.get("moved"):
            raise NetMonMoved(str(data["moved"]))
        if status in (401, 403):
            self._refused = NetMonAuthError(detail_of(data) or "accesso non riuscito")
            raise self._refused
        if status == 429:
            raise NetMonThrottled(detail_of(data) or "troppi tentativi")
        if status != 200:
            raise NetMonError(f"risposta {status} dal server")
        morsel = resp.cookies.get(COOKIE)
        if morsel is None or not morsel.value:
            raise NetMonError("il server non ha dato la sessione")
        if isinstance(data, dict) and data.get("must_change"):
            self._refused = NetMonAuthError("prima cambia la password provvisoria dalla pagina di NetMon")
            raise self._refused
        self._cookie = morsel.value

    async def status(self) -> dict[str, Any]:
        """Stato di sonde e dispositivi; se la sessione è scaduta rifà l'accesso una volta."""
        for attempt in range(2):
            if self._cookie is None:
                async with self._login_lock:
                    if self._cookie is None:
                        await self.login()
            # un solo evento: la pagina ne chiede 25, qui non servono
            status, data, _ = await self._request("GET", "/api/status", params={"events": 1},
                                                  headers={"Cookie": f"{COOKIE}={self._cookie}"})
            if status == 401 and attempt == 0:
                self._cookie = None
                continue
            if status in (401, 403):
                raise NetMonAuthError(detail_of(data) or "accesso negato")
            if status != 200 or not isinstance(data, dict):
                raise NetMonError(f"risposta {status} dal server")
            return data
        raise NetMonAuthError("accesso negato")
