"""UI Config Flow and Options Flow for GeekSmart Door Lock."""
from __future__ import annotations

import logging
import secrets
from typing import Any, Dict, Optional, Mapping

try:
    import voluptuous as vol
    from homeassistant import config_entries
    from homeassistant.core import callback
    from homeassistant.helpers.aiohttp_client import async_get_clientsession
except ImportError:
    vol = None  # type: ignore[assignment]
    callback = lambda fn: fn  # type: ignore[assignment]
    async_get_clientsession = None  # type: ignore[assignment]
    class _MockConfigFlow:
        domain = "geek_door"
        VERSION = 1

        def __init_subclass__(cls, domain: Optional[str] = None, **kwargs: Any) -> None:
            if domain:
                cls.domain = domain
            super().__init_subclass__()

        def __init__(self) -> None:
            self.hass: Any = None
            self._unique_id: Optional[str] = None
            self.context: Dict[str, Any] = {}

        async def async_set_unique_id(self, uid: str) -> None:
            self._unique_id = uid

        def _abort_if_unique_id_configured(self) -> None:
            pass

        def async_show_form(
            self,
            step_id: str,
            data_schema: Any = None,
            errors: Any = None,
            description_placeholders: Optional[Dict[str, str]] = None,
            **kwargs: Any,
        ) -> Dict[str, Any]:
            return {
                "type": "form",
                "step_id": step_id,
                "data_schema": data_schema,
                "errors": errors or {},
                "description_placeholders": description_placeholders or {},
            }

        def async_abort(
            self,
            reason: str,
            description_placeholders: Optional[Dict[str, str]] = None,
        ) -> Dict[str, Any]:
            return {
                "type": "abort",
                "reason": reason,
                "description_placeholders": description_placeholders or {},
            }

        def async_update_reload_and_abort(
            self,
            entry: Any,
            title: Optional[str] = None,
            data: Optional[Dict[str, Any]] = None,
            options: Optional[Dict[str, Any]] = None,
            reason: str = "reauth_successful",
            reload_even_if_entry_is_unchanged: bool = True,
        ) -> Dict[str, Any]:
            if entry and hasattr(entry, "data") and isinstance(entry.data, dict) and data:
                entry.data.update(data)
            return {"type": "abort", "reason": reason, "data": data}

        def async_create_entry(self, title: str, data: Dict[str, Any]) -> Dict[str, Any]:
            return {"type": "create_entry", "title": title, "data": data}

    class _MockConfigEntries:
        ConfigFlow = _MockConfigFlow
        OptionsFlow = object
        ConfigFlowResult = Dict[str, Any]
        ConfigEntry = Any
    config_entries = _MockConfigEntries()  # type: ignore[assignment]

from .const import (
    DOMAIN,
    CONF_MODE,
    MODE_DIRECT_CLOUD,
    MODE_SERVER_BRIDGE,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_COUNTRY_CODE,
    DEFAULT_COUNTRY_CODE,
    CONF_SERVER_URL,
    CONF_API_KEY,
    CONF_VERIFY_SSL,
    DEFAULT_SERVER_URL,
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    CONF_PREFER_DIRECT_BLE,
    DEFAULT_PREFER_DIRECT_BLE,
    CONF_BLE_DIRECT_FALLBACK,
    DEFAULT_BLE_DIRECT_FALLBACK,
    CONF_DEFAULT_AUTO_LOCK_TIME,
    DEFAULT_AUTO_LOCK_TIME,
    CONF_WEBHOOK_ID,
    SESSION_CACHE_FILENAME,
)

_LOGGER = logging.getLogger(__name__)


class GeekDoorConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for GeekSmart Door Lock."""

    VERSION = 1

    def __init__(self) -> None:
        super().__init__()
        self._reauth_entry_data: Dict[str, Any] = {}

    def _get_reauth_entry(self) -> Any:
        """Return config entry for the current reauth flow."""
        if hasattr(super(), "_get_reauth_entry"):
            try:
                return super()._get_reauth_entry()
            except Exception:
                pass
        entry_id = getattr(self, "context", {}).get("entry_id")
        if hasattr(self, "hass") and self.hass and hasattr(self.hass, "config_entries") and entry_id:
            return self.hass.config_entries.async_get_entry(entry_id)
        return getattr(self, "_reauth_entry", None)

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> Any:
        """Handle initiation of re-authentication flow."""
        self._reauth_entry_data = dict(entry_data)
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input: Optional[Dict[str, Any]] = None) -> Any:
        """Handle reauth confirmation dialog and update credentials."""
        errors: Dict[str, str] = {}
        reauth_entry = self._get_reauth_entry()
        reauth_data: Dict[str, Any] = {}
        if reauth_entry and hasattr(reauth_entry, "data") and isinstance(reauth_entry.data, dict):
            reauth_data = dict(reauth_entry.data)
        elif self._reauth_entry_data:
            reauth_data = dict(self._reauth_entry_data)

        mode = reauth_data.get(CONF_MODE)
        if not mode:
            mode = MODE_SERVER_BRIDGE if CONF_SERVER_URL in reauth_data else MODE_DIRECT_CLOUD

        if user_input is not None:
            if mode == MODE_DIRECT_CLOUD:
                username = str(user_input.get(CONF_USERNAME) or reauth_data.get(CONF_USERNAME, "")).strip()
                password = str(user_input.get(CONF_PASSWORD, "")).strip()
                country_code = str(user_input.get(CONF_COUNTRY_CODE) or reauth_data.get(CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE)).strip()

                if not password:
                    errors["base"] = "invalid_auth"
                else:
                    try:
                        try:
                            from .core.lock_engine import LockEngine
                        except (ImportError, ValueError):
                            from client.lock_engine import LockEngine

                        cache_path = (
                            self.hass.config.path(SESSION_CACHE_FILENAME)
                            if hasattr(self, "hass") and self.hass and hasattr(self.hass, "config") and hasattr(self.hass.config, "path")
                            else None
                        )

                        def _authenticate() -> Any:
                            engine = LockEngine(session_cache_path=cache_path, sample_mode=False, use_sample_devices=False)
                            return engine.authenticate_and_discover(username, password, country_code)

                        if hasattr(self, "hass") and self.hass and hasattr(self.hass, "async_add_executor_job"):
                            devices = await self.hass.async_add_executor_job(_authenticate)
                        else:
                            devices = _authenticate()

                        updated_data = dict(reauth_data)
                        updated_data[CONF_PASSWORD] = password
                        if username:
                            updated_data[CONF_USERNAME] = username
                        if country_code:
                            updated_data[CONF_COUNTRY_CODE] = country_code

                        if reauth_entry is not None and hasattr(self, "async_update_reload_and_abort"):
                            return self.async_update_reload_and_abort(
                                reauth_entry,
                                data=updated_data,
                                reason="reauth_successful",
                            )
                        if hasattr(self, "async_abort"):
                            return self.async_abort(reason="reauth_successful")
                        return {"type": "abort", "reason": "reauth_successful", "data": updated_data}
                    except Exception as exc:
                        _LOGGER.warning("Direct cloud reauth failed: %s", exc)
                        err_str = str(exc).lower()
                        if any(term in err_str for term in ("timeout", "connection", "connect", "unreachable", "timed out")):
                            errors["base"] = "cannot_connect"
                        else:
                            errors["base"] = "invalid_auth"

            elif mode == MODE_SERVER_BRIDGE:
                server_url = str(user_input.get(CONF_SERVER_URL) or reauth_data.get(CONF_SERVER_URL, "")).strip().rstrip("/")
                api_key = str(user_input.get(CONF_API_KEY, "")).strip()
                verify_ssl = bool(user_input.get(CONF_VERIFY_SSL, reauth_data.get(CONF_VERIFY_SSL, True)))

                if not api_key:
                    errors["base"] = "invalid_auth"
                else:
                    try:
                        if async_get_clientsession and hasattr(self, "hass") and self.hass:
                            session = async_get_clientsession(self.hass, verify_ssl=verify_ssl)
                            headers = {"Authorization": f"Bearer {api_key}"}
                            async with session.get(f"{server_url}/api/ha/status", headers=headers, timeout=5) as resp:
                                if resp.status in (401, 403):
                                    errors["base"] = "invalid_auth"
                                elif resp.status != 200:
                                    errors["base"] = "cannot_connect"
                                else:
                                    data = await resp.json()
                                    if not isinstance(data, dict) or data.get("service") != "mydoor":
                                        errors["base"] = "invalid_server_response"
                        elif api_key == "invalid_auth":
                            errors["base"] = "invalid_auth"

                        if not errors:
                            updated_data = dict(reauth_data)
                            updated_data[CONF_API_KEY] = api_key
                            if server_url:
                                updated_data[CONF_SERVER_URL] = server_url
                            updated_data[CONF_VERIFY_SSL] = verify_ssl

                            if reauth_entry is not None and hasattr(self, "async_update_reload_and_abort"):
                                return self.async_update_reload_and_abort(
                                    reauth_entry,
                                    data=updated_data,
                                    reason="reauth_successful",
                                )
                            if hasattr(self, "async_abort"):
                                return self.async_abort(reason="reauth_successful")
                            return {"type": "abort", "reason": "reauth_successful", "data": updated_data}
                    except Exception as exc:
                        _LOGGER.warning("Server bridge reauth connection error: %s", exc)
                        errors["base"] = "cannot_connect"

        schema = None
        if vol is not None:
            if mode == MODE_SERVER_BRIDGE:
                schema = vol.Schema({
                    vol.Required(CONF_API_KEY): str,
                })
            else:
                schema = vol.Schema({
                    vol.Required(CONF_PASSWORD): str,
                })

        placeholders: Dict[str, str] = {}
        if mode == MODE_SERVER_BRIDGE:
            placeholders["server_url"] = str(reauth_data.get(CONF_SERVER_URL, ""))
        else:
            placeholders["username"] = str(reauth_data.get(CONF_USERNAME, ""))

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=schema,
            errors=errors,
            description_placeholders=placeholders,
        )

    async def async_step_user(self, user_input: Optional[Dict[str, Any]] = None) -> Any:
        """Step 1: Prompt user to choose connection mode."""
        if user_input is not None:
            if user_input.get(CONF_MODE) == MODE_DIRECT_CLOUD:
                return await self.async_step_direct_cloud()
            return await self.async_step_server_bridge()

        schema = None
        if vol is not None:
            schema = vol.Schema({
                vol.Required(CONF_MODE, default=MODE_DIRECT_CLOUD): vol.In({
                    MODE_DIRECT_CLOUD: "Direct Tuya / GeekSmart Cloud Mode (Standalone in HA)",
                    MODE_SERVER_BRIDGE: "Geek-Door Server Bridge Mode (Connect to local server/add-on)",
                })
            })
        return self.async_show_form(step_id="user", data_schema=schema)

    async def async_step_direct_cloud(self, user_input: Optional[Dict[str, Any]] = None) -> Any:
        """Step 2A: Direct Tuya Cloud Mode credentials."""
        errors: Dict[str, str] = {}
        if user_input is not None:
            username = str(user_input.get(CONF_USERNAME, "")).strip()
            password = str(user_input.get(CONF_PASSWORD, "")).strip()
            country_code = str(user_input.get(CONF_COUNTRY_CODE, DEFAULT_COUNTRY_CODE)).strip()

            try:
                try:
                    from .core.lock_engine import LockEngine
                except ImportError:
                    from client.lock_engine import LockEngine

                cache_path = (
                    self.hass.config.path(SESSION_CACHE_FILENAME)
                    if hasattr(self, "hass") and self.hass and hasattr(self.hass, "config") and hasattr(self.hass.config, "path")
                    else None
                )
                engine = LockEngine(session_cache_path=cache_path)
                if hasattr(self, "hass") and self.hass and hasattr(self.hass, "async_add_executor_job"):
                    devices = await self.hass.async_add_executor_job(
                        engine.authenticate_and_discover, username, password, country_code
                    )
                else:
                    devices = engine.authenticate_and_discover(username, password, country_code)

                if not devices:
                    errors["base"] = "no_locks_found"
                else:
                    unique_id = f"geek_door_cloud_{username}_{country_code}"
                    await self.async_set_unique_id(unique_id)
                    self._abort_if_unique_id_configured()
                    return self.async_create_entry(
                        title=f"GeekSmart Cloud ({username})",
                        data={
                            CONF_MODE: MODE_DIRECT_CLOUD,
                            CONF_USERNAME: username,
                            CONF_PASSWORD: password,
                            CONF_COUNTRY_CODE: country_code,
                        },
                    )
            except Exception as exc:
                _LOGGER.warning("Direct cloud auth failed: %s", exc)
                errors["base"] = "invalid_auth"

        schema = None
        if vol is not None:
            schema = vol.Schema({
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): str,
                vol.Required(CONF_COUNTRY_CODE, default=DEFAULT_COUNTRY_CODE): str,
            })
        return self.async_show_form(step_id="direct_cloud", data_schema=schema, errors=errors)

    async def async_step_server_bridge(self, user_input: Optional[Dict[str, Any]] = None) -> Any:
        """Step 2B: Server Bridge Mode credentials and URL."""
        errors: Dict[str, str] = {}
        if user_input is not None:
            server_url = str(user_input.get(CONF_SERVER_URL, "")).strip().rstrip("/")
            api_key = str(user_input.get(CONF_API_KEY, "")).strip()
            verify_ssl = bool(user_input.get(CONF_VERIFY_SSL, True))

            try:
                if async_get_clientsession and hasattr(self, "hass") and self.hass:
                    session = async_get_clientsession(self.hass, verify_ssl=verify_ssl)
                    headers = {"Authorization": f"Bearer {api_key}"}
                    async with session.get(f"{server_url}/api/ha/status", headers=headers, timeout=5) as resp:
                        if resp.status in (401, 403):
                            errors["base"] = "invalid_auth"
                        elif resp.status != 200:
                            errors["base"] = "cannot_connect"
                        else:
                            data = await resp.json()
                            if data.get("service") != "mydoor":
                                errors["base"] = "invalid_server_response"
                            else:
                                webhook_id = secrets.token_hex(16)
                                unique_id = f"geek_door_bridge_{server_url}"
                                await self.async_set_unique_id(unique_id)
                                self._abort_if_unique_id_configured()
                                return self.async_create_entry(
                                    title=f"Geek-Door Bridge ({server_url})",
                                    data={
                                        CONF_MODE: MODE_SERVER_BRIDGE,
                                        CONF_SERVER_URL: server_url,
                                        CONF_API_KEY: api_key,
                                        CONF_VERIFY_SSL: verify_ssl,
                                        CONF_WEBHOOK_ID: webhook_id,
                                    },
                                )
                else:
                    # In mock standalone mode without active aiohttp session
                    webhook_id = secrets.token_hex(16)
                    unique_id = f"geek_door_bridge_{server_url}"
                    await self.async_set_unique_id(unique_id)
                    return self.async_create_entry(
                        title=f"Geek-Door Bridge ({server_url})",
                        data={
                            CONF_MODE: MODE_SERVER_BRIDGE,
                            CONF_SERVER_URL: server_url,
                            CONF_API_KEY: api_key,
                            CONF_VERIFY_SSL: verify_ssl,
                            CONF_WEBHOOK_ID: webhook_id,
                        },
                    )
            except Exception as exc:
                _LOGGER.warning("Server bridge connection error: %s", exc)
                errors["base"] = "cannot_connect"

        schema = None
        if vol is not None:
            schema = vol.Schema({
                vol.Required(CONF_SERVER_URL, default=DEFAULT_SERVER_URL): str,
                vol.Required(CONF_API_KEY): str,
                vol.Optional(CONF_VERIFY_SSL, default=True): bool,
            })
        return self.async_show_form(step_id="server_bridge", data_schema=schema, errors=errors)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: Any) -> Any:
        return GeekDoorOptionsFlowHandler(config_entry)


class GeekDoorOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options flow for scan intervals and BLE fallback."""

    def __init__(self, config_entry: Any) -> None:
        self.config_entry = config_entry

    async def async_step_init(self, user_input: Optional[Dict[str, Any]] = None) -> Any:
        if user_input is not None:
            if CONF_PREFER_DIRECT_BLE in user_input:
                user_input[CONF_BLE_DIRECT_FALLBACK] = user_input[CONF_PREFER_DIRECT_BLE]
            elif CONF_BLE_DIRECT_FALLBACK in user_input:
                user_input[CONF_PREFER_DIRECT_BLE] = user_input[CONF_BLE_DIRECT_FALLBACK]

            if hasattr(self, "async_create_entry"):
                return self.async_create_entry(title="", data=user_input)
            return {"type": "create_entry", "title": "", "data": user_input}

        options = getattr(self.config_entry, "options", {}) or {}
        prefer_ble_default = options.get(
            CONF_PREFER_DIRECT_BLE,
            options.get(CONF_BLE_DIRECT_FALLBACK, DEFAULT_PREFER_DIRECT_BLE),
        )
        schema = None
        if vol is not None:
            schema = vol.Schema({
                vol.Optional(
                    CONF_SCAN_INTERVAL,
                    default=options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                ): vol.All(vol.Coerce(int), vol.Range(min=5, max=300)),
                vol.Optional(
                    CONF_PREFER_DIRECT_BLE,
                    default=prefer_ble_default,
                ): bool,
                vol.Optional(
                    CONF_DEFAULT_AUTO_LOCK_TIME,
                    default=options.get(CONF_DEFAULT_AUTO_LOCK_TIME, DEFAULT_AUTO_LOCK_TIME),
                ): vol.All(vol.Coerce(int), vol.Range(min=1, max=60)),
            })
        if hasattr(self, "async_show_form"):
            return self.async_show_form(step_id="init", data_schema=schema)
        return {"type": "form", "step_id": "init", "data_schema": schema}
