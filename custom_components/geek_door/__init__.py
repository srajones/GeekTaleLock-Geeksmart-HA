"""GeekSmart Door Lock Home Assistant Custom Component."""
from __future__ import annotations

import logging
from typing import Any, Dict

try:
    from aiohttp import web
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.const import CONF_MODE
    from homeassistant.core import HomeAssistant
    from homeassistant.components import webhook
    from homeassistant.helpers import service
except ImportError:
    # Lightweight mock fallbacks for standalone unit testing
    web = None  # type: ignore[assignment]
    webhook = None  # type: ignore[assignment]
    service = None  # type: ignore[assignment]

from .const import (
    DOMAIN,
    PLATFORMS,
    MODE_SERVER_BRIDGE,
    CONF_WEBHOOK_ID,
    SERVICE_KEEP_UNLOCKED,
    ATTR_DURATION,
)
from .coordinator import GeekDoorDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: Any, config: Dict[str, Any]) -> bool:
    """Set up the GeekSmart Door Lock component from configuration.yaml."""
    if hasattr(hass, "data"):
        hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: Any, entry: Any) -> bool:
    """Set up GeekSmart Door Lock from a config entry."""
    coordinator = GeekDoorDataUpdateCoordinator(hass, entry)
    if hasattr(coordinator, "async_config_entry_first_refresh"):
        await coordinator.async_config_entry_first_refresh()

    # Store coordinator reference with dual-version compatibility
    if hasattr(entry, "runtime_data"):
        entry.runtime_data = coordinator
    if hasattr(hass, "data"):
        hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    # Setup incoming webhook for push updates if in Server Bridge mode
    mode = entry.data.get("mode")
    webhook_id = entry.data.get(CONF_WEBHOOK_ID)
    if mode == MODE_SERVER_BRIDGE and webhook_id and webhook is not None:
        async def async_handle_webhook(
            hass_inst: Any, wh_id: str, request: Any
        ) -> Any:
            try:
                payload = await request.json()
            except Exception:
                return web.Response(status=400, text="Malformed JSON") if web else None

            if not isinstance(payload, dict):
                return (
                    web.Response(status=400, text="Invalid JSON format: expected JSON object")
                    if web
                    else None
                )

            try:
                coordinator.async_handle_push_data(payload)
            except Exception as exc:
                _LOGGER.error("Error processing push webhook payload: %s", exc)
                return web.Response(status=500, text="Internal Error") if web else None

            return web.Response(status=200, text="OK") if web else None

        try:
            webhook.async_register(
                hass,
                DOMAIN,
                f"GeekDoor Bridge ({entry.title})",
                webhook_id,
                async_handle_webhook,
            )
        except Exception as exc:
            _LOGGER.debug("Webhook registration skipped: %s", exc)

    # Register custom service: geek_door.keep_unlocked
    if hasattr(hass, "services") and hasattr(hass.services, "has"):
        if not hass.services.has(DOMAIN, SERVICE_KEEP_UNLOCKED):
            async def async_service_keep_unlocked(call: Any) -> None:
                duration = call.data.get(ATTR_DURATION)
                entity_ids = []
                if service and hasattr(service, "async_extract_entity_ids"):
                    entity_ids = await service.async_extract_entity_ids(hass, call)
                for entity_id in entity_ids:
                    component = hass.data.get("lock")
                    if component:
                        entity = component.get_entity(entity_id)
                        if entity and hasattr(entity, "async_keep_unlocked"):
                            await entity.async_keep_unlocked(duration_seconds=duration)

            hass.services.async_register(
                DOMAIN,
                SERVICE_KEEP_UNLOCKED,
                async_service_keep_unlocked,
            )

    # Forward setup to platforms
    if hasattr(hass, "config_entries") and hasattr(hass.config_entries, "async_forward_entry_setups"):
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Update listener
    if hasattr(entry, "async_on_unload") and hasattr(entry, "add_update_listener"):
        entry.async_on_unload(entry.add_update_listener(async_reload_entry))
    return True


async def async_unload_entry(hass: Any, entry: Any) -> bool:
    """Unload a GeekSmart Door Lock config entry."""
    webhook_id = entry.data.get(CONF_WEBHOOK_ID)
    if webhook_id and webhook is not None and hasattr(webhook, "async_unregister"):
        try:
            webhook.async_unregister(hass, webhook_id)
        except Exception:
            pass

    # Retrieve coordinator reference prior to platform unload
    coordinator = None
    if hasattr(entry, "runtime_data") and entry.runtime_data:
        coordinator = entry.runtime_data
    elif hasattr(hass, "data") and DOMAIN in hass.data:
        coordinator = hass.data[DOMAIN].get(entry.entry_id)

    unload_ok = True
    if hasattr(hass, "config_entries") and hasattr(hass.config_entries, "async_unload_platforms"):
        unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        if coordinator and hasattr(coordinator, "async_shutdown"):
            try:
                await coordinator.async_shutdown()
            except Exception as exc:
                _LOGGER.warning("Error shutting down coordinator on unload: %s", exc)

        if hasattr(hass, "data") and DOMAIN in hass.data:
            hass.data[DOMAIN].pop(entry.entry_id, None)

        if hasattr(entry, "runtime_data"):
            entry.runtime_data = None

    if hasattr(hass, "services") and hasattr(hass, "data"):
        if not hass.data.get(DOMAIN) and hasattr(hass.services, "async_remove"):
            hass.services.async_remove(DOMAIN, SERVICE_KEEP_UNLOCKED)

    return unload_ok


async def async_reload_entry(hass: Any, entry: Any) -> None:
    """Reload config entry when options are updated."""
    if hasattr(hass, "config_entries") and hasattr(hass.config_entries, "async_reload"):
        await hass.config_entries.async_reload(entry.entry_id)
