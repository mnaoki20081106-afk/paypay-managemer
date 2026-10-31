"""SMS virtual number service wrapper for the web app.

Env vars:
  SMSV_ACCESS_TOKEN  — smsvirtual.app access token
  SMSV_REFRESH_TOKEN — smsvirtual.app refresh token (recommended)
"""
from __future__ import annotations

import logging
import os

import aiohttp

from sms_api_base import Config, APIError
from sms_provider import SMSProvider, OutOfStockError, sms_items, public_phone

__all__ = [
    'SMSNotConfiguredError', 'APIError', 'OutOfStockError',
    'is_configured', 'get_provider', 'shutdown',
    'sms_items', 'public_phone',
]

_LOG = logging.getLogger('sms.service')

_session: aiohttp.ClientSession | None = None
_provider: SMSProvider | None = None


class SMSNotConfiguredError(Exception):
    pass


def is_configured() -> bool:
    return bool(
        os.getenv('SMSV_ACCESS_TOKEN', '').strip()
        or os.getenv('SMSV_REFRESH_TOKEN', '').strip()
    )


def _make_config() -> Config:
    access = os.getenv('SMSV_ACCESS_TOKEN', '').strip()
    refresh = os.getenv('SMSV_REFRESH_TOKEN', '').strip()
    if not access and not refresh:
        raise SMSNotConfiguredError()
    # bot_token / owner_id are Discord fields — unused by SMSVirtualAPI
    return Config(bot_token='web', owner_id=0, access_token=access, refresh_token=refresh)


def get_provider() -> SMSProvider:
    global _session, _provider
    if _provider is None:
        config = _make_config()
        _session = aiohttp.ClientSession()
        _provider = SMSProvider(_session, config)
    return _provider


async def shutdown() -> None:
    global _session, _provider
    if _session is not None:
        await _session.close()
    _session = None
    _provider = None
