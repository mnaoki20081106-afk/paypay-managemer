"""PayPay balance fetch — Web API endpoint found from GitHub analysis of
taka-4602/PayPaython (GET /app/v1/bff/getBalanceInfo).
NOT in zip3; implemented based on GitHub analysis as requested by dj.
"""
from __future__ import annotations

import asyncio
import logging

import aiohttp

import paypay_auth
from paypay_auth import PayPayAuthError, browser_headers

BALANCE_LOG = logging.getLogger('paypaython.balance')
BALANCE_ENDPOINT = 'https://www.paypay.ne.jp/app/v1/bff/getBalanceInfo'
TIMEOUT_SECONDS = 20


class BalanceError(Exception):
    def __init__(self, reason: str, *, status: int | None = None):
        super().__init__(reason)
        self.reason = reason
        self.status = status


async def get_balance(phone: str) -> dict:
    """Fetch balance for a registered account.

    Returns {'balance': int, 'raw': dict} on success.
    Raises BalanceError or PayPayAuthError on failure.

    Endpoint: GET https://www.paypay.ne.jp/app/v1/bff/getBalanceInfo
    Source: taka-4602/PayPaython (Web API, not mobile API)
    """
    token = paypay_auth.get_token(phone)
    if not token:
        raise BalanceError('session_expired')

    headers = browser_headers(
        'https://www.paypay.ne.jp/app/account/home',
        json_body=False,
    )
    headers['Authorization'] = f'Bearer {token}'

    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
        ) as session:
            async with session.get(BALANCE_ENDPOINT, headers=headers) as response:
                http_status = response.status
                try:
                    body = await response.json(content_type=None)
                except (ValueError, aiohttp.ContentTypeError):
                    raise BalanceError('invalid_json', status=http_status) from None
    except (aiohttp.ClientError, asyncio.TimeoutError):
        raise BalanceError('network_error') from None

    if not isinstance(body, dict):
        raise BalanceError('unexpected_response', status=http_status)

    result_code = (body.get('header') or {}).get('resultCode')
    if result_code != 'S0000':
        BALANCE_LOG.warning('getBalanceInfo resultCode=%s phone=%s', result_code, phone)
        raise BalanceError('api_error', status=http_status)

    try:
        balance = body['payload']['walletDetail']['emoneyBalanceInfo']['balance']
    except (KeyError, TypeError):
        raise BalanceError('missing_balance_field') from None

    if not isinstance(balance, (int, float)):
        raise BalanceError('unexpected_balance_type')

    return {'balance': int(balance), 'raw': body}
