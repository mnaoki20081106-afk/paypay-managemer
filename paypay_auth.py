"""Multi-account PayPay OAuth manager.

OAuthFlow, AuthResult, parse_oauth_reply, browser_headers, UUID_RE, OTP_CODE_RE,
BROWSER_USER_AGENT, SESSION_MAX_SECONDS, TIMEOUT_SECONDS are taken directly from
zip3/paypayu.py without modification.

The only adaptation is multi-account: instead of a singleton file-based store
and a single PayPayAuthManager, credentials are keyed by phone number in
storage.py (SQLite + Fernet).  The public API (start_login / submit_otp /
refresh_account) mirrors PayPayWebClient from zip3/paypaython_web_mobile.py.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass
from uuid import uuid4

import aiohttp

import storage

AUTH_LOG = logging.getLogger('paypaython.auth')

TOKEN_ENDPOINT = 'https://www.paypay.ne.jp/app/v1/oauth/token'
SESSION_MAX_SECONDS = 7200
TIMEOUT_SECONDS = 25
BROWSER_USER_AGENT = (
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) '
    'AppleWebKit/605.1.15 (KHTML, like Gecko) '
    'Version/18.0 Mobile/15E148 Safari/604.1'
)
BROWSER_CLIENT_HINTS: dict = {}

UUID_RE = re.compile(r'^[a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')
OTP_CODE_RE = re.compile(r'^[0-9]{4}$')


# ── From zip3/paypayu.py verbatim ─────────────────────────────────────────

def browser_headers(referer: str, *, json_body: bool = True) -> dict:
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'ja,en-US;q=0.9,en;q=0.8',
        'Origin': 'https://www.paypay.ne.jp',
        'Referer': referer,
        'User-Agent': BROWSER_USER_AGENT,
        **BROWSER_CLIENT_HINTS,
    }
    if json_body:
        headers['Content-Type'] = 'application/json'
    return headers


class PayPayAuthError(Exception):
    """A sanitized error; do not retain the raw response or request."""
    def __init__(self, reason: str, *, status: int | None = None,
                 provider_code: str | None = None,
                 response_type: str | None = None,
                 reason_hint: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.status = status
        self.provider_code = provider_code
        self.response_type = response_type
        self.reason_hint = reason_hint


@dataclass(frozen=True)
class AuthResult:
    kind: str  # token / otp
    access_token: str = ''
    expires_in: int = 0
    otp_reference_id: str = ''
    otp_prefix: str = ''


def _extract_code(data: dict) -> str | None:
    if not isinstance(data, dict):
        return None
    candidates = [
        data.get('error_code'), data.get('code'), data.get('result_code'),
        (data.get('result_info') or {}).get('result_code')
        if isinstance(data.get('result_info'), dict) else None,
    ]
    for value in candidates:
        if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,60}', value):
            return value
    return None


def parse_oauth_reply(data: object, http_status: int) -> AuthResult:
    """A success requires a real access_token. OTP is an explicit challenge."""
    if not isinstance(data, dict):
        raise PayPayAuthError('unexpected_response', status=http_status)
    code = _extract_code(data)
    if (200 <= http_status < 300
            and isinstance(data.get('access_token'), str)
            and len(data['access_token']) >= 10):
        raw_expiry = data.get('expires_in')
        if isinstance(raw_expiry, (int, float)) and raw_expiry > 0:
            seconds = min(int(raw_expiry), SESSION_MAX_SECONDS)
        else:
            seconds = SESSION_MAX_SECONDS
        return AuthResult('token', access_token=data['access_token'],
                          expires_in=seconds)
    otp_id, otp_prefix = data.get('otp_reference_id'), data.get('otp_prefix')
    if (isinstance(otp_id, str) and otp_id
            and isinstance(otp_prefix, str)
            and re.fullmatch(r'[A-Za-z]{2,8}', otp_prefix)):
        return AuthResult('otp', otp_reference_id=otp_id, otp_prefix=otp_prefix)
    response_type = data.get('response_type')
    if not isinstance(response_type, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,50}', response_type):
        response_type = None
    info = data.get('result_info')
    result_message = info.get('result_msg') if isinstance(info, dict) else None
    reason_hint = None
    if result_message == 'Bad credentials':
        reason_hint = 'bad_credentials'
    elif isinstance(result_message, str) and result_message.startswith('Validate OTP call to notification service'):
        reason_hint = 'otp_validation_failed'
    raise PayPayAuthError('oauth_rejected', status=http_status, provider_code=code,
                          response_type=response_type, reason_hint=reason_hint)


class OAuthFlow:
    """Keeps browser-like cookies within password -> OTP authentication."""
    def __init__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
        )
        self.closed = False

    def authenticated_cookie(self) -> str:
        """HttpOnly token set by PayPay after OAuth success; never log it."""
        from yarl import URL
        jar = self.session.cookie_jar.filter_cookies(URL('https://www.paypay.ne.jp/'))
        morsel = jar.get('token')
        value = morsel.value if morsel else ''
        return value if isinstance(value, str) and value and not any(
            ch in value for ch in '\r\n;'
        ) else ''

    async def close(self):
        if not self.closed:
            self.closed = True
            await self.session.close()

    async def request(self, payload: dict, *, referer: str) -> AuthResult:
        headers = browser_headers(referer)
        AUTH_LOG.info('PayPay OAuth POST starting grant_type=%s',
                      payload.get('grant_type', '-'))
        try:
            async with self.session.post(TOKEN_ENDPOINT, json=payload,
                                         headers=headers) as response:
                status = response.status
                try:
                    body = await response.json(content_type=None)
                except (ValueError, aiohttp.ContentTypeError):
                    raise PayPayAuthError('invalid_json', status=status) from None
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            AUTH_LOG.warning('PayPay OAuth network failure type=%s grant_type=%s',
                             type(exc).__name__, payload.get('grant_type', '-'))
            raise PayPayAuthError('network_error') from None
        if isinstance(body, dict):
            code = _extract_code(body)
        else:
            code = None
        AUTH_LOG.info('PayPay OAuth response http_status=%s result_code=%s grant_type=%s',
                      status, code or '-', payload.get('grant_type', '-'))
        return parse_oauth_reply(body, status)

    async def login_password(self, phone: str, password: str,
                             uuid: str) -> AuthResult:
        return await self.request(
            {'scope': 'SIGN_IN', 'client_uuid': uuid, 'grant_type': 'password',
             'username': phone, 'password': password,
             'add_otp_prefix': True, 'language': 'ja'},
            referer='https://www.paypay.ne.jp/app/account/sign-in',
        )

    async def login_otp(self, uuid: str, otp: str, otp_prefix: str,
                        otp_reference_id: str) -> AuthResult:
        if not OTP_CODE_RE.fullmatch(otp):
            raise PayPayAuthError('invalid_otp_format')
        return await self.request(
            {'scope': 'SIGN_IN', 'grant_type': 'otp', 'client_uuid': uuid,
             'otp': otp, 'otp_prefix': otp_prefix,
             'otp_reference_id': otp_reference_id,
             'username_type': 'MOBILE', 'language': 'ja'},
            referer='https://www.paypay.ne.jp/app/account/sign-in',
        )


# ── Multi-account adaptation ───────────────────────────────────────────────
# Per-phone asyncio locks and in-memory OTP challenges (cleared on restart).

_locks: dict[str, asyncio.Lock] = {}
_pending: dict[str, dict] = {}  # phone -> {flow, uuid, password, otp_prefix, otp_reference_id}


def _lock(phone: str) -> asyncio.Lock:
    if phone not in _locks:
        _locks[phone] = asyncio.Lock()
    return _locks[phone]


def account_valid(data: dict | None, now: float | None = None) -> bool:
    if not data or not data.get('access_token'):
        return False
    current = time.time() if now is None else now
    return current < float(data.get('expires_at') or 0) - 60


def account_status(phone: str) -> dict:
    data = storage.load_account(phone)
    valid = account_valid(data)
    return {
        'phone': phone,
        'registered': bool(data),
        'valid': valid,
        'payment_ready': bool(valid and data and data.get('session_cookie')),
        'expires_at': float(data.get('expires_at') or 0) if data else 0,
        'otp_pending': phone in _pending,
    }


def list_accounts() -> list[dict]:
    return [account_status(p) for p in storage.list_phones()]


def _save_success(phone: str, password: str, uuid: str,
                  result: AuthResult, session_cookie: str) -> None:
    """Mirror zip3 register_success: write a fresh credential dict."""
    if result.kind != 'token' or not result.access_token:
        raise PayPayAuthError('missing_access_token')
    if not UUID_RE.fullmatch(uuid):
        raise PayPayAuthError('invalid_uuid')
    now = time.time()
    storage.save_account(phone, {
        'phone': phone,
        'password': password,
        'uuid': uuid,
        'access_token': result.access_token,
        'session_cookie': session_cookie,
        'expires_at': now + result.expires_in,
        'refreshed_at': now,
    })


# Public API mirrors PayPayWebClient from zip3/paypaython_web_mobile.py

async def start_login(phone: str, password: str) -> dict:
    """Begin login. Returns {'status': 'otp_required', 'otp_prefix': ...}
    or {'status': 'logged_in', 'payment_ready': bool}.
    Reuses existing UUID if already registered (same as PayPayWebClient.start_login).
    """
    phone = phone.strip()
    if not phone or not password:
        raise PayPayAuthError('missing_credentials')
    existing = storage.load_account(phone)
    client_uuid = (
        existing.get('uuid')
        if existing and UUID_RE.fullmatch(existing.get('uuid', ''))
        else str(uuid4())
    )
    async with _lock(phone):
        if phone in _pending:
            await _pending[phone]['flow'].close()
            del _pending[phone]
        flow = OAuthFlow()
        try:
            result = await flow.login_password(phone, password, client_uuid)
            if result.kind == 'otp':
                self_challenge = {
                    'phone': phone, 'password': password, 'uuid': client_uuid,
                    'otp_prefix': result.otp_prefix,
                    'otp_reference_id': result.otp_reference_id,
                }
                _pending[phone] = {'flow': flow, **self_challenge}
                return {'status': 'otp_required', 'otp_prefix': result.otp_prefix}
            cookie = flow.authenticated_cookie()
            await flow.close()
            _save_success(phone, password, client_uuid, result, cookie)
            return {'status': 'logged_in', 'payment_ready': bool(cookie)}
        except Exception:
            if flow not in [_pending.get(phone, {}).get('flow')]:
                await flow.close()
            raise


async def submit_otp(phone: str, otp: str) -> dict:
    """Submit the 4-digit SMS code using the same OAuthFlow session as start_login.
    Mirrors PayPayWebClient.submit_otp.
    """
    async with _lock(phone):
        entry = _pending.get(phone)
        if not entry:
            raise PayPayAuthError('no_pending_otp')
        flow: OAuthFlow = entry['flow']
        try:
            result = await flow.login_otp(
                entry['uuid'], otp,
                entry['otp_prefix'], entry['otp_reference_id'],
            )
            if result.kind != 'token':
                raise PayPayAuthError('unexpected_otp_challenge')
            cookie = flow.authenticated_cookie()
            _save_success(entry['phone'], entry['password'],
                          entry['uuid'], result, cookie)
            return {'status': 'logged_in', 'payment_ready': bool(cookie)}
        finally:
            await flow.close()
            _pending.pop(phone, None)


async def refresh_account(phone: str) -> dict:
    """Re-login with saved credentials. Mirrors PayPayAuthManager.refresh logic.
    Returns {'status': 'renewed'} or {'status': 'otp_required', 'otp_prefix': ...}.
    """
    data = storage.load_account(phone)
    if not data:
        raise PayPayAuthError('not_registered')
    pw = data.get('password')
    uuid = data.get('uuid')
    if not all(isinstance(x, str) and x for x in (pw, uuid)):
        raise PayPayAuthError('missing_saved_credentials')
    async with _lock(phone):
        if phone in _pending:
            await _pending[phone]['flow'].close()
            del _pending[phone]
        flow = OAuthFlow()
        try:
            result = await flow.login_password(phone, pw, uuid)
            if result.kind == 'otp':
                _pending[phone] = {
                    'flow': flow, 'phone': phone, 'password': pw, 'uuid': uuid,
                    'otp_prefix': result.otp_prefix,
                    'otp_reference_id': result.otp_reference_id,
                }
                return {'status': 'otp_required', 'otp_prefix': result.otp_prefix}
            fresh_cookie = flow.authenticated_cookie()
            if not fresh_cookie:
                AUTH_LOG.warning('PayPay OAuth token renewed, but no browser session '
                                 'cookie was returned; receive not verified')
            await flow.close()
            _save_success(phone, pw, uuid, result, fresh_cookie)
            AUTH_LOG.info('PayPay session renewal succeeded; credential UUID retained')
            return {'status': 'renewed'}
        except PayPayAuthError:
            await flow.close()
            raise


def get_session(phone: str) -> dict | None:
    """Return {uuid, session_cookie} if the account is payment-ready.
    Mirrors PayPayAuthManager.payment_session_if_valid.
    """
    data = storage.load_account(phone)
    if account_valid(data) and data and data.get('session_cookie'):
        return {'uuid': data['uuid'], 'session_cookie': data['session_cookie']}
    return None


def get_token(phone: str) -> str | None:
    """Mirrors PayPayAuthManager.get_token_if_valid."""
    data = storage.load_account(phone)
    return data.get('access_token') if account_valid(data) else None
