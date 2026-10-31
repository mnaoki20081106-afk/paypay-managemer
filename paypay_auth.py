"""Multi-account PayPay OAuth manager.

Based on browser-observed OAuth traffic from paypayu.py (zip1).
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

LOG = logging.getLogger("paypay.auth")

TOKEN_ENDPOINT = "https://www.paypay.ne.jp/app/v1/oauth/token"
SESSION_MAX_SECONDS = 7200
TIMEOUT_SECONDS = 25
USER_AGENT = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/18.0 Mobile/15E148 Safari/604.1"
)
UUID_RE = re.compile(
    r"^[a-fA-F0-9]{8}-(?:[a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$"
)
OTP_RE = re.compile(r"^[0-9]{4,8}$")


class PayPayAuthError(Exception):
    def __init__(self, reason: str, *, status: int | None = None,
                 provider_code: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.status = status
        self.provider_code = provider_code


@dataclass(frozen=True)
class _AuthResult:
    kind: str
    access_token: str = ""
    expires_in: int = 0
    otp_reference_id: str = ""
    otp_prefix: str = ""


def _browser_headers(referer: str) -> dict:
    return {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "ja,en-US;q=0.9,en;q=0.8",
        "Content-Type": "application/json",
        "Origin": "https://www.paypay.ne.jp",
        "Referer": referer,
        "User-Agent": USER_AGENT,
    }


def _extract_code(data: dict) -> str | None:
    candidates = [
        data.get("error_code"), data.get("code"), data.get("result_code"),
        (data.get("result_info") or {}).get("result_code")
        if isinstance(data.get("result_info"), dict) else None,
    ]
    for v in candidates:
        if isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,60}", v):
            return v
    return None


def _parse_reply(data: object, http_status: int) -> _AuthResult:
    if not isinstance(data, dict):
        raise PayPayAuthError("unexpected_response", status=http_status)
    code = _extract_code(data)
    if (200 <= http_status < 300
            and isinstance(data.get("access_token"), str)
            and len(data["access_token"]) >= 10):
        raw = data.get("expires_in")
        seconds = (
            min(int(raw), SESSION_MAX_SECONDS)
            if isinstance(raw, (int, float)) and raw > 0
            else SESSION_MAX_SECONDS
        )
        return _AuthResult("token", access_token=data["access_token"],
                           expires_in=seconds)
    otp_id = data.get("otp_reference_id")
    otp_prefix = data.get("otp_prefix")
    if (isinstance(otp_id, str) and otp_id
            and isinstance(otp_prefix, str)
            and re.fullmatch(r"[A-Za-z]{2,8}", otp_prefix)):
        return _AuthResult("otp", otp_reference_id=otp_id, otp_prefix=otp_prefix)
    info = data.get("result_info")
    msg = info.get("result_msg") if isinstance(info, dict) else None
    hint = None
    if msg == "Bad credentials":
        hint = "bad_credentials"
    elif isinstance(msg, str) and msg.startswith("Validate OTP"):
        hint = "otp_validation_failed"
    raise PayPayAuthError(
        hint or "oauth_rejected",
        status=http_status,
        provider_code=code,
    )


class _Flow:
    def __init__(self):
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
        )
        self.closed = False

    def session_cookie(self) -> str:
        from yarl import URL
        jar = self._session.cookie_jar.filter_cookies(
            URL("https://www.paypay.ne.jp/")
        )
        morsel = jar.get("token")
        v = morsel.value if morsel else ""
        return v if isinstance(v, str) and v and not any(
            c in v for c in "\r\n;"
        ) else ""

    async def _post(self, payload: dict, referer: str) -> _AuthResult:
        try:
            async with self._session.post(
                TOKEN_ENDPOINT, json=payload,
                headers=_browser_headers(referer)
            ) as resp:
                status = resp.status
                try:
                    body = await resp.json(content_type=None)
                except (ValueError, aiohttp.ContentTypeError):
                    raise PayPayAuthError("invalid_json", status=status)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            raise PayPayAuthError("network_error")
        LOG.info("PayPay OAuth %s → HTTP %s code=%s",
                 payload.get("grant_type"), status,
                 _extract_code(body) if isinstance(body, dict) else "-")
        return _parse_reply(body, status)

    async def login_password(self, phone: str, password: str,
                             uuid: str) -> _AuthResult:
        return await self._post(
            {"scope": "SIGN_IN", "client_uuid": uuid, "grant_type": "password",
             "username": phone, "password": password,
             "add_otp_prefix": True, "language": "ja"},
            referer="https://www.paypay.ne.jp/app/account/sign-in",
        )

    async def login_otp(self, uuid: str, otp: str, prefix: str,
                        reference_id: str) -> _AuthResult:
        if not OTP_RE.fullmatch(otp):
            raise PayPayAuthError("invalid_otp_format")
        return await self._post(
            {"scope": "SIGN_IN", "grant_type": "otp", "client_uuid": uuid,
             "otp": otp, "otp_prefix": prefix, "otp_reference_id": reference_id,
             "username_type": "MOBILE", "language": "ja"},
            referer="https://www.paypay.ne.jp/app/account/sign-in",
        )

    async def close(self):
        if not self.closed:
            self.closed = True
            await self._session.close()


# Per-phone locks and pending OTP challenges (in-memory, lost on restart).
_locks: dict[str, asyncio.Lock] = {}
_pending: dict[str, dict] = {}  # phone -> {flow, uuid, password, prefix, ref_id}


def _lock(phone: str) -> asyncio.Lock:
    if phone not in _locks:
        _locks[phone] = asyncio.Lock()
    return _locks[phone]


def account_valid(data: dict | None) -> bool:
    if not data or not data.get("access_token"):
        return False
    return time.time() < float(data.get("expires_at") or 0) - 60


def account_status(phone: str) -> dict:
    data = storage.load_account(phone)
    valid = account_valid(data)
    expires_at = float(data.get("expires_at") or 0) if data else 0
    return {
        "phone": phone,
        "registered": bool(data),
        "valid": valid,
        "payment_ready": bool(valid and data and data.get("session_cookie")),
        "expires_at": expires_at,
        "otp_pending": phone in _pending,
    }


def list_accounts() -> list[dict]:
    return [account_status(p) for p in storage.list_phones()]


async def start_login(phone: str, password: str) -> dict:
    """Begin login. Returns {status: 'otp_required', otp_prefix} or {status: 'logged_in'}."""
    if not phone or not password:
        raise PayPayAuthError("missing_credentials")
    existing = storage.load_account(phone)
    uuid = (
        existing.get("uuid")
        if existing and UUID_RE.fullmatch(existing.get("uuid", ""))
        else str(uuid4())
    )
    async with _lock(phone):
        if phone in _pending:
            await _pending[phone]["flow"].close()
            del _pending[phone]
        flow = _Flow()
        try:
            result = await flow.login_password(phone, password, uuid)
        except PayPayAuthError:
            await flow.close()
            raise
        if result.kind == "otp":
            _pending[phone] = {
                "flow": flow,
                "uuid": uuid,
                "phone": phone,
                "password": password,
                "prefix": result.otp_prefix,
                "ref_id": result.otp_reference_id,
            }
            return {"status": "otp_required", "otp_prefix": result.otp_prefix}
        cookie = flow.session_cookie()
        await flow.close()
        _save_success(phone, password, uuid, result, cookie)
        return {"status": "logged_in", "payment_ready": bool(cookie)}


async def submit_otp(phone: str, otp_code: str) -> dict:
    """Submit 4-digit OTP. Must be called after start_login returns otp_required."""
    async with _lock(phone):
        challenge = _pending.get(phone)
        if not challenge:
            raise PayPayAuthError("no_pending_otp")
        flow: _Flow = challenge["flow"]
        try:
            result = await flow.login_otp(
                challenge["uuid"], otp_code,
                challenge["prefix"], challenge["ref_id"]
            )
            if result.kind != "token":
                raise PayPayAuthError("unexpected_otp_response")
            cookie = flow.session_cookie()
            _save_success(
                phone, challenge["password"], challenge["uuid"], result, cookie
            )
            return {"status": "logged_in", "payment_ready": bool(cookie)}
        finally:
            await flow.close()
            _pending.pop(phone, None)


async def refresh_account(phone: str) -> dict:
    """Re-login with saved credentials. Returns {status: ..., message: ...}."""
    data = storage.load_account(phone)
    if not data:
        raise PayPayAuthError("not_registered")
    pw = data.get("password")
    uuid = data.get("uuid")
    if not pw or not uuid:
        raise PayPayAuthError("missing_saved_credentials")
    async with _lock(phone):
        flow = _Flow()
        try:
            result = await flow.login_password(phone, pw, uuid)
            if result.kind == "otp":
                _pending[phone] = {
                    "flow": flow,
                    "uuid": uuid,
                    "phone": phone,
                    "password": pw,
                    "prefix": result.otp_prefix,
                    "ref_id": result.otp_reference_id,
                }
                return {"status": "otp_required", "otp_prefix": result.otp_prefix}
            cookie = flow.session_cookie()
            await flow.close()
            _save_success(phone, pw, uuid, result, cookie)
            return {"status": "renewed"}
        except PayPayAuthError:
            await flow.close()
            raise


def get_session(phone: str) -> dict | None:
    """Return {uuid, session_cookie} if the account is payment-ready."""
    data = storage.load_account(phone)
    if account_valid(data) and data and data.get("session_cookie"):
        return {"uuid": data["uuid"], "session_cookie": data["session_cookie"]}
    return None


def get_token(phone: str) -> str | None:
    data = storage.load_account(phone)
    return data.get("access_token") if account_valid(data) else None


def _save_success(phone: str, password: str, uuid: str,
                  result: _AuthResult, cookie: str):
    now = time.time()
    data = storage.load_account(phone) or {}
    data.update({
        "phone": phone,
        "password": password,
        "uuid": uuid,
        "access_token": result.access_token,
        "session_cookie": cookie,
        "expires_at": now + result.expires_in,
        "refreshed_at": now,
    })
    storage.save_account(phone, data)
