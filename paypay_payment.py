"""PayPay P2P link receipt — adapted from zip3/paypayu.py receive_payment.

Multi-account: takes an explicit phone parameter instead of a singleton manager.
Logic (normalize_link, validate_link_info, validate_accept_reply, hold detection)
is taken directly from the supplied source without modification.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import aiohttp

import paypay_auth
from paypay_auth import PayPayAuthError

GATEWAY_LOG = logging.getLogger('paypaython.payment')
ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / 'data' / 'paypay_payments.sqlite3'

LINK_CHECK_ENDPOINT = 'https://www.paypay.ne.jp/app/v2/p2p-api/getP2PLinkInfo'
LINK_ACCEPT_ENDPOINT = 'https://www.paypay.ne.jp/app/v2/p2p-api/acceptP2PSendMoneyLink'

BROWSER_USER_AGENT = (
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) '
    'AppleWebKit/605.1.15 (KHTML, like Gecko) '
    'Version/18.0 Mobile/15E148 Safari/604.1'
)

LINK_RE = re.compile(r'https://pay\.paypay\.ne\.jp/([A-Za-z0-9]{6,128})(?![A-Za-z0-9])', re.I)
LINK_CODE_RE = re.compile(r'[A-Za-z0-9]{6,128}\Z')
_LOCK = asyncio.Lock()
HOLD_CODES = frozenset({'42007013', '42007014', '42007015', '42007016'})
HOLD_NOTICE = (
    'PayPay側で一時保留になっている可能性があります。'
    'PayPayアプリで送金の状態を確認し、解除操作が表示される場合は解除してください。'
    '解除後は販売者側で受取状況を再確認します。'
    '確認が終わるまで、同じリンクを再送したり新しい送金をしたりしないでください。'
)


def browser_headers(referer: str, *, json_body: bool = True) -> dict:
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'ja,en-US;q=0.9,en;q=0.8',
        'Origin': 'https://www.paypay.ne.jp',
        'Referer': referer,
        'User-Agent': BROWSER_USER_AGENT,
    }
    if json_body:
        headers['Content-Type'] = 'application/json'
    return headers


# ── Errors ─────────────────────────────────────────────────────────────────

class PaymentError(Exception):
    """Public-safe error — does not expose URLs, cookies, tokens."""
    def __init__(self, kind: str, public_message: str):
        super().__init__(kind)
        self.kind = kind
        self.message = public_message


class TemporaryHold(PaymentError):
    def __init__(self, provider_code: str, payment_id: str):
        super().__init__('temporary_hold', HOLD_NOTICE)
        self.provider_code = provider_code
        self.payment_id = payment_id


# ── Link parsing / validation (from zip3) ─────────────────────────────────

def normalize_link(raw: str) -> str | None:
    """Support bare link, code, and copied notification with a single unambiguous link."""
    if not isinstance(raw, str) or not 1 <= len(raw) <= 4000:
        return None
    raw = raw.strip()
    if LINK_CODE_RE.fullmatch(raw):
        return raw
    urls = LINK_RE.findall(raw)
    if not urls or len(set(urls)) != 1:
        return None
    all_urls = re.findall(r'https?://[^\s<>\[\]\(\)"\']+', raw, re.I)
    for url in all_urls:
        try:
            parts = urlsplit(url.rstrip('.,;。'))
            if parts.scheme != 'https' or parts.hostname != 'pay.paypay.ne.jp':
                return None
            if not re.fullmatch('/' + re.escape(urls[0]) + '/?', parts.path):
                return None
            if parts.username or parts.password or parts.port or parts.fragment or parts.query:
                return None
        except ValueError:
            return None
    return urls[0]


def _parse_iso(value: str) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        date = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return date if date.tzinfo else None
    except ValueError:
        return None


def validate_link_info(body: object, amount: int) -> dict:
    """Check a valid pending link without requiring a configured receiver ID."""
    if not isinstance(body, dict) or (body.get('header') or {}).get('resultCode') != 'S0000':
        raise PaymentError('invalid_link', 'PayPayリンクを確認できませんでした。')
    p = body.get('payload')
    if not isinstance(p, dict) or p.get('orderStatus') != 'PENDING':
        raise PaymentError('not_pending', 'このリンクは未受取状態ではありません。別のリンクを使用してください。')
    info = p.get('pendingP2PInfo')
    message = p.get('message')
    if not isinstance(info, dict) or not isinstance(message, dict):
        raise PaymentError('missing_fields', '送金リンクの取引情報が不足しています。')
    if type(info.get('amount')) is not int or info['amount'] != amount or amount < 1:
        raise PaymentError('amount_mismatch', 'PayPayリンクの送金金額と商品の合計額が一致しません。')
    if info.get('isLinkBlocked') is not False or info.get('isSetPasscode') is not False:
        raise PaymentError('blocked_or_passcode', 'ブロック中またはパスコード付きのリンクは利用できません。')
    expires_at = _parse_iso(info.get('expiredAt'))
    if expires_at is None or expires_at <= datetime.now(timezone.utc):
        raise PaymentError('expired', 'PayPayリンクの有効期限が切れているか、確認できません。')
    receiver = p.get('receiver')
    sender = p.get('sender')
    if not isinstance(receiver, dict) or not isinstance(sender, dict):
        raise PaymentError('identity_missing', '送金元・受取先を確認できませんでした。')
    receiver_id = receiver.get('externalId')
    sender_id = sender.get('externalId')
    if not isinstance(receiver_id, str) or not receiver_id or not isinstance(sender_id, str) or not sender_id:
        raise PaymentError('identity_missing', '送金元・受取先の識別情報が不足しています。')
    if sender_id == receiver_id:
        raise PaymentError('self_payment', '送金元と受取先が同一のリンクは利用できません。')
    data = message.get('data')
    if not isinstance(data, dict):
        raise PaymentError('message_missing', 'リンクのメッセージ情報が不足しています。')
    order_id = info.get('orderId')
    if not isinstance(order_id, str) or not order_id or data.get('orderId') != order_id:
        raise PaymentError('order_mismatch', 'リンクの注文情報が一致しません。')
    if data.get('amount') != amount or data.get('status') != 'PENDING':
        raise PaymentError('message_mismatch', 'リンクの金額・状態が一致しません。')
    message_id, chat_id = message.get('messageId'), message.get('chatRoomId')
    transaction_at = data.get('transactionAt')
    if not all(isinstance(v, str) and v for v in (message_id, chat_id, transaction_at)) or not _parse_iso(transaction_at):
        raise PaymentError('message_incomplete', 'リンクの受取パラメータが不足しています。')
    return {
        'order_id': order_id, 'message_id': message_id, 'chat_id': chat_id,
        'request_at': transaction_at, 'amount': amount,
        'sender_id': sender_id, 'receiver_id': receiver_id,
    }


def validate_accept_reply(body: object) -> bool:
    return (
        isinstance(body, dict)
        and isinstance(body.get('header'), dict)
        and body['header'].get('resultCode') == 'S0000'
        and isinstance(body.get('payload'), dict)
        and body['payload'].get('orderStatus') == 'COMPLETED'
        and body.get('error') is None
    )


def _provider_hold_code(body: object) -> str | None:
    """Read only structured result-code fields, never arbitrary message text."""
    if not isinstance(body, dict):
        return None
    candidates = []

    def collect(obj):
        if not isinstance(obj, dict):
            return
        for field in ('resultCode', 'result_code', 'errorCode', 'error_code', 'code'):
            value = obj.get(field)
            if type(value) in (str, int):
                candidates.append(str(value))

    collect(body)
    for key in ('header', 'error', 'result_info', 'resultInfo'):
        collect(body.get(key))
    errors = body.get('errors')
    if isinstance(errors, list):
        for obj in errors[:10]:
            collect(obj)
    for code in candidates:
        if code in HOLD_CODES:
            return code
    return None


# ── Ledger (adds account_phone for multi-account tracking) ────────────────

@contextmanager
def _db():
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(LEDGER, timeout=20)
    if os.name != 'nt':
        os.chmod(LEDGER, 0o600)
    try:
        conn.execute('PRAGMA busy_timeout=20000')
        conn.execute('''CREATE TABLE IF NOT EXISTS accepted_links (
            code_hash TEXT PRIMARY KEY,
            order_id TEXT NOT NULL UNIQUE,
            purchase_id TEXT NOT NULL UNIQUE,
            account_phone TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL,
            amount INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )''')
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def reserve_link(code: str, order_id: str, purchase_id: str,
                 amount: int, phone: str) -> str:
    digest = hashlib.sha256(code.encode('utf-8')).hexdigest()
    with _db() as con:
        try:
            con.execute(
                '''INSERT INTO accepted_links
                   (code_hash, order_id, purchase_id, account_phone, status, amount)
                   VALUES (?, ?, ?, ?, 'attempted', ?)''',
                (digest, order_id, purchase_id, phone, amount),
            )
        except sqlite3.IntegrityError:
            raise PaymentError(
                'duplicate',
                'このPayPayリンクは既に処理中または使用済みです。再購入せず販売者に確認してください。',
            ) from None
    return digest


def mark_status(digest: str, status: str):
    if status not in ('paid', 'pending', 'review', 'delivered', 'delivery_failed'):
        raise ValueError('invalid local payment status')
    with _db() as con:
        con.execute(
            'UPDATE accepted_links SET status=?,updated_at=CURRENT_TIMESTAMP WHERE code_hash=?',
            (status, digest),
        )


def list_payments(limit: int = 50) -> list[dict]:
    with _db() as conn:
        rows = conn.execute(
            'SELECT order_id, account_phone, status, amount, created_at, updated_at '
            'FROM accepted_links ORDER BY created_at DESC LIMIT ?',
            (limit,),
        ).fetchall()
    return [
        dict(zip(['order_id', 'phone', 'status', 'amount', 'created_at', 'updated_at'], r))
        for r in rows
    ]


# ── Core receive (from zip3 receive_payment, multi-account adapted) ────────

async def _get_link(session: aiohttp.ClientSession, code: str, uuid: str) -> object:
    try:
        async with session.get(
            LINK_CHECK_ENDPOINT,
            params={'verificationCode': code, 'client_uuid': uuid},
        ) as response:
            if response.status != 200:
                raise PaymentError('link_http', 'PayPayリンクの確認に失敗しました。')
            return await response.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        raise PaymentError('link_network', 'PayPayリンク確認で通信エラーが発生しました。') from None


async def receive_link(phone: str, raw_link: str, amount: int,
                       purchase_id: str | None = None) -> dict:
    """Accept a P2P payment link for the given account phone.

    Returns {status: 'paid', payment_id, amount} on confirmed success.
    Raises TemporaryHold or PaymentError on failure.
    """
    code = normalize_link(raw_link)
    if not code:
        raise PaymentError('bad_link', 'PayPay送金リンクが正しくありません。')

    pid = purchase_id or str(uuid4())

    async with _LOCK:
        try:
            account = paypay_auth.get_session(phone)
        except PayPayAuthError:
            account = None
        if not account:
            raise PaymentError(
                'login_required',
                f'{phone} のPayPayセッションが有効ではありません。再ログインしてください。',
            )

        link_referer = (
            f'https://www.paypay.ne.jp/app/p2p/{code}'
            f'?pid=SMS&link_key={code}'
            '&af_dp=paypay%3A%2F%2Fpending%2Fdetail%3Fsource%3Dsns_link'
        )
        headers = browser_headers(link_referer)

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=25),
            headers=headers,
            cookies={'token': account['session_cookie']},
        ) as session:
            body = await _get_link(session, code, account['uuid'])
            verified = validate_link_info(body, amount)
            digest = reserve_link(code, verified['order_id'], pid, amount, phone)

            payload = {
                'requestAt': verified['request_at'],
                'orderId': verified['order_id'],
                'requestId': str(uuid4()),
                'senderChannelUrl': verified['chat_id'],
                'senderMessageId': verified['message_id'],
                'verificationCode': code,
                'client_uuid': account['uuid'],
                'iosMinimumVersion': '3.45.0',
                'androidMinimumVersion': '3.45.0',
            }

            try:
                async with session.post(LINK_ACCEPT_ENDPOINT, json=payload) as response:
                    http_status = response.status
                    try:
                        reply = await response.json(content_type=None)
                    except (ValueError, aiohttp.ContentTypeError, UnicodeError):
                        reply = None

                if http_status == 200 and validate_accept_reply(reply):
                    mark_status(digest, 'paid')
                    return {'status': 'paid', 'payment_id': digest, 'amount': amount}

                hold_code = _provider_hold_code(reply)
                if hold_code:
                    mark_status(digest, 'pending')
                    raise TemporaryHold(hold_code, digest)

                mark_status(digest, 'review')
                if http_status != 200:
                    raise PaymentError('accept_http', 'PayPay受取結果を確定できませんでした。再購入せず販売者にお問い合わせください。')
                raise PaymentError('accept_unconfirmed', 'PayPay受取結果を確認できませんでした。再購入せず販売者にお問い合わせください。')

            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
                mark_status(digest, 'review')
                raise PaymentError(
                    'accept_uncertain',
                    'PayPayの受取結果が不明です。同じリンクを再利用せず販売者にお問い合わせください。',
                ) from None
