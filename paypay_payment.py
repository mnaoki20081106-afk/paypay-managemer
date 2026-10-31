"""PayPay P2P link receipt for a named account.

Adapted from paypayu.py (zip1) to support multi-account usage.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import sqlite3
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import aiohttp

import paypay_auth
from paypay_auth import PayPayAuthError

LOG = logging.getLogger("paypay.payment")

ROOT = Path(__file__).resolve().parent
LEDGER = ROOT / "data" / "payments.sqlite3"

LINK_CHECK = "https://www.paypay.ne.jp/app/v2/p2p-api/getP2PLinkInfo"
LINK_ACCEPT = "https://www.paypay.ne.jp/app/v2/p2p-api/acceptP2PSendMoneyLink"
LINK_RE = re.compile(
    r"https://pay\.paypay\.ne\.jp/([A-Za-z0-9]{6,128})(?![A-Za-z0-9])", re.I
)
CODE_RE = re.compile(r"[A-Za-z0-9]{6,128}\Z")
HOLD_CODES = frozenset({"42007013", "42007014", "42007015", "42007016"})
_LOCK = asyncio.Lock()


class PaymentError(Exception):
    def __init__(self, kind: str, message: str):
        super().__init__(kind)
        self.kind = kind
        self.message = message


class TemporaryHold(PaymentError):
    def __init__(self, code: str, payment_id: str):
        super().__init__("temporary_hold",
                         "PayPay側で一時保留になっています。アプリで確認してください。")
        self.provider_code = code
        self.payment_id = payment_id


@contextmanager
def _db():
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(LEDGER, timeout=20)
    if os.name != "nt":
        os.chmod(LEDGER, 0o600)
    try:
        conn.execute("PRAGMA busy_timeout=20000")
        conn.execute("""CREATE TABLE IF NOT EXISTS payments (
            code_hash TEXT PRIMARY KEY,
            order_id TEXT NOT NULL UNIQUE,
            purchase_id TEXT NOT NULL UNIQUE,
            account_phone TEXT NOT NULL,
            status TEXT NOT NULL,
            amount INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def normalize_link(raw: str) -> str | None:
    if not isinstance(raw, str) or not 1 <= len(raw) <= 4000:
        return None
    raw = raw.strip()
    if CODE_RE.fullmatch(raw):
        return raw
    urls = LINK_RE.findall(raw)
    if not urls or len(set(urls)) != 1:
        return None
    return urls[0]


def _hold_code(body: object) -> str | None:
    if not isinstance(body, dict):
        return None
    candidates = []
    def collect(obj):
        if not isinstance(obj, dict):
            return
        for f in ("resultCode", "result_code", "errorCode", "error_code", "code"):
            v = obj.get(f)
            if type(v) in (str, int):
                candidates.append(str(v))
    collect(body)
    for k in ("header", "error", "result_info"):
        collect(body.get(k))
    for c in candidates:
        if c in HOLD_CODES:
            return c
    return None


def _parse_iso(v: str):
    if not isinstance(v, str):
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
        return d if d.tzinfo else None
    except ValueError:
        return None


def _validate_link_info(body: object, amount: int) -> dict:
    if not isinstance(body, dict) or (body.get("header") or {}).get("resultCode") != "S0000":
        raise PaymentError("invalid_link", "PayPayリンクを確認できませんでした。")
    p = body.get("payload")
    if not isinstance(p, dict) or p.get("orderStatus") != "PENDING":
        raise PaymentError("not_pending", "このリンクは未受取状態ではありません。")
    info = p.get("pendingP2PInfo")
    message = p.get("message")
    if not isinstance(info, dict) or not isinstance(message, dict):
        raise PaymentError("missing_fields", "送金リンクの情報が不足しています。")
    if type(info.get("amount")) is not int or info["amount"] != amount or amount < 1:
        raise PaymentError("amount_mismatch", f"金額が一致しません（リンク: {info.get('amount')}円）。")
    if info.get("isLinkBlocked") is not False or info.get("isSetPasscode") is not False:
        raise PaymentError("blocked_or_passcode", "ブロック中またはパスコード付きリンクです。")
    expires_at = _parse_iso(info.get("expiredAt"))
    if expires_at is None or expires_at <= datetime.now(timezone.utc):
        raise PaymentError("expired", "リンクの有効期限が切れています。")
    receiver = p.get("receiver")
    sender = p.get("sender")
    if not isinstance(receiver, dict) or not isinstance(sender, dict):
        raise PaymentError("identity_missing", "送金元・受取先を確認できませんでした。")
    receiver_id = receiver.get("externalId")
    sender_id = sender.get("externalId")
    if not all(isinstance(x, str) and x for x in (receiver_id, sender_id)):
        raise PaymentError("identity_missing", "送金元・受取先の情報が不足しています。")
    if sender_id == receiver_id:
        raise PaymentError("self_payment", "送金元と受取先が同じリンクは使えません。")
    data = message.get("data")
    if not isinstance(data, dict):
        raise PaymentError("message_missing", "リンクのメッセージ情報が不足しています。")
    order_id = info.get("orderId")
    if (not isinstance(order_id, str) or not order_id
            or data.get("orderId") != order_id
            or data.get("amount") != amount
            or data.get("status") != "PENDING"):
        raise PaymentError("order_mismatch", "リンクの注文情報が一致しません。")
    msg_id = message.get("messageId")
    chat_id = message.get("chatRoomId")
    tx_at = data.get("transactionAt")
    if not all(isinstance(v, str) and v for v in (msg_id, chat_id, tx_at)):
        raise PaymentError("message_incomplete", "受取パラメータが不足しています。")
    return {
        "order_id": order_id, "message_id": msg_id, "chat_id": chat_id,
        "request_at": tx_at, "amount": amount,
        "sender_id": sender_id, "receiver_id": receiver_id,
    }


def _reserve(code: str, order_id: str, purchase_id: str,
             amount: int, phone: str) -> str:
    digest = hashlib.sha256(code.encode()).hexdigest()
    with _db() as conn:
        try:
            conn.execute(
                "INSERT INTO payments(code_hash,order_id,purchase_id,account_phone,status,amount) "
                "VALUES (?,?,?,?,?,?)",
                (digest, order_id, purchase_id, phone, "attempted", amount),
            )
        except sqlite3.IntegrityError:
            raise PaymentError(
                "duplicate",
                "このリンクは既に処理中または使用済みです。"
            )
    return digest


def _mark(digest: str, status: str):
    with _db() as conn:
        conn.execute(
            "UPDATE payments SET status=?,updated_at=CURRENT_TIMESTAMP "
            "WHERE code_hash=?",
            (status, digest),
        )


def list_payments(limit: int = 50) -> list[dict]:
    with _db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS payments (
            code_hash TEXT PRIMARY KEY,
            order_id TEXT NOT NULL UNIQUE,
            purchase_id TEXT NOT NULL UNIQUE,
            account_phone TEXT NOT NULL,
            status TEXT NOT NULL,
            amount INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        conn.commit()
        rows = conn.execute(
            "SELECT order_id,account_phone,status,amount,created_at,updated_at "
            "FROM payments ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(zip(
        ["order_id", "phone", "status", "amount", "created_at", "updated_at"], r
    )) for r in rows]


async def receive_link(phone: str, raw_link: str, amount: int,
                       purchase_id: str | None = None) -> dict:
    """Accept a P2P payment link for the given account phone.

    Returns {status: 'paid', payment_id, amount} on success.
    """
    code = normalize_link(raw_link)
    if not code:
        raise PaymentError("bad_link", "PayPay送金リンクが正しくありません。")
    if amount < 1:
        raise PaymentError("bad_amount", "金額は1円以上を指定してください。")
    pid = purchase_id or str(uuid4())
    async with _LOCK:
        session = paypay_auth.get_session(phone)
        if not session:
            raise PaymentError(
                "login_required",
                f"{phone} のPayPayセッションが有効ではありません。再ログインしてください。"
            )
        referer = (
            f"https://www.paypay.ne.jp/app/p2p/{code}"
            f"?pid=SMS&link_key={code}"
            "&af_dp=paypay%3A%2F%2Fpending%2Fdetail%3Fsource%3Dsns_link"
        )
        from paypay_auth import _browser_headers
        headers = _browser_headers(referer)
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=25),
            headers=headers,
            cookies={"token": session["session_cookie"]},
        ) as http:
            try:
                async with http.get(
                    LINK_CHECK,
                    params={"verificationCode": code, "client_uuid": session["uuid"]},
                ) as resp:
                    if resp.status != 200:
                        raise PaymentError("link_http", "リンク確認に失敗しました。")
                    body = await resp.json(content_type=None)
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
                raise PaymentError("link_network", "リンク確認で通信エラーが発生しました。")
            verified = _validate_link_info(body, amount)
            digest = _reserve(code, verified["order_id"], pid, amount, phone)
            payload = {
                "requestAt": verified["request_at"],
                "orderId": verified["order_id"],
                "requestId": str(uuid4()).upper(),
                "senderChannelUrl": verified["chat_id"],
                "senderMessageId": verified["message_id"],
                "verificationCode": code,
                "client_uuid": session["uuid"],
                "iosMinimumVersion": "3.45.0",
                "androidMinimumVersion": "3.45.0",
            }
            try:
                async with http.post(LINK_ACCEPT, json=payload) as resp:
                    http_status = resp.status
                    try:
                        reply = await resp.json(content_type=None)
                    except (ValueError, aiohttp.ContentTypeError):
                        reply = None
            except (aiohttp.ClientError, asyncio.TimeoutError):
                _mark(digest, "review")
                raise PaymentError(
                    "accept_uncertain",
                    "受取結果が不明です。同じリンクを再利用せずに確認してください。"
                )
            if (http_status == 200
                    and isinstance(reply, dict)
                    and isinstance(reply.get("header"), dict)
                    and reply["header"].get("resultCode") == "S0000"
                    and isinstance(reply.get("payload"), dict)
                    and reply["payload"].get("orderStatus") == "COMPLETED"):
                _mark(digest, "paid")
                return {"status": "paid", "payment_id": digest, "amount": amount}
            hold = _hold_code(reply)
            if hold:
                _mark(digest, "pending")
                raise TemporaryHold(hold, digest)
            _mark(digest, "review")
            raise PaymentError(
                "accept_unconfirmed",
                "受取結果を確認できませんでした。再購入せず確認してください。"
            )
