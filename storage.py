"""Encrypted multi-account storage for PayPay credentials."""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
DB = DATA / "accounts.sqlite3"
KEY_FILE = DATA / "storage.key"


def _cipher() -> Fernet:
    DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not KEY_FILE.exists():
        fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(Fernet.generate_key())
        except BaseException:
            KEY_FILE.unlink(missing_ok=True)
            raise
    return Fernet(KEY_FILE.read_bytes().strip())


@contextmanager
def _db():
    DATA.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB, timeout=20)
    conn.row_factory = sqlite3.Row
    if os.name != "nt":
        os.chmod(DB, 0o600)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=20000")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS accounts (
                phone TEXT PRIMARY KEY,
                credentials BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )"""
        )
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def save_account(phone: str, data: dict) -> None:
    now = int(time.time())
    enc = _cipher().encrypt(json.dumps(data, ensure_ascii=False).encode())
    with _db() as conn:
        conn.execute(
            "INSERT INTO accounts(phone, credentials, created_at, updated_at) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(phone) DO UPDATE SET "
            "credentials=excluded.credentials, updated_at=excluded.updated_at",
            (phone, enc, now, now),
        )


def load_account(phone: str) -> dict | None:
    with _db() as conn:
        row = conn.execute(
            "SELECT credentials FROM accounts WHERE phone=?", (phone,)
        ).fetchone()
    if row is None:
        return None
    return json.loads(_cipher().decrypt(row["credentials"]))


def list_phones() -> list[str]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT phone FROM accounts ORDER BY created_at"
        ).fetchall()
    return [r["phone"] for r in rows]


def delete_account(phone: str) -> bool:
    with _db() as conn:
        cur = conn.execute("DELETE FROM accounts WHERE phone=?", (phone,))
        return cur.rowcount == 1
