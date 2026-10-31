"""Minimal SQLite store for SMS number purchases.

Tracks service_key alongside each order so cancel() always has it.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

DB_PATH = Path(__file__).parent / 'sms_numbers.sqlite3'


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS sms_numbers (
            order_id    TEXT PRIMARY KEY,
            service_key TEXT NOT NULL,
            country_id  INTEGER NOT NULL DEFAULT 182,
            phone       TEXT NOT NULL,
            expires_at  INTEGER,
            created_at  INTEGER NOT NULL
        )
    ''')
    conn.commit()
    return conn


def save_number(order_id: str, service_key: str, country_id: int, phone: str,
                expires_at: int | None) -> None:
    with _connect() as conn:
        conn.execute(
            '''INSERT OR REPLACE INTO sms_numbers
               (order_id, service_key, country_id, phone, expires_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (order_id, service_key, country_id, phone, expires_at, int(time.time())),
        )


def get_number(order_id: str) -> dict | None:
    conn = _connect()
    row = conn.execute(
        'SELECT * FROM sms_numbers WHERE order_id = ?', (order_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def delete_number(order_id: str) -> None:
    with _connect() as conn:
        conn.execute('DELETE FROM sms_numbers WHERE order_id = ?', (order_id,))
