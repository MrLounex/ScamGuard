"""
database.py
============
Lapisan persistence menggunakan SQLite (melalui sqlite3 standar library).

PRIVASI: Secara default, database HANYA menyimpan metadata analisis
(user_id, timestamp, jenis input, skor risiko, level risiko, verdict).
Isi pesan asli / file screenshot TIDAK disimpan permanen.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from config import settings

logger = logging.getLogger(__name__)


def _resolve_db_path() -> str:
    """Ubah DATABASE_URL bergaya 'sqlite:///namafile.db' menjadi path file."""
    url = settings.database_url
    prefix = "sqlite:///"
    if url.startswith(prefix):
        return url[len(prefix):]
    # Jika sudah berupa path biasa, gunakan langsung.
    return url or "scamguard.db"


DB_PATH = _resolve_db_path()

SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    input_type TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    verdict TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_analysis_history_user_id
    ON analysis_history (user_id);

CREATE TABLE IF NOT EXISTS rate_limit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    timestamp INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_events_user_id
    ON rate_limit_events (user_id, timestamp);
"""


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    """Context manager koneksi SQLite yang aman (auto commit/rollback/close)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Inisialisasi skema database. Aman dipanggil berkali-kali (idempotent)."""
    with get_connection() as conn:
        conn.executescript(SCHEMA)
    logger.info("Database siap di: %s", DB_PATH)


@dataclass
class AnalysisRecord:
    """Representasi satu baris riwayat analisis."""

    id: Optional[int]
    user_id: int
    timestamp: int
    input_type: str
    risk_score: int
    risk_level: str
    verdict: str


def save_analysis(
    user_id: int,
    input_type: str,
    risk_score: int,
    risk_level: str,
    verdict: str,
) -> None:
    """Simpan satu hasil analisis ke riwayat (tanpa menyimpan isi pesan asli)."""
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO analysis_history
                (user_id, timestamp, input_type, risk_score, risk_level, verdict)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, int(time.time()), input_type, risk_score, risk_level, verdict),
        )


def get_history(user_id: int, limit: int = 10) -> list[AnalysisRecord]:
    """Ambil riwayat analisis terbaru milik seorang user."""
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, user_id, timestamp, input_type, risk_score, risk_level, verdict
            FROM analysis_history
            WHERE user_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
    return [
        AnalysisRecord(
            id=row["id"],
            user_id=row["user_id"],
            timestamp=row["timestamp"],
            input_type=row["input_type"],
            risk_score=row["risk_score"],
            risk_level=row["risk_level"],
            verdict=row["verdict"],
        )
        for row in rows
    ]


def delete_history(user_id: int) -> int:
    """Hapus seluruh riwayat analisis milik seorang user. Mengembalikan jumlah baris dihapus."""
    with get_connection() as conn:
        cursor = conn.execute(
            "DELETE FROM analysis_history WHERE user_id = ?",
            (user_id,),
        )
        return cursor.rowcount


def record_rate_limit_event(user_id: int) -> None:
    """Catat satu event request untuk keperluan rate limiting."""
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO rate_limit_events (user_id, timestamp) VALUES (?, ?)",
            (user_id, int(time.time())),
        )


def count_recent_requests(user_id: int, window_seconds: int) -> int:
    """Hitung jumlah request user dalam window waktu tertentu (detik)."""
    cutoff = int(time.time()) - window_seconds
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS cnt FROM rate_limit_events
            WHERE user_id = ? AND timestamp >= ?
            """,
            (user_id, cutoff),
        ).fetchone()
    return int(row["cnt"]) if row else 0


def cleanup_old_rate_limit_events(older_than_seconds: int = 86400) -> None:
    """Bersihkan event rate-limit lama agar tabel tidak membengkak."""
    cutoff = int(time.time()) - older_than_seconds
    with get_connection() as conn:
        conn.execute("DELETE FROM rate_limit_events WHERE timestamp < ?", (cutoff,))
