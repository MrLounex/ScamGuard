"""
utils/rate_limiter.py
======================
Rate limiting sederhana berbasis database (SQLite) agar konfigurasi
tetap konsisten walau bot di-restart, dan agar tidak perlu dependency
tambahan seperti Redis untuk kasus penggunaan skala kecil-menengah.
"""

from __future__ import annotations

from config import settings
from database import count_recent_requests, record_rate_limit_event


def is_rate_limited(user_id: int) -> bool:
    """Cek apakah user sudah melebihi batas request dalam window waktu berjalan."""
    count = count_recent_requests(user_id, settings.rate_limit_window_seconds)
    return count >= settings.rate_limit_requests


def register_request(user_id: int) -> None:
    """Catat satu request baru dari user (dipanggil setelah lolos pengecekan limit)."""
    record_rate_limit_event(user_id)
