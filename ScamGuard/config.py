"""
config.py
=========
Memuat konfigurasi aplikasi dari environment variables (.env).

Semua nilai sensitif (token, API key) HARUS diisi melalui file `.env`.
Jangan pernah hardcode nilai-nilai ini langsung di source code.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

# Muat file .env dari root project (jika ada)
load_dotenv()

logger = logging.getLogger(__name__)


def _get_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    try:
        return int(value)
    except ValueError:
        logger.warning("Nilai %s tidak valid, menggunakan default %s", name, default)
        return default


@dataclass(frozen=True)
class Settings:
    """Kumpulan konfigurasi aplikasi ScamGuard Bot."""

    # --- Telegram ---
    telegram_bot_token: str = field(default_factory=lambda: os.getenv("TELEGRAM_BOT_TOKEN", ""))

    # --- AI / LLM provider ---
    ai_api_key: str = field(default_factory=lambda: os.getenv("AI_API_KEY", ""))
    ai_model: str = field(default_factory=lambda: os.getenv("AI_MODEL", "gpt-4o-mini"))
    ai_provider: str = field(default_factory=lambda: os.getenv("AI_PROVIDER", "openai"))
    ai_base_url: str = field(default_factory=lambda: os.getenv("AI_BASE_URL", "https://api.openai.com/v1"))

    # --- Database ---
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///scamguard.db"))

    # --- Upload limits ---
    max_file_size_mb: int = field(default_factory=lambda: _get_int("MAX_FILE_SIZE_MB", 10))

    # --- Rate limiting ---
    rate_limit_requests: int = field(default_factory=lambda: _get_int("RATE_LIMIT_REQUESTS", 10))
    rate_limit_window_seconds: int = field(
        default_factory=lambda: _get_int("RATE_LIMIT_WINDOW_SECONDS", 600)
    )

    # --- URL reputation provider (opsional) ---
    url_reputation_api_key: str = field(
        default_factory=lambda: os.getenv("URL_REPUTATION_API_KEY", "")
    )
    url_reputation_provider: str = field(
        default_factory=lambda: os.getenv("URL_REPUTATION_PROVIDER", "none")
    )

    # --- Logging ---
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))

    def validate(self) -> None:
        """Validasi konfigurasi wajib. Melempar RuntimeError jika ada yang kosong."""
        missing = []
        if not self.telegram_bot_token:
            missing.append("TELEGRAM_BOT_TOKEN")
        if missing:
            raise RuntimeError(
                "Environment variable berikut belum diisi di file .env: "
                + ", ".join(missing)
                + ". Salin .env.example menjadi .env lalu isi nilainya."
            )
        if not self.ai_api_key:
            logger.warning(
                "AI_API_KEY belum diisi. Bot akan tetap berjalan menggunakan "
                "rule-based detection saja (tanpa analisis AI)."
            )


settings = Settings()


def configure_logging() -> None:
    """Konfigurasi logging global. Tidak pernah mencetak data sensitif."""
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )
    # Redam log verbose dari library pihak ketiga
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("telegram").setLevel(logging.WARNING)
