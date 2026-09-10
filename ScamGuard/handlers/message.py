"""
handlers/message.py
====================
Handler untuk pesan teks biasa (termasuk forward message) yang dikirim
user untuk dianalisis. Jika pesan HANYA berisi satu URL, tetap diproses
di sini karena analisis teks sudah mencakup analisis URL yang ditemukan.
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from database import save_analysis
from services.analysis_pipeline import analyze_input
from utils.formatters import format_analysis_result
from utils.rate_limiter import is_rate_limited, register_request

logger = logging.getLogger(__name__)

RATE_LIMIT_MESSAGE = (
    "⏳ Terlalu banyak permintaan.\n"
    "Silakan coba lagi beberapa menit."
)


async def handle_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handler utama untuk semua pesan teks (termasuk forward).
    Terhubung ke pipeline analisis lengkap dan menyimpan hasilnya ke riwayat.
    """
    message = update.message
    user = update.effective_user
    if not message or not user or not message.text:
        return

    if is_rate_limited(user.id):
        await message.reply_text(RATE_LIMIT_MESSAGE)
        return
    register_request(user.id)

    text = message.text.strip()
    if not text:
        return

    is_forwarded = bool(message.forward_origin) if hasattr(message, "forward_origin") else bool(
        getattr(message, "forward_date", None)
    )

    processing_msg = await message.reply_text("🔎 Menganalisis pesan Anda, mohon tunggu...")

    try:
        assessment = await analyze_input(text=text)
    except Exception:  # noqa: BLE001 - lapisan pengaman terakhir agar bot tidak mati
        logger.exception("Kesalahan tak terduga saat menganalisis pesan teks")
        await processing_msg.edit_text(
            "⚠️ Maaf, terjadi kesalahan saat menganalisis pesan Anda. "
            "Silakan coba lagi beberapa saat lagi."
        )
        return

    input_type = "forward" if is_forwarded else "text"
    try:
        save_analysis(
            user_id=user.id,
            input_type=input_type,
            risk_score=assessment.risk_score,
            risk_level=assessment.risk_level,
            verdict=assessment.verdict,
        )
    except Exception:  # noqa: BLE001
        logger.exception("Gagal menyimpan riwayat analisis ke database")

    result_text = format_analysis_result(assessment)
    await processing_msg.edit_text(result_text, parse_mode=ParseMode.MARKDOWN)
