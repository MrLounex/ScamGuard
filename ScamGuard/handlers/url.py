"""
handlers/url.py
================
Handler khusus untuk permintaan pengecekan URL secara eksplisit
(mis. ketika user menekan tombol "Cek Link" lalu mengirim URL, atau
mengirim pesan yang murni berisi satu URL).

Catatan: handlers/message.py juga sudah mendeteksi & menganalisis URL
yang ada di dalam teks bebas. Handler ini memberikan format hasil yang
lebih berfokus pada detail URL saja, dan dapat dipakai bila Anda ingin
memisahkan alur "cek link" dari "analisis pesan umum" di masa depan.
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from database import save_analysis
from services import url_checker
from services.risk_engine import assess
from utils.formatters import format_analysis_result
from utils.rate_limiter import is_rate_limited, register_request
from utils.validators import extract_urls

logger = logging.getLogger(__name__)

RATE_LIMIT_MESSAGE = (
    "⏳ Terlalu banyak permintaan.\n"
    "Silakan coba lagi beberapa menit."
)


async def handle_url_check(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handler untuk pengecekan URL secara eksplisit.
    Dapat dipanggil langsung jika Anda mendaftarkan handler terpisah untuk
    kasus "user hanya mengirim satu URL tanpa teks lain".
    """
    message = update.message
    user = update.effective_user
    if not message or not user or not message.text:
        return

    if is_rate_limited(user.id):
        await message.reply_text(RATE_LIMIT_MESSAGE)
        return
    register_request(user.id)

    urls = extract_urls(message.text)
    if not urls:
        await message.reply_text(
            "Saya tidak menemukan URL yang valid pada pesan Anda. "
            "Silakan kirim link yang ingin diperiksa."
        )
        return

    processing_msg = await message.reply_text("🔎 Memeriksa link Anda, mohon tunggu...")

    all_signals: list[str] = []
    detail_lines: list[str] = []

    for target_url in urls:
        try:
            result = await url_checker.analyze(target_url)
        except Exception:  # noqa: BLE001
            logger.exception("Gagal memeriksa URL %s", target_url)
            detail_lines.append(f"• {target_url} — gagal diperiksa")
            continue

        for signal in result.signals:
            if signal not in all_signals:
                all_signals.append(signal)

        if result.error:
            detail_lines.append(f"• {target_url} — {result.error}")

    assessment = assess(all_signals, has_sufficient_evidence=True)

    try:
        save_analysis(
            user_id=user.id,
            input_type="url",
            risk_score=assessment.risk_score,
            risk_level=assessment.risk_level,
            verdict=assessment.verdict,
        )
    except Exception:  # noqa: BLE001
        logger.exception("Gagal menyimpan riwayat analisis URL ke database")

    result_text = format_analysis_result(assessment)
    if detail_lines:
        result_text += "\n\n" + "\n".join(detail_lines)

    await processing_msg.edit_text(result_text, parse_mode=ParseMode.MARKDOWN)
