"""
handlers/photo.py
==================
Handler untuk foto/screenshot yang dikirim user (percakapan mencurigakan,
bukti transfer, invoice, dll).

Alur:
1. Validasi ukuran file (MAX_FILE_SIZE_MB dari .env).
2. Download foto ke file sementara.
3. Jalankan OCR untuk mengekstrak teks.
4. Hapus file sementara SEGERA setelah OCR selesai (privacy-first).
5. Jalankan pipeline analisis terhadap teks hasil OCR.
6. Simpan hanya metadata hasil analisis ke database (bukan isi gambar/teks).
"""

from __future__ import annotations

import logging
import os
import tempfile

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from config import settings
from database import save_analysis
from services.analysis_pipeline import analyze_input
from services.ocr_service import run_ocr
from utils.formatters import format_analysis_result
from utils.rate_limiter import is_rate_limited, register_request

logger = logging.getLogger(__name__)

RATE_LIMIT_MESSAGE = (
    "⏳ Terlalu banyak permintaan.\n"
    "Silakan coba lagi beberapa menit."
)


async def handle_photo_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handler utama untuk foto/screenshot yang dikirim user."""
    message = update.message
    user = update.effective_user
    if not message or not user or not message.photo:
        return

    if is_rate_limited(user.id):
        await message.reply_text(RATE_LIMIT_MESSAGE)
        return
    register_request(user.id)

    # Ambil resolusi tertinggi yang tersedia (elemen terakhir dalam list photo).
    photo = message.photo[-1]

    max_size_bytes = settings.max_file_size_mb * 1024 * 1024
    if photo.file_size and photo.file_size > max_size_bytes:
        await message.reply_text(
            f"⚠️ Ukuran file terlalu besar (maksimal {settings.max_file_size_mb} MB). "
            "Silakan kirim gambar dengan ukuran lebih kecil."
        )
        return

    processing_msg = await message.reply_text("📸 Memproses screenshot Anda, mohon tunggu...")

    temp_path: str | None = None
    try:
        telegram_file = await photo.get_file()

        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
            temp_path = tmp.name

        await telegram_file.download_to_drive(custom_path=temp_path)

        ocr_result = run_ocr(temp_path)

    except Exception:  # noqa: BLE001
        logger.exception("Gagal mengunduh atau memproses foto")
        await processing_msg.edit_text(
            "⚠️ Maaf, terjadi kesalahan saat mengunduh/memproses gambar Anda. "
            "Silakan coba lagi."
        )
        return
    finally:
        # PRIVASI: selalu hapus file sementara, apa pun hasilnya.
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                logger.warning("Gagal menghapus file sementara: %s", temp_path)

    if not ocr_result.success:
        await processing_msg.edit_text(f"⚠️ {ocr_result.error}")
        return

    try:
        assessment = await analyze_input(ocr_text=ocr_result.text)
    except Exception:  # noqa: BLE001
        logger.exception("Kesalahan tak terduga saat menganalisis hasil OCR")
        await processing_msg.edit_text(
            "⚠️ Maaf, terjadi kesalahan saat menganalisis screenshot Anda. "
            "Silakan coba lagi beberapa saat lagi."
        )
        return

    try:
        save_analysis(
            user_id=user.id,
            input_type="photo",
            risk_score=assessment.risk_score,
            risk_level=assessment.risk_level,
            verdict=assessment.verdict,
        )
    except Exception:  # noqa: BLE001
        logger.exception("Gagal menyimpan riwayat analisis foto ke database")

    result_text = format_analysis_result(assessment)
    await processing_msg.edit_text(result_text, parse_mode=ParseMode.MARKDOWN)
