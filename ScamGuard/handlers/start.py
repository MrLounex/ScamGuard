"""
handlers/start.py
==================
Handler untuk command /start, /help, dan /privacy, serta menu utama
dalam bentuk InlineKeyboardButton.
"""

from __future__ import annotations

import logging

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

logger = logging.getLogger(__name__)

WELCOME_TEXT = (
    "🛡️ *ScamGuard*\n\n"
    "Saya membantu mendeteksi indikasi penipuan dari:\n\n"
    "🔗 Link\n"
    "💬 Pesan\n"
    "📸 Screenshot\n"
    "📄 Informasi transaksi\n\n"
    "Pilih menu di bawah, atau langsung kirim pesan/link/screenshot "
    "yang ingin dianalisis."
)

HELP_TEXT = (
    "ℹ️ *Bantuan ScamGuard*\n\n"
    "Cara pakai:\n"
    "1️⃣ Kirim pesan teks mencurigakan langsung ke chat ini\n"
    "2️⃣ Kirim link/URL yang ingin dicek\n"
    "3️⃣ Kirim screenshot percakapan/transaksi\n"
    "4️⃣ Forward pesan dari orang lain ke chat ini\n\n"
    "*Perintah tersedia:*\n"
    "/start — Tampilkan menu utama\n"
    "/help — Tampilkan bantuan ini\n"
    "/history — Lihat riwayat analisis Anda\n"
    "/delete_history — Hapus seluruh riwayat analisis Anda\n"
    "/privacy — Kebijakan privasi bot ini\n\n"
    "⚠️ Hasil analisis bersifat *indikasi*, bukan kepastian mutlak. "
    "Selalu lakukan verifikasi mandiri melalui kanal resmi."
)

PRIVACY_TEXT = (
    "🔒 *Kebijakan Privasi ScamGuard*\n\n"
    "• Kami TIDAK menyimpan isi pesan, screenshot, OTP, password, atau PIN Anda.\n"
    "• Screenshot yang Anda kirim diproses sementara untuk OCR, lalu file "
    "dihapus segera setelah analisis selesai.\n"
    "• Yang kami simpan hanya metadata ringkas: waktu, jenis input, dan "
    "skor/level risiko — untuk fitur riwayat (/history).\n"
    "• Anda dapat menghapus seluruh riwayat kapan saja dengan /delete_history.\n\n"
    "⚠️ *Penting:* Jangan pernah mengirimkan OTP, password, PIN, atau data "
    "sensitif lain ke bot mana pun, termasuk bot ini, kecuali benar-benar "
    "diperlukan untuk analisis dan Anda memahami risikonya."
)


def build_main_menu() -> InlineKeyboardMarkup:
    """Bangun keyboard menu utama."""
    keyboard = [
        [InlineKeyboardButton("🔍 Analisis Pesan", callback_data="menu_analyze_text")],
        [InlineKeyboardButton("🔗 Cek Link", callback_data="menu_check_url")],
        [InlineKeyboardButton("📸 Analisis Screenshot", callback_data="menu_analyze_photo")],
        [InlineKeyboardButton("📜 Riwayat", callback_data="menu_history")],
        [InlineKeyboardButton("ℹ️ Bantuan", callback_data="menu_help")],
    ]
    return InlineKeyboardMarkup(keyboard)


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handler untuk /start."""
    if not update.message:
        return
    await update.message.reply_text(
        WELCOME_TEXT,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=build_main_menu(),
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handler untuk /help."""
    if not update.message:
        return
    await update.message.reply_text(HELP_TEXT, parse_mode=ParseMode.MARKDOWN)


async def privacy_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handler untuk /privacy."""
    if not update.message:
        return
    await update.message.reply_text(PRIVACY_TEXT, parse_mode=ParseMode.MARKDOWN)


async def menu_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handler untuk tombol-tombol pada menu utama (InlineKeyboard callback)."""
    query = update.callback_query
    if not query or not query.data:
        return
    await query.answer()

    prompts = {
        "menu_analyze_text": (
            "💬 Silakan kirim pesan teks yang ingin Anda analisis "
            "(bisa juga forward pesan dari chat lain)."
        ),
        "menu_check_url": "🔗 Silakan kirim link/URL yang ingin Anda cek.",
        "menu_analyze_photo": (
            "📸 Silakan kirim screenshot atau foto (misalnya bukti transfer/invoice) "
            "yang ingin dianalisis."
        ),
        "menu_help": HELP_TEXT,
    }

    if query.data == "menu_history":
        # Impor lokal untuk menghindari circular import antar handler.
        from handlers.history import send_history

        await send_history(update, context)
        return

    text = prompts.get(query.data)
    if text and query.message:
        parse_mode = ParseMode.MARKDOWN if query.data == "menu_help" else None
        await query.message.reply_text(text, parse_mode=parse_mode)
