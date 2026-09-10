"""
handlers/history.py
====================
Handler untuk melihat dan menghapus riwayat analisis pengguna.
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from database import delete_history, get_history
from utils.formatters import format_history

logger = logging.getLogger(__name__)


async def send_history(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Kirim riwayat analisis milik user (dipakai oleh /history dan menu callback)."""
    user = update.effective_user
    if not user:
        return

    records = get_history(user.id, limit=10)
    text = format_history(records)

    target_message = update.message or (update.callback_query.message if update.callback_query else None)
    if target_message:
        await target_message.reply_text(text, parse_mode=ParseMode.MARKDOWN)


async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handler untuk /history."""
    await send_history(update, context)


async def delete_history_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handler untuk /delete_history."""
    user = update.effective_user
    if not user or not update.message:
        return

    deleted_count = delete_history(user.id)
    if deleted_count > 0:
        await update.message.reply_text(
            f"🗑️ Berhasil menghapus {deleted_count} riwayat analisis Anda."
        )
    else:
        await update.message.reply_text("Anda belum memiliki riwayat analisis untuk dihapus.")
