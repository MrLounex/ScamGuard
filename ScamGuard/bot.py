"""
bot.py
======
Entry point utama ScamGuard Bot.

Menjalankan bot dengan menjalankan:
    python bot.py

Pastikan file .env sudah dikonfigurasi terlebih dahulu (lihat .env.example
dan README.md untuk instruksi lengkap).
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from config import configure_logging, settings
from database import cleanup_old_rate_limit_events, init_db
from handlers.history import delete_history_command, history_command
from handlers.message import handle_text_message
from handlers.photo import handle_photo_message
from handlers.start import help_command, menu_callback_handler, privacy_command, start_command

configure_logging()
logger = logging.getLogger(__name__)


async def _on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Global error handler. Menangkap seluruh exception yang tidak tertangani
    di level handler agar bot TIDAK mati, dan mencatatnya ke log tanpa
    membocorkan data sensitif (mis. isi pesan user atau API key).
    """
    logger.error("Unhandled exception saat memproses update", exc_info=context.error)

    if isinstance(update, Update) and update.effective_message:
        try:
            await update.effective_message.reply_text(
                "⚠️ Maaf, terjadi kesalahan tak terduga. Tim kami akan segera "
                "memeriksanya. Silakan coba lagi beberapa saat."
            )
        except Exception:  # noqa: BLE001 - jangan sampai error handler sendiri crash
            logger.exception("Gagal mengirim pesan error ke user")


async def _post_init(application: Application) -> None:
    """Dijalankan sekali setelah aplikasi siap, sebelum polling dimulai."""
    init_db()
    cleanup_old_rate_limit_events()
    logger.info("ScamGuard Bot siap berjalan.")


def build_application() -> Application:
    """Bangun dan konfigurasikan instance Application dari python-telegram-bot."""
    settings.validate()

    application = (
        Application.builder()
        .token(settings.telegram_bot_token)
        .post_init(_post_init)
        .build()
    )

    # --- Command handlers ---
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("privacy", privacy_command))
    application.add_handler(CommandHandler("history", history_command))
    application.add_handler(CommandHandler("delete_history", delete_history_command))

    # --- Callback query handler (tombol menu) ---
    application.add_handler(CallbackQueryHandler(menu_callback_handler))

    # --- Message handlers ---
    # Foto (screenshot / bukti transfer)
    application.add_handler(MessageHandler(filters.PHOTO, handle_photo_message))
    # Teks bebas (termasuk forward & link yang ditulis sebagai teks)
    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_message)
    )

    # --- Global error handler ---
    application.add_error_handler(_on_error)

    return application


def main() -> None:
    """Titik masuk utama aplikasi."""
    application = build_application()
    logger.info("Menjalankan ScamGuard Bot (polling mode)...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
