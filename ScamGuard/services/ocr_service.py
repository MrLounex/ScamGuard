"""
services/ocr_service.py
========================
Layanan OCR (Optical Character Recognition) untuk membaca teks dari
screenshot/foto yang dikirim user.

Menggunakan library `pytesseract` (wrapper Python untuk Tesseract OCR).

INSTALASI DEPENDENCY (di luar pip install):
- Windows: unduh & install Tesseract dari
  https://github.com/UB-Mannheim/tesseract/wiki lalu tambahkan folder
  instalasinya (mis. C:\\Program Files\\Tesseract-OCR) ke PATH, atau set
  TESSERACT_CMD di .env agar aplikasi tahu lokasinya.
- Linux (Debian/Ubuntu): sudo apt-get install tesseract-ocr
- Linux (bahasa Indonesia): sudo apt-get install tesseract-ocr-ind

Jika Tesseract tidak ditemukan di sistem, fungsi run_ocr akan mengembalikan
error yang jelas alih-alih membuat bot crash.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)

try:
    import pytesseract
    pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    from PIL import Image

    _OCR_AVAILABLE = True
except ImportError:  # pragma: no cover - tergantung environment instalasi
    _OCR_AVAILABLE = False
    logger.warning(
        "Library OCR (pytesseract/Pillow) tidak ditemukan. "
        "Jalankan 'pip install pytesseract Pillow' untuk mengaktifkan fitur OCR."
    )

# Jika di-set, arahkan pytesseract ke lokasi binary tesseract secara eksplisit.
_TESSERACT_CMD = os.getenv("TESSERACT_CMD")
if _OCR_AVAILABLE and _TESSERACT_CMD:
    pytesseract.pytesseract.tesseract_cmd = _TESSERACT_CMD


@dataclass
class OCRResult:
    """Hasil proses OCR terhadap sebuah gambar."""

    success: bool
    text: str = ""
    error: str | None = None


def is_ocr_available() -> bool:
    """Cek apakah dependency OCR terpasang dengan benar."""
    return _OCR_AVAILABLE


def run_ocr(image_path: str, languages: str = "ind+eng") -> OCRResult:
    """
    Jalankan OCR terhadap file gambar di `image_path`.

    Args:
        image_path: path file gambar sementara (lihat handlers/photo.py untuk
            bagaimana file diunduh & dibersihkan setelah diproses).
        languages: kode bahasa Tesseract, default Indonesia + Inggris.

    Returns:
        OCRResult berisi teks hasil ekstraksi atau pesan error yang jelas.
    """
    if not _OCR_AVAILABLE:
        return OCRResult(
            success=False,
            error=(
                "Fitur OCR belum aktif di server ini. Library 'pytesseract' "
                "dan/atau Tesseract OCR belum terpasang. Silakan hubungi admin bot."
            ),
        )

    if not os.path.exists(image_path):
        return OCRResult(success=False, error="File gambar tidak ditemukan.")

    try:
        with Image.open(image_path) as img:
            text = pytesseract.image_to_string(img, lang=languages)
        text = text.strip()
        if not text:
            return OCRResult(
                success=False,
                error=(
                    "Tidak ada teks yang terbaca dari gambar. Pastikan "
                    "screenshot jelas, tidak buram, dan berisi teks."
                ),
            )
        return OCRResult(success=True, text=text)
    except pytesseract.TesseractNotFoundError:
        logger.error("Tesseract OCR tidak ditemukan di sistem (binary tidak ada di PATH).")
        return OCRResult(
            success=False,
            error=(
                "Tesseract OCR tidak terpasang di server. Silakan install "
                "Tesseract OCR sesuai instruksi di README, lalu restart bot."
            ),
        )
    except Exception as exc:  # noqa: BLE001 - jangan sampai OCR error meng-crash bot
        logger.exception("Kesalahan tak terduga saat menjalankan OCR")
        return OCRResult(
            success=False,
            error=f"Terjadi kesalahan saat memproses gambar: {type(exc).__name__}",
        )
