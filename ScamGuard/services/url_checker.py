"""
services/url_checker.py
========================
Pemeriksaan URL: validasi dasar (sintaksis) dan pemeriksaan reputasi
opsional melalui provider eksternal yang dapat diganti (pluggable).

PENTING: Modul ini TIDAK melakukan crawling agresif. Permintaan HTTP yang
dilakukan (jika ada) hanya bersifat ringan (HEAD/GET dengan timeout singkat)
untuk mengecek keberadaan redirect, dan menghormati batas wajar penggunaan.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

import httpx

from config import settings
from services.scam_detector import analyze_url_basic
from utils.validators import get_hostname, is_valid_url

logger = logging.getLogger(__name__)


@dataclass
class URLCheckResult:
    """Hasil lengkap pemeriksaan sebuah URL."""

    url: str
    is_valid: bool
    hostname: str | None = None
    signals: list[str] = field(default_factory=list)
    final_url_after_redirect: str | None = None
    reputation_provider: str | None = None
    reputation_verdict: str | None = None  # "malicious" | "suspicious" | "clean" | "unknown"
    error: str | None = None


class ReputationProvider(Protocol):
    """Interface provider reputasi URL agar mudah diganti (mis. VirusTotal, Google Safe Browsing, dll)."""

    async def check(self, url: str) -> tuple[str, str | None]:
        """Mengembalikan tuple (verdict, error_message)."""
        ...


class NullReputationProvider:
    """Provider default ketika tidak ada API reputasi yang dikonfigurasi."""

    async def check(self, url: str) -> tuple[str, str | None]:
        return "unknown", None


class GenericHTTPReputationProvider:
    """
    Contoh provider generik yang memanggil endpoint reputasi berbasis HTTP.
    Diisi/disesuaikan sesuai layanan yang benar-benar Anda gunakan
    (mis. Google Safe Browsing API, VirusTotal API, dll).

    Endpoint dan format request/response HARUS disesuaikan dengan dokumentasi
    provider yang dipilih -- implementasi di sini adalah kerangka umum.
    """

    def __init__(self, api_key: str, base_url: str) -> None:
        self._api_key = api_key
        self._base_url = base_url

    async def check(self, url: str) -> tuple[str, str | None]:
        if not self._api_key:
            return "unknown", "API key reputasi URL tidak dikonfigurasi"
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                response = await client.post(
                    self._base_url,
                    json={"url": url},
                    headers={"Authorization": f"Bearer {self._api_key}"},
                )
                response.raise_for_status()
                data = response.json()
                # Sesuaikan parsing ini dengan skema response provider Anda.
                verdict = data.get("verdict", "unknown")
                return verdict, None
        except httpx.HTTPError as exc:
            logger.warning("Reputation provider error (tidak fatal): %s", type(exc).__name__)
            return "unknown", "Layanan reputasi URL sedang tidak dapat diakses"
        except Exception as exc:  # noqa: BLE001 - fallback aman, jangan sampai bot crash
            logger.warning("Reputation provider unexpected error: %s", type(exc).__name__)
            return "unknown", "Terjadi kesalahan saat memeriksa reputasi URL"


def _get_reputation_provider() -> ReputationProvider:
    """Factory untuk memilih provider reputasi berdasarkan konfigurasi .env."""
    if settings.url_reputation_provider == "generic" and settings.url_reputation_api_key:
        return GenericHTTPReputationProvider(
            api_key=settings.url_reputation_api_key,
            base_url="https://example-reputation-provider.invalid/v1/check",
        )
    return NullReputationProvider()


def basic_check(url: str) -> URLCheckResult:
    """Pemeriksaan sintaksis/heuristik dasar tanpa network call."""
    if not is_valid_url(url):
        return URLCheckResult(url=url, is_valid=False, error="Format URL tidak valid")

    hostname = get_hostname(url)
    signals = analyze_url_basic(url)

    return URLCheckResult(
        url=url,
        is_valid=True,
        hostname=hostname,
        signals=signals,
    )


async def check_redirect(url: str) -> str | None:
    """
    Cek apakah URL melakukan redirect ke tujuan lain (satu request ringan saja).
    Mengembalikan None jika gagal/tidak ada redirect.
    """
    try:
        async with httpx.AsyncClient(
            timeout=6.0, follow_redirects=True, max_redirects=3
        ) as client:
            response = await client.head(url)
            final_url = str(response.url)
            return final_url if final_url != url else None
    except httpx.HTTPError:
        logger.info("Tidak dapat memeriksa redirect untuk URL (network error)")
        return None
    except Exception:  # noqa: BLE001
        return None


async def reputation_check(url: str) -> tuple[str, str | None]:
    """Cek reputasi URL melalui provider yang dikonfigurasi (jika ada)."""
    provider = _get_reputation_provider()
    return await provider.check(url)


async def analyze(url: str, use_reputation: bool = True, use_redirect_check: bool = True) -> URLCheckResult:
    """
    Fungsi utama: gabungkan basic_check, redirect check, dan reputation_check.
    Setiap tahap bersifat best-effort -- kegagalan di satu tahap tidak
    menghentikan analisis keseluruhan.
    """
    result = basic_check(url)
    if not result.is_valid:
        return result

    if use_redirect_check:
        try:
            result.final_url_after_redirect = await check_redirect(url)
        except Exception:  # noqa: BLE001
            logger.info("Redirect check gagal, melanjutkan tanpa info redirect")

    if use_reputation:
        verdict, error = await reputation_check(url)
        result.reputation_provider = settings.url_reputation_provider
        result.reputation_verdict = verdict
        if error:
            result.error = error
        if verdict in ("malicious", "suspicious") and "suspicious_url" not in result.signals:
            result.signals.append("suspicious_url")

    return result
