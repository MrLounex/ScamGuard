"""
services/ai_analyzer.py
========================
Lapisan analisis berbasis AI/LLM. Bersifat OPSIONAL & PELENGKAP --
scam_detector.py (rule-based) tetap menjadi lapisan deteksi utama.

Desain provider-agnostic: AIAnalyzer menerima "provider" apa pun yang
mengimplementasikan method async `complete(prompt: str) -> str`, sehingga
mudah mengganti OpenAI dengan provider lain (Anthropic, Azure OpenAI, dll)
tanpa mengubah logika analisis.

Validasi ketat diterapkan pada output AI: jika AI mengembalikan JSON yang
tidak sesuai skema, sistem akan fallback secara aman (tidak membuat bot crash)
dan menandai hasil sebagai tidak tersedia dari AI.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from config import settings

logger = logging.getLogger(__name__)

_ALLOWED_RISK_LEVELS = {"low", "caution", "suspicious", "high", "critical"}
_ALLOWED_VERDICTS = {
    "indikasi risiko rendah",
    "perlu diwaspadai",
    "terindikasi mencurigakan",
    "berisiko tinggi sebagai penipuan",
    "sangat kuat terindikasi penipuan",
    "tidak dapat dipastikan",
}

_SYSTEM_PROMPT = """Anda adalah asisten analisis keamanan siber yang membantu mendeteksi
indikasi penipuan (scam/fraud) dari pesan, link, atau hasil OCR screenshot.

ATURAN PENTING:
1. Jangan pernah menyatakan kesimpulan mutlak seperti "orang ini pasti penipu".
   Selalu gunakan istilah: indikasi, mencurigakan, berisiko, perlu verifikasi.
2. Jika bukti tidak cukup, katakan dengan jujur bahwa hasil tidak dapat dipastikan.
3. Jawaban HARUS berupa JSON valid saja, tanpa teks lain, tanpa markdown code fence,
   dengan skema persis seperti berikut:

{
  "risk_level": "low" | "caution" | "suspicious" | "high" | "critical",
  "risk_score": <integer 0-100>,
  "verdict": "indikasi risiko rendah" | "perlu diwaspadai" | "terindikasi mencurigakan" | "berisiko tinggi sebagai penipuan" | "sangat kuat terindikasi penipuan" | "tidak dapat dipastikan",
  "reasons": ["...", "..."],
  "detected_tactics": ["...", "..."],
  "recommendations": ["...", "..."]
}
"""


class LLMProvider(Protocol):
    """Interface provider LLM generik agar mudah diganti."""

    async def complete(self, system_prompt: str, user_prompt: str) -> str:
        ...


class OpenAICompatibleProvider:
    """
    Implementasi provider untuk API bergaya OpenAI Chat Completions.
    Kompatibel dengan OpenAI asli maupun banyak provider lain yang meniru
    format API-nya (cukup ganti AI_BASE_URL di .env).
    """

    def __init__(self, api_key: str, base_url: str, model: str) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model

    async def complete(self, system_prompt: str, user_prompt: str) -> str:
        url = f"{self._base_url}/chat/completions"
        headers = {"Authorization": f"Bearer {self._api_key}"}
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]


def _get_provider() -> LLMProvider | None:
    """Factory provider AI berdasarkan konfigurasi. Mengembalikan None jika tidak dikonfigurasi."""
    if not settings.ai_api_key:
        return None
    if settings.ai_provider in ("openai", "generic"):
        return OpenAICompatibleProvider(
            api_key=settings.ai_api_key,
            base_url=settings.ai_base_url,
            model=settings.ai_model,
        )
    logger.warning("AI_PROVIDER '%s' tidak dikenali, AI analyzer dinonaktifkan", settings.ai_provider)
    return None


@dataclass
class AIAnalysisResult:
    """Hasil analisis AI yang sudah divalidasi, atau kosong jika AI gagal/tidak tersedia."""

    available: bool
    risk_level: str | None = None
    risk_score: int | None = None
    verdict: str | None = None
    reasons: list[str] = field(default_factory=list)
    detected_tactics: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    error: str | None = None


def _validate_ai_json(raw: dict[str, Any]) -> AIAnalysisResult:
    """Validasi ketat struktur JSON dari AI. Mengembalikan hasil kosong (available=False) jika invalid."""
    try:
        risk_level = raw["risk_level"]
        risk_score = raw["risk_score"]
        verdict = raw["verdict"]
        reasons = raw.get("reasons", [])
        detected_tactics = raw.get("detected_tactics", [])
        recommendations = raw.get("recommendations", [])

        if risk_level not in _ALLOWED_RISK_LEVELS:
            raise ValueError(f"risk_level tidak valid: {risk_level!r}")
        if not isinstance(risk_score, int) or not (0 <= risk_score <= 100):
            raise ValueError(f"risk_score tidak valid: {risk_score!r}")
        if verdict not in _ALLOWED_VERDICTS:
            raise ValueError(f"verdict tidak valid: {verdict!r}")
        if not isinstance(reasons, list) or not all(isinstance(r, str) for r in reasons):
            raise ValueError("reasons harus berupa list of string")
        if not isinstance(detected_tactics, list) or not all(isinstance(t, str) for t in detected_tactics):
            raise ValueError("detected_tactics harus berupa list of string")
        if not isinstance(recommendations, list) or not all(isinstance(r, str) for r in recommendations):
            raise ValueError("recommendations harus berupa list of string")

        return AIAnalysisResult(
            available=True,
            risk_level=risk_level,
            risk_score=risk_score,
            verdict=verdict,
            reasons=reasons,
            detected_tactics=detected_tactics,
            recommendations=recommendations,
        )
    except (KeyError, ValueError, TypeError) as exc:
        logger.warning("Output AI tidak sesuai skema yang diharapkan: %s", exc)
        return AIAnalysisResult(available=False, error="Format respons AI tidak valid")


async def analyze_with_ai(
    text: str = "",
    urls: list[str] | None = None,
    ocr_text: str = "",
    signals: list[str] | None = None,
) -> AIAnalysisResult:
    """
    Kirim data terstruktur ke AI dan kembalikan hasil analisis yang sudah divalidasi.

    Jika AI tidak dikonfigurasi atau gagal dipanggil, mengembalikan
    AIAnalysisResult(available=False) -- pemanggil (scam analyzer gabungan)
    harus tetap bisa memberi hasil hanya dari rule-based detection.
    """
    provider = _get_provider()
    if provider is None:
        return AIAnalysisResult(available=False, error="AI analyzer tidak dikonfigurasi")

    structured_input = {
        "text": text or "",
        "urls": urls or [],
        "ocr_text": ocr_text or "",
        "signals": signals or [],
    }
    user_prompt = (
        "Analisis data berikut dan kembalikan JSON sesuai skema yang ditentukan:\n\n"
        + json.dumps(structured_input, ensure_ascii=False, indent=2)
    )

    try:
        raw_response = await provider.complete(_SYSTEM_PROMPT, user_prompt)
    except httpx.HTTPStatusError as exc:
        logger.warning("AI API mengembalikan error HTTP %s", exc.response.status_code)
        return AIAnalysisResult(available=False, error="Layanan AI sedang bermasalah")
    except httpx.HTTPError:
        logger.warning("AI API tidak dapat dihubungi (network error)")
        return AIAnalysisResult(available=False, error="Tidak dapat menghubungi layanan AI")
    except Exception as exc:  # noqa: BLE001
        logger.exception("Kesalahan tak terduga saat memanggil AI API")
        return AIAnalysisResult(available=False, error=f"Kesalahan AI: {type(exc).__name__}")

    try:
        # Bersihkan kemungkinan markdown code fence jika provider tetap menyisipkannya.
        cleaned = raw_response.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:]
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        logger.warning("Respons AI bukan JSON yang valid")
        return AIAnalysisResult(available=False, error="Respons AI tidak dapat dibaca")

    return _validate_ai_json(parsed)
