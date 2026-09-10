"""
services/analysis_pipeline.py
==============================
Menggabungkan scam_detector (rule-based), ai_analyzer (AI/LLM, opsional),
dan risk_engine (scoring) menjadi satu alur analisis yang dipakai oleh
semua handler (text, url, photo).

Ini adalah "pintu masuk" utama untuk melakukan analisis lengkap terhadap
sebuah input, sehingga handler tidak perlu tahu detail tiap service.
"""

from __future__ import annotations

import logging

from services import ai_analyzer, scam_detector, url_checker
from services.risk_engine import RiskAssessment, assess

logger = logging.getLogger(__name__)


async def analyze_input(
    text: str = "",
    ocr_text: str = "",
    check_url_reputation: bool = True,
) -> RiskAssessment:
    """
    Jalankan pipeline analisis lengkap terhadap teks bebas dan/atau hasil OCR.

    Alur:
    1. Rule-based detection (scam_detector) terhadap teks & OCR text.
    2. Pemeriksaan URL lebih dalam (url_checker) untuk setiap URL yang ditemukan.
    3. Analisis AI opsional (ai_analyzer) sebagai pelengkap.
    4. Gabungkan semua signal, hitung skor akhir (risk_engine).
    """
    combined_text = "\n".join(part for part in [text, ocr_text] if part)

    detection = scam_detector.analyze_text(combined_text)
    all_signals = list(detection.signals)

    # Pemeriksaan URL lebih dalam (redirect + reputasi) untuk tiap URL ditemukan.
    for url in detection.urls_found:
        try:
            url_result = await url_checker.analyze(url, use_reputation=check_url_reputation)
            for signal in url_result.signals:
                if signal not in all_signals:
                    all_signals.append(signal)
        except Exception:  # noqa: BLE001 - jangan sampai satu URL bermasalah menghentikan analisis
            logger.exception("Gagal menganalisis URL secara mendalam, melanjutkan tanpa hasil ini")

    has_evidence = scam_detector.has_sufficient_evidence(all_signals, len(combined_text))

    # Analisis AI sebagai pelengkap (opsional, best-effort).
    ai_result = await ai_analyzer.analyze_with_ai(
        text=text,
        urls=detection.urls_found,
        ocr_text=ocr_text,
        signals=all_signals,
    )

    if ai_result.available:
        # AI melengkapi taktik & rekomendasi, tetapi skor akhir tetap
        # dihitung dari rule-based signals agar konsisten & dapat dijelaskan.
        assessment = assess(all_signals, has_sufficient_evidence=has_evidence)
        if ai_result.detected_tactics:
            assessment.detected_tactics = ai_result.detected_tactics
        if ai_result.reasons:
            # Gabungkan alasan rule-based dengan temuan tambahan dari AI (dedupe).
            for reason in ai_result.reasons:
                if reason not in assessment.reasons:
                    assessment.reasons.append(reason)
        if ai_result.recommendations:
            for rec in ai_result.recommendations:
                if rec not in assessment.recommendations:
                    assessment.recommendations.append(rec)
        return assessment

    # Fallback: hanya rule-based (AI tidak tersedia/gagal) -- bot tetap berfungsi.
    return assess(all_signals, has_sufficient_evidence=has_evidence)
