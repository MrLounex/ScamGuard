"""
utils/formatters.py
====================
Fungsi-fungsi untuk memformat hasil analisis menjadi pesan Telegram yang rapi.
"""

from __future__ import annotations

from services.risk_engine import RiskAssessment
from database import AnalysisRecord

_RISK_LEVEL_DISPLAY = {
    "low": ("🟢", "Risiko Rendah"),
    "caution": ("🟡", "Perlu Waspada"),
    "suspicious": ("🟠", "Mencurigakan"),
    "high": ("🔴", "Risiko Tinggi"),
    "critical": ("🚨", "Sangat Mencurigakan"),
}


def _risk_emoji_label(risk_level: str) -> tuple[str, str]:
    return _RISK_LEVEL_DISPLAY.get(risk_level, ("⚪", "Tidak Diketahui"))


def format_analysis_result(assessment: RiskAssessment) -> str:
    """Format objek RiskAssessment menjadi pesan Telegram yang mudah dibaca."""
    emoji, label = _risk_emoji_label(assessment.risk_level)

    lines = [
        "━━━━━━━━━━━━━━━━",
        "🛡️ *SCAMGUARD ANALYSIS*",
        "━━━━━━━━━━━━━━━━",
        "",
        f"Risk Score: *{assessment.risk_score}/100*",
        "",
        f"{emoji} {label}",
        "",
    ]

    if assessment.reasons:
        lines.append("🔍 *Temuan:*")
        for reason in assessment.reasons:
            lines.append(f"• {reason}")
        lines.append("")

    if assessment.detected_tactics:
        lines.append("🎯 *Taktik yang terdeteksi:*")
        for tactic in assessment.detected_tactics:
            lines.append(f"• {tactic}")
        lines.append("")

    if assessment.recommendations:
        lines.append("🛡️ *Rekomendasi:*")
        for rec in assessment.recommendations:
            lines.append(f"• {rec}")
        lines.append("")

    if assessment.is_uncertain:
        lines.append(
            "❓ *Catatan:* Bukti yang tersedia belum cukup untuk memberikan "
            "kesimpulan yang pasti. Tetap berhati-hati dan lakukan verifikasi "
            "mandiri melalui kanal resmi."
        )
        lines.append("")

    lines.append(
        "⚠️ _Analisis ini hanya memberikan indikasi berdasarkan informasi yang "
        "tersedia dan bukan jaminan bahwa suatu pesan/orang pasti melakukan "
        "penipuan._"
    )
    lines.append("━━━━━━━━━━━━━━━━")

    return "\n".join(lines)


def format_history(records: list[AnalysisRecord]) -> str:
    """Format daftar riwayat analisis menjadi pesan Telegram."""
    if not records:
        return (
            "📜 *Riwayat Analisis*\n\n"
            "Anda belum memiliki riwayat analisis apa pun."
        )

    input_type_labels = {
        "text": "Pesan",
        "url": "Link",
        "photo": "Screenshot",
        "forward": "Forward",
    }

    lines = ["📜 *Riwayat Analisis*", ""]
    for i, record in enumerate(records, start=1):
        emoji, _ = _risk_emoji_label(record.risk_level)
        type_label = input_type_labels.get(record.input_type, record.input_type)
        lines.append(f"{i}. {emoji} {type_label} — {record.risk_score}/100")

    return "\n".join(lines)


def escape_markdown(text: str) -> str:
    """Escape karakter spesial Markdown (legacy) agar tidak merusak format pesan."""
    special_chars = ["_", "*", "`", "["]
    for char in special_chars:
        text = text.replace(char, f"\\{char}")
    return text
