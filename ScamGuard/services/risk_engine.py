"""
services/risk_engine.py
========================
Mesin penghitung risk score (0-100) berdasarkan kumpulan "signal" yang
ditemukan oleh scam_detector (rule-based) dan/atau ai_analyzer (LLM).

Dipisahkan dari scam_detector agar bobot skor mudah dikalibrasi ulang
tanpa mengubah logika deteksi pola.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# Bobot setiap signal terhadap risk score. Nilai ini yang menentukan
# seberapa besar pengaruh sebuah temuan terhadap skor akhir.
SIGNAL_WEIGHTS: dict[str, int] = {
    "requests_otp": 25,
    "requests_password_pin": 20,
    "requests_money_transfer": 20,
    "uses_threat_or_pressure": 15,
    "unrealistic_reward": 15,
    "suspicious_url": 10,
    "unknown_or_new_domain": 10,
    "impersonates_institution": 10,
    "urgent_action_required": 10,
    "requests_personal_data": 10,
    "url_is_ip_address": 15,
    "url_uses_punycode": 15,
    "url_shortener": 8,
    "brand_impersonation_domain": 20,
    "no_https": 5,
    "invoice_requests_callback": 25,
    "unsolicited_subscription_charge": 20,
}

# Deskripsi manusiawi untuk tiap signal, dipakai untuk menyusun daftar "Temuan".
SIGNAL_DESCRIPTIONS: dict[str, str] = {
    "requests_otp": "Meminta kode OTP",
    "requests_password_pin": "Meminta password/PIN/kode verifikasi",
    "requests_money_transfer": "Meminta transfer uang di luar platform resmi",
    "uses_threat_or_pressure": "Menggunakan ancaman atau tekanan waktu",
    "unrealistic_reward": "Menawarkan hadiah/keuntungan yang tidak masuk akal",
    "suspicious_url": "Mengandung URL yang mencurigakan",
    "unknown_or_new_domain": "Domain tidak dikenal/berpotensi baru dibuat",
    "impersonates_institution": "Menyamar sebagai institusi resmi (bank/pemerintah/e-commerce)",
    "urgent_action_required": "Meminta tindakan segera/mendesak",
    "requests_personal_data": "Meminta data pribadi sensitif",
    "url_is_ip_address": "Alamat URL menggunakan IP, bukan nama domain",
    "url_uses_punycode": "Domain menggunakan encoding punycode (berpotensi homograph attack)",
    "url_shortener": "Menggunakan layanan pemendek URL (menyembunyikan tujuan asli)",
    "brand_impersonation_domain": "Domain menyerupai nama brand resmi tetapi bukan domain aslinya",
    "no_https": "Situs tidak menggunakan koneksi aman (HTTPS)",
    "invoice_requests_callback": "Invoice/tagihan meminta korban menghubungi nomor telepon tertentu (pola callback scam)",
    "unsolicited_subscription_charge": "Mengklaim tagihan/langganan otomatis untuk layanan yang mungkin tidak pernah didaftar",
}

# Rekomendasi standar berdasarkan level risiko.
_BASE_RECOMMENDATIONS = [
    "❌ Jangan klik link yang mencurigakan",
    "❌ Jangan transfer uang ke pihak yang tidak dikenal/tidak terverifikasi",
    "❌ Jangan memberikan OTP, password, atau PIN kepada siapa pun",
    "✅ Verifikasi informasi melalui kanal resmi (website/CS resmi)",
]


def classify_risk_level(score: int) -> str:
    """Klasifikasikan skor numerik menjadi kategori level risiko."""
    if score <= 20:
        return "low"
    elif score <= 40:
        return "caution"
    elif score <= 60:
        return "suspicious"
    elif score <= 80:
        return "high"
    else:
        return "critical"


@dataclass
class RiskAssessment:
    """Hasil akhir penilaian risiko yang siap ditampilkan ke user."""

    risk_score: int
    risk_level: str
    verdict: str
    reasons: list[str] = field(default_factory=list)
    detected_tactics: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    is_uncertain: bool = False


def calculate_risk_score(signals: list[str]) -> int:
    """
    Hitung risk score (0-100) dari daftar signal yang terdeteksi.
    Skor dijumlahkan lalu di-cap maksimal 100.
    """
    total = sum(SIGNAL_WEIGHTS.get(signal, 0) for signal in signals)
    return min(total, 100)


def build_reasons(signals: list[str]) -> list[str]:
    """Ubah daftar signal teknis menjadi kalimat "Temuan" yang mudah dibaca."""
    return [SIGNAL_DESCRIPTIONS[s] for s in signals if s in SIGNAL_DESCRIPTIONS]


def build_recommendations(risk_level: str) -> list[str]:
    """Susun daftar rekomendasi berdasarkan level risiko."""
    recs = list(_BASE_RECOMMENDATIONS)
    if risk_level in ("low", "caution"):
        recs.append("✅ Tetap waspada meskipun risiko saat ini tergolong rendah")
    return recs


def determine_verdict(risk_level: str, has_sufficient_evidence: bool) -> str:
    """
    Tentukan verdict akhir. Bot tidak boleh mengklaim kepastian mutlak,
    jadi verdict selalu menggunakan istilah "indikasi"/"berpotensi".
    """
    if not has_sufficient_evidence:
        return "tidak dapat dipastikan"
    mapping = {
        "low": "indikasi risiko rendah",
        "caution": "perlu diwaspadai",
        "suspicious": "terindikasi mencurigakan",
        "high": "berisiko tinggi sebagai penipuan",
        "critical": "sangat kuat terindikasi penipuan",
    }
    return mapping.get(risk_level, "tidak dapat dipastikan")


def assess(signals: list[str], has_sufficient_evidence: bool = True) -> RiskAssessment:
    """
    Fungsi utama: gabungkan signal menjadi satu RiskAssessment lengkap.

    Args:
        signals: daftar signal teknis yang terdeteksi (lihat SIGNAL_WEIGHTS).
        has_sufficient_evidence: jika False, verdict akan menyatakan hasil
            tidak dapat dipastikan alih-alih memberi kesimpulan tegas.
    """
    score = calculate_risk_score(signals)
    level = classify_risk_level(score)
    reasons = build_reasons(signals)
    recommendations = build_recommendations(level)
    verdict = determine_verdict(level, has_sufficient_evidence)

    is_uncertain = not has_sufficient_evidence or len(signals) == 0

    return RiskAssessment(
        risk_score=score,
        risk_level=level,
        verdict=verdict,
        reasons=reasons if reasons else ["Tidak ditemukan indikator mencurigakan yang jelas"],
        detected_tactics=[],
        recommendations=recommendations,
        is_uncertain=is_uncertain,
    )
