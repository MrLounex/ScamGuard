"""
services/scam_detector.py
==========================
Rule-based & regex-based scam detection. Ini adalah lapisan deteksi utama
yang TIDAK bergantung pada AI, sehingga bot tetap dapat memberikan analisis
dasar meskipun AI_API_KEY tidak dikonfigurasi atau API AI sedang gagal.

Hasil dari modul ini (daftar "signals") akan digabungkan dengan hasil
AI analyzer (jika tersedia) sebelum dihitung skornya oleh risk_engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from utils.validators import (
    extract_urls,
    get_hostname,
    is_ip_hostname,
    is_punycode,
    is_valid_url,
    looks_like_brand_impersonation,
)

# --- Kamus kata kunci (bahasa Indonesia & Inggris) ---
# Setiap kategori berisi pattern Bahasa Indonesia DAN Bahasa Inggris,
# karena banyak scam (terutama invoice/subscription palsu ala PayPal/McAfee/
# Norton/Amazon) beredar dalam bahasa Inggris meskipun korbannya orang Indonesia.

_OTP_PATTERNS = [
    r"\botp\b", r"kode\s*otp", r"kode\s*verifikasi", r"one[\s-]?time[\s-]?password",
    r"verification\s*code", r"security\s*code",
]

_PASSWORD_PIN_PATTERNS = [
    r"\bpassword\b", r"\bkata\s*sandi\b", r"\bpin\b(?!\w)", r"\bcvv\b",
    r"nomor\s*kartu", r"masa\s*berlaku\s*kartu",
    r"card\s*number", r"expiry\s*date", r"login\s*credentials",
]

_MONEY_TRANSFER_PATTERNS = [
    r"transfer(?:kan)?\s*(?:uang|dana|sejumlah|ke)", r"kirim(?:kan)?\s*uang",
    r"bayar(?:kan)?\s*(?:melalui|via|ke)\s*(?:rekening|nomor)", r"top\s*up",
    r"biaya\s*admin(?:istrasi)?", r"biaya\s*pencairan",
    r"will\s*(?:be\s*)?(?:debit|charge)(?:ed)?\s*from\s*your\s*account",
    r"debited?\s*from\s*your\s*(?:account|card)", r"auto[\s-]?renew(?:al)?",
    r"subscription\s*(?:will\s*)?renew",
]

_THREAT_PRESSURE_PATTERNS = [
    r"segera", r"sekarang\s*juga", r"dalam\s*\d+\s*(?:menit|jam)", r"batas\s*waktu",
    r"akun\s*(?:anda\s*)?akan\s*(?:diblokir|ditutup|dinonaktifkan)",
    r"terakhir\s*kali", r"jangan\s*diabaikan", r"tindakan\s*hukum",
    r"within\s*(?:the\s*next\s*)?\d+\s*(?:hours?|hrs?|minutes?|mins?|days?)",
    r"you\s*have\s*\d+\s*(?:hours?|hrs?|days?)", r"act\s*now", r"immediately",
    r"unauthorized\s*transaction", r"account\s*will\s*be\s*(?:suspended|locked|closed)",
]

_UNREALISTIC_REWARD_PATTERNS = [
    r"selamat[,!]?\s*anda\s*(?:mendapatkan|memenangkan|terpilih)", r"hadiah\s*rp",
    r"undian", r"menang(?:kan)?\s*(?:uang|hadiah)", r"gratis\s*100%",
    r"cashback\s*besar", r"bonus\s*fantastis",
    r"congratulations?[,!]?\s*you(?:'ve|\s*have)", r"you(?:'ve|\s*have)\s*won",
    r"claim\s*your\s*(?:prize|reward|gift)",
]

_INSTITUTION_IMPERSONATION_PATTERNS = [
    r"\bbank\s*(?:bca|mandiri|bri|bni|cimb)\b", r"\bojk\b", r"\bpajak\b",
    r"\bbea\s*cukai\b", r"customer\s*service\s*resmi", r"\bpln\b", r"\bbpjs\b",
    r"\bpaypal\b", r"\bmcafee\b", r"\bnorton\b", r"\bamazon\b", r"\bapple\s*(?:id|support)\b",
    r"\bmicrosoft\s*support\b", r"\bnetflix\b",
]

_PERSONAL_DATA_PATTERNS = [
    r"nomor\s*ktp", r"\bnik\b", r"nomor\s*kartu\s*keluarga", r"tanggal\s*lahir\s*lengkap",
    r"nama\s*ibu\s*kandung", r"social\s*security\s*number", r"\bssn\b",
]

_URGENT_ACTION_PATTERNS = [
    r"klik\s*(?:link|tautan)\s*(?:ini|berikut|di\s*bawah)", r"segera\s*(?:klik|verifikasi|konfirmasi)",
    r"verifikasi\s*(?:akun\s*)?(?:anda\s*)?sekarang",
    r"click\s*(?:the\s*)?link\s*(?:below|here)", r"verify\s*(?:your\s*)?account\s*(?:now|immediately)",
    r"contact\s*(?:our\s*)?(?:customer\s*(?:care|support)|billing\s*department)\s*(?:as\s*soon\s*as\s*possible|immediately|now)",
    r"call\s*(?:us\s*)?(?:now|immediately|toll[\s-]?free)",
]

# --- Signal khusus pola invoice/tagihan/subscription palsu ---
# Pola ini SENGAJA dipisah dari kategori umum di atas karena punya ciri
# struktural sendiri: nomor telepon "customer support" yang diminta dihubungi
# balik, klaim pembayaran otomatis untuk layanan yang tidak pernah didaftar,
# dan format invoice/faktur.

_FAKE_INVOICE_PATTERNS = [
    r"invoice", r"\bfaktur\b", r"receipt", r"order\s*confirmation",
    r"product\s*code", r"subscription\s*(?:id|number)", r"billed\s*to",
    r"renewal\s*date", r"auto[\s-]?renewal", r"subtotal", r"unauthorized\s*charge",
]

_CALLBACK_PHONE_PATTERNS = [
    r"customer\s*(?:care|support|service)\s*:?\s*[\+\(]?\d",
    r"call\s*(?:us\s*)?(?:at|on)?\s*:?\s*[\+\(]?\d{2,}",
    r"toll[\s-]?free\s*:?\s*[\+\(]?\d",
    r"hubungi\s*(?:kami\s*)?(?:di|pada)?\s*:?\s*[\+\(]?\d",
]

_UNRECOGNIZED_SUBSCRIPTION_PATTERNS = [
    r"if\s*you\s*(?:did(?:n't| not)|didn)\s*authorize\s*this", r"if\s*this\s*(?:wasn't|was\s*not)\s*you",
    r"jika\s*anda\s*tidak\s*(?:melakukan|mengenali|merasa)",
]

# --- Signal khusus pola lowongan kerja palsu ---
# Ciri khas: gaji tidak masuk akal untuk pekerjaan sederhana, minta bayar
# di muka (untuk "admin", "training kit", dsb), proses rekrutmen instan
# tanpa interview yang wajar, komunikasi hanya lewat WhatsApp/Telegram pribadi.

_JOB_OFFER_SHAPED_PATTERNS = [
    r"lowongan\s*(?:kerja|pekerjaan)", r"loker\b", r"job\s*(?:offer|vacancy|opening)",
    r"rekrutmen", r"recruit(?:ment|ing)", r"part[\s-]?time", r"kerja\s*(?:sampingan|paruh\s*waktu)",
    r"work\s*from\s*home", r"\bwfh\b",
]

_JOB_SCAM_RED_FLAG_PATTERNS = [
    r"gaji\s*(?:harian|mingguan)\s*(?:hingga\s*)?rp", r"penghasilan\s*(?:tambahan\s*)?rp\s*\d",
    r"tanpa\s*pengalaman", r"tanpa\s*interview", r"tanpa\s*cv",
    r"bayar(?:kan)?\s*(?:biaya\s*)?(?:admin|pendaftaran|training|pelatihan)",
    r"deposit\s*(?:awal|dulu)", r"join(?:kan)?\s*(?:dulu|fee)",
    r"hubungi\s*(?:admin\s*)?(?:via\s*)?whatsapp", r"chat\s*admin",
    r"cukup\s*(?:klik|like|follow|subscribe)\s*(?:dan\s*)?(?:dapat|dapatkan)",
]

# --- Signal khusus pola investasi bodong / skema Ponzi ---
# Ciri khas: janji keuntungan tetap dan tidak masuk akal, tekanan untuk
# ajak orang lain bergabung (skema piramida), testimoni berlebihan,
# istilah "trading robot", "member get member", dsb.

_INVESTMENT_SHAPED_PATTERNS = [
    r"investasi", r"invest(?:ment|ing)?\b", r"trading\b", r"\bforex\b",
    r"reksadana", r"saham\s*(?:pasti|dijamin)", r"\bcrypto\b", r"robot\s*trading",
]

_INVESTMENT_SCAM_RED_FLAG_PATTERNS = [
    r"profit\s*(?:pasti|tetap|terjamin|\d+%)", r"keuntungan\s*(?:pasti|tetap|terjamin)",
    r"balik\s*modal\s*dalam", r"tanpa\s*risiko", r"no\s*risk", r"risk\s*free",
    r"member\s*get\s*member", r"ajak(?:kan)?\s*(?:teman|downline)",
    r"bonus\s*referral", r"sistem\s*piramida", r"guaranteed\s*(?:profit|returns?)",
    r"double\s*(?:your\s*)?money", r"passive\s*income\s*(?:pasti|otomatis)",
]

# --- Signal khusus pola romance scam / love scam ---
# Ciri khas: hubungan romantis online yang cepat intens, lalu diikuti
# permintaan uang dengan berbagai alasan (sakit, terjebak di luar negeri,
# biaya visa/customs, dll), sering mengaku warga negara asing/militer/pekerja
# di kapal/pengeboran minyak.

_ROMANCE_SHAPED_PATTERNS = [
    r"sayang(?:ku)?\b", r"\bdarling\b", r"\bmy\s*love\b", r"\bhoney\b",
    r"jodoh", r"calon\s*(?:suami|istri)", r"i\s*love\s*you",
]

_ROMANCE_SCAM_RED_FLAG_PATTERNS = [
    r"terjebak\s*di\s*(?:bandara|luar\s*negeri|customs|bea\s*cukai)",
    r"stuck\s*(?:at|in)\s*(?:the\s*)?(?:airport|customs)",
    r"butuh\s*(?:bantuan\s*)?(?:uang|dana)\s*(?:untuk|buat)",
    r"kirim(?:kan)?\s*(?:uang|dana)\s*(?:untuk|buat)\s*(?:tiket|visa|obat|rumah\s*sakit)",
    r"military\s*(?:base|deployment)", r"oil\s*rig", r"pengeboran\s*minyak",
    r"belum\s*pernah\s*(?:bertemu|ketemu)\s*(?:langsung|tatap\s*muka)",
]

_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "s.id", "shorturl.at", "tiny.cc",
}

_KNOWN_BRANDS = [
    "bca", "mandiri", "bri", "bni", "gopay", "ovo", "dana", "shopee",
    "tokopedia", "grab", "gojek", "pln", "bpjs", "pajak",
]


@dataclass
class DetectionResult:
    """Hasil deteksi rule-based sebelum digabung dengan AI dan dihitung skornya."""

    signals: list[str] = field(default_factory=list)
    urls_found: list[str] = field(default_factory=list)
    matched_keywords: list[str] = field(default_factory=list)


def _matches_any(text_lower: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text_lower, flags=re.IGNORECASE) for pattern in patterns)


def analyze_text(text: str) -> DetectionResult:
    """
    Jalankan seluruh rule-based & regex detection terhadap sebuah teks.
    Tidak melakukan network call apa pun (analisis URL mendalam dilakukan
    terpisah oleh services.url_checker).
    """
    result = DetectionResult()
    if not text:
        return result

    text_lower = text.lower()

    checks: list[tuple[str, list[str]]] = [
        ("requests_otp", _OTP_PATTERNS),
        ("requests_password_pin", _PASSWORD_PIN_PATTERNS),
        ("requests_money_transfer", _MONEY_TRANSFER_PATTERNS),
        ("uses_threat_or_pressure", _THREAT_PRESSURE_PATTERNS),
        ("unrealistic_reward", _UNREALISTIC_REWARD_PATTERNS),
        ("impersonates_institution", _INSTITUTION_IMPERSONATION_PATTERNS),
        ("requests_personal_data", _PERSONAL_DATA_PATTERNS),
        ("urgent_action_required", _URGENT_ACTION_PATTERNS),
    ]

    for signal_name, patterns in checks:
        if _matches_any(text_lower, patterns):
            result.signals.append(signal_name)

    # Pola invoice/tagihan palsu HANYA relevan dijadikan signal jika teks
    # memang berbentuk invoice/tagihan (untuk menghindari false positive pada
    # pesan biasa yang kebetulan menyebut kata "invoice"). Signal ini
    # ditambahkan sebagai kombinasi: bentuk invoice + minimal satu ciri
    # mencurigakan lain (nomor telepon callback ATAU klaim auto-charge
    # untuk layanan yang mungkin tidak dikenali user).
    is_invoice_shaped = _matches_any(text_lower, _FAKE_INVOICE_PATTERNS)
    has_callback_phone = _matches_any(text_lower, _CALLBACK_PHONE_PATTERNS)
    has_unrecognized_charge_claim = _matches_any(text_lower, _UNRECOGNIZED_SUBSCRIPTION_PATTERNS)

    if is_invoice_shaped and has_callback_phone:
        result.signals.append("invoice_requests_callback")
    if is_invoice_shaped and has_unrecognized_charge_claim:
        result.signals.append("unsolicited_subscription_charge")

    # Pola lowongan kerja palsu: butuh KOMBINASI konteks lowongan kerja +
    # minimal satu red flag (gaji tidak masuk akal, minta bayar di muka, dll).
    # Ini mencegah pesan lowongan kerja SUNGGUHAN ikut ke-flag hanya karena
    # menyebut kata "loker" atau "WFH".
    is_job_shaped = _matches_any(text_lower, _JOB_OFFER_SHAPED_PATTERNS)
    has_job_red_flag = _matches_any(text_lower, _JOB_SCAM_RED_FLAG_PATTERNS)
    if is_job_shaped and has_job_red_flag:
        result.signals.append("job_scam_pattern")

    # Pola investasi bodong: konteks investasi/trading + red flag klasik
    # skema Ponzi (profit pasti, member get member, tanpa risiko, dll).
    is_investment_shaped = _matches_any(text_lower, _INVESTMENT_SHAPED_PATTERNS)
    has_investment_red_flag = _matches_any(text_lower, _INVESTMENT_SCAM_RED_FLAG_PATTERNS)
    if is_investment_shaped and has_investment_red_flag:
        result.signals.append("investment_scam_pattern")

    # Pola romance scam: konteks hubungan romantis + red flag permintaan
    # uang dengan alasan klasik (terjebak di luar negeri, tiket, dll).
    is_romance_shaped = _matches_any(text_lower, _ROMANCE_SHAPED_PATTERNS)
    has_romance_red_flag = _matches_any(text_lower, _ROMANCE_SCAM_RED_FLAG_PATTERNS)
    if is_romance_shaped and has_romance_red_flag:
        result.signals.append("romance_scam_pattern")
    elif has_romance_red_flag:
        # Permintaan uang dengan alasan "terjebak di luar negeri" dkk tetap
        # signifikan sebagai red flag bahkan tanpa konteks romantis eksplisit
        # (mis. korban forward pesan tanpa awalan "sayang").
        result.signals.append("romance_scam_pattern")

    # Ekstraksi & analisis dasar URL yang muncul di teks
    urls = extract_urls(text)
    result.urls_found = urls

    for url in urls:
        url_signals = analyze_url_basic(url)
        for signal in url_signals:
            if signal not in result.signals:
                result.signals.append(signal)

    return result


def analyze_url_basic(url: str) -> list[str]:
    """
    Analisis dasar sebuah URL tanpa melakukan HTTP request (murni sintaksis).
    Untuk pengecekan yang membutuhkan network (redirect, reputasi), lihat
    services/url_checker.py.
    """
    signals: list[str] = []

    if not is_valid_url(url):
        return signals

    hostname = get_hostname(url)

    if is_ip_hostname(hostname):
        signals.append("url_is_ip_address")

    if is_punycode(hostname):
        signals.append("url_uses_punycode")

    if hostname and hostname.lower() in _URL_SHORTENERS:
        signals.append("url_shortener")

    if not url.lower().startswith("https://"):
        signals.append("no_https")

    brand_matches = looks_like_brand_impersonation(hostname, _KNOWN_BRANDS)
    if brand_matches:
        signals.append("brand_impersonation_domain")

    return signals


def has_sufficient_evidence(signals: list[str], text_length: int) -> bool:
    """
    Tentukan apakah bukti yang ada cukup untuk memberi kesimpulan.
    Jika teks terlalu pendek dan tidak ada signal signifikan, hasil
    dianggap tidak dapat dipastikan.
    """
    if signals:
        return True
    if text_length < 15:
        return False
    return True