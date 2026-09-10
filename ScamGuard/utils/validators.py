"""
utils/validators.py
====================
Fungsi-fungsi validasi kecil yang dipakai di berbagai tempat:
ekstraksi URL dari teks, validasi format URL, dan deteksi IP-as-hostname.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# Regex sederhana namun cukup akurat untuk menangkap sebagian besar URL dalam teks bebas.
_URL_REGEX = re.compile(
    r"""(?xi)
    \b
    (
        (?:https?://|www\.)
        [^\s<>"'\)\]]+
    )
    """
)


def extract_urls(text: str) -> list[str]:
    """Ekstrak semua URL dari sebuah teks bebas."""
    if not text:
        return []
    found = _URL_REGEX.findall(text)
    normalized = []
    for url in found:
        url = url.rstrip(".,;:!?")
        if url.startswith("www."):
            url = "http://" + url
        normalized.append(url)
    # Hilangkan duplikat sambil menjaga urutan
    seen: set[str] = set()
    unique_urls = []
    for url in normalized:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    return unique_urls


def is_valid_url(url: str) -> bool:
    """Cek apakah string merupakan URL yang well-formed (skema + host)."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return bool(parsed.scheme in ("http", "https") and parsed.netloc)


def get_hostname(url: str) -> str | None:
    """Ambil hostname dari sebuah URL."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    return parsed.hostname


def is_ip_hostname(hostname: str | None) -> bool:
    """Cek apakah hostname sebenarnya adalah alamat IP (indikasi phishing umum)."""
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def is_punycode(hostname: str | None) -> bool:
    """Cek apakah hostname menggunakan encoding punycode (xn--), sering dipakai untuk homograph attack."""
    if not hostname:
        return False
    return any(label.startswith("xn--") for label in hostname.split("."))


def looks_like_brand_impersonation(hostname: str | None, brands: list[str]) -> list[str]:
    """
    Deteksi sederhana: hostname mengandung nama brand resmi tapi bukan domain resminya.
    Contoh: 'bca-secure-login.com' mengandung 'bca' tapi bukan domain bca.co.id.
    Mengembalikan daftar brand yang terdeteksi mencurigakan.
    """
    if not hostname:
        return []
    hostname_lower = hostname.lower()
    matches = []
    for brand in brands:
        brand_lower = brand.lower()
        if brand_lower in hostname_lower and not hostname_lower.endswith(f"{brand_lower}.co.id") \
                and not hostname_lower.endswith(f"{brand_lower}.com") \
                and hostname_lower != brand_lower:
            matches.append(brand)
    return matches


def truncate_text(text: str, max_length: int = 500) -> str:
    """Potong teks panjang agar aman ditampilkan/diproses, dengan penanda pemotongan."""
    if len(text) <= max_length:
        return text
    return text[:max_length].rstrip() + "… (dipotong)"
