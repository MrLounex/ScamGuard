# 🛡️ ScamGuard Bot

Telegram Bot yang membantu menganalisis apakah sebuah **pesan, link, atau screenshot**
memiliki indikasi penipuan (scam), menggunakan kombinasi **rule-based detection**,
**regex**, dan **AI/LLM** (opsional).

> ⚠️ Bot ini memberikan **indikasi risiko**, bukan kepastian mutlak. Selalu lakukan
> verifikasi mandiri melalui kanal resmi sebelum mengambil keputusan.

---

## Daftar Isi

1. [Arsitektur](#arsitektur)
2. [Struktur Folder](#struktur-folder)
3. [Persiapan](#persiapan)
4. [Instalasi (Windows)](#instalasi-windows)
5. [Instalasi (Linux)](#instalasi-linux)
6. [Konfigurasi .env](#konfigurasi-env)
7. [Menjalankan Bot](#menjalankan-bot)
8. [Contoh Penggunaan](#contoh-penggunaan)
9. [Troubleshooting](#troubleshooting)
10. [Menambahkan Fitur Baru](#menambahkan-fitur-baru)
11. [Privasi & Keamanan](#privasi--keamanan)

---

## Arsitektur

```
Telegram Update
      │
      ▼
  handlers/*          ← hanya menangani interaksi Telegram (menerima update, kirim balasan)
      │
      ▼
services/analysis_pipeline.py   ← orkestrasi alur analisis
      │
      ├──► services/scam_detector.py   (rule-based + regex, SELALU jalan)
      ├──► services/url_checker.py     (validasi & reputasi URL)
      ├──► services/ocr_service.py     (ekstraksi teks dari screenshot)
      ├──► services/ai_analyzer.py     (AI/LLM, OPSIONAL & pelengkap)
      └──► services/risk_engine.py     (hitung skor 0-100 & level risiko)
      │
      ▼
  database.py          ← simpan metadata riwayat (SQLite)
```

**Prinsip desain:**
- Rule-based detection adalah lapisan **utama** — bot tetap berfungsi walau AI tidak dikonfigurasi/gagal.
- AI bersifat **pelengkap** untuk memperkaya alasan & rekomendasi, bukan penentu skor akhir.
- Semua provider eksternal (AI, reputasi URL) dibungkus dalam **abstraksi** agar mudah diganti.
- Privasi diutamakan: tidak ada isi pesan/screenshot yang disimpan permanen.

---

## Struktur Folder

```
ScamGuard/
│
├── bot.py                    # Entry point, mendaftarkan semua handler
├── config.py                 # Loader konfigurasi dari .env
├── database.py                # Lapisan SQLite (riwayat & rate limit)
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
│
├── handlers/                  # Hanya menangani interaksi Telegram
│   ├── start.py               # /start, /help, /privacy, menu tombol
│   ├── message.py             # Analisis pesan teks & forward
│   ├── photo.py                # Analisis screenshot (OCR)
│   ├── url.py                 # Pengecekan URL eksplisit
│   └── history.py             # /history, /delete_history
│
├── services/                  # Business logic
│   ├── ai_analyzer.py         # Integrasi AI/LLM (opsional, provider-agnostic)
│   ├── analysis_pipeline.py   # Orkestrasi seluruh alur analisis
│   ├── scam_detector.py       # Rule-based & regex detection
│   ├── url_checker.py         # Validasi & reputasi URL
│   ├── ocr_service.py         # OCR (pytesseract)
│   └── risk_engine.py         # Perhitungan skor & level risiko
│
└── utils/
    ├── validators.py          # Ekstraksi URL, validasi hostname, dsb
    ├── formatters.py           # Format pesan Telegram
    └── rate_limiter.py         # Anti-spam sederhana
```

---

## Persiapan

Sebelum instalasi, siapkan:

1. **Python 3.11+** — cek dengan `python --version` atau `python3 --version`.
2. **Akun Telegram** untuk membuat bot melalui [@BotFather](https://t.me/BotFather):
   - Chat `/newbot` ke @BotFather
   - Ikuti instruksi (nama bot, username bot harus diakhiri `bot`)
   - Simpan **Token** yang diberikan (format: `123456789:ABCdefGhIJKlmNoPQRstuVWxyZ`)
3. **(Opsional) API key AI** — misalnya dari [OpenAI](https://platform.openai.com/api-keys)
   jika ingin mengaktifkan analisis AI. Bot tetap berfungsi tanpa ini (hanya rule-based).
4. **(Opsional) Tesseract OCR** — dibutuhkan untuk fitur analisis screenshot.

---

## Instalasi (Windows)

Buka **PowerShell** atau **CMD**, lalu jalankan:

```powershell
# 1. Clone atau download project, lalu masuk ke foldernya
cd ScamGuard

# 2. Buat virtual environment
python -m venv venv

# 3. Aktifkan virtual environment
venv\Scripts\activate

# 4. Install semua dependency
pip install -r requirements.txt

# 5. Salin file konfigurasi
copy .env.example .env
```

**Install Tesseract OCR (untuk fitur screenshot):**
1. Unduh installer dari: https://github.com/UB-Mannheim/tesseract/wiki
2. Install seperti biasa (catat lokasi instalasi, mis. `C:\Program Files\Tesseract-OCR`)
3. Buka file `.env`, isi baris berikut dengan path tesseract.exe Anda:
   ```
   TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe
   ```

**Edit file `.env`** menggunakan Notepad atau editor lain, isi minimal:
```
TELEGRAM_BOT_TOKEN=isi_token_dari_botfather
```

---

## Instalasi (Linux)

Buka terminal:

```bash
# 1. Clone atau download project, lalu masuk ke foldernya
cd ScamGuard

# 2. Buat virtual environment
python3 -m venv venv

# 3. Aktifkan virtual environment
source venv/bin/activate

# 4. Install semua dependency
pip install -r requirements.txt

# 5. Salin file konfigurasi
cp .env.example .env
```

**Install Tesseract OCR (untuk fitur screenshot):**
```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install tesseract-ocr tesseract-ocr-ind
```

**Edit file `.env`** menggunakan nano/vim, isi minimal:
```bash
nano .env
```
```
TELEGRAM_BOT_TOKEN=isi_token_dari_botfather
```

---

## Konfigurasi .env

Semua variabel yang tersedia (lihat juga `.env.example`):

| Variabel | Wajib? | Default | Keterangan |
|---|---|---|---|
| `TELEGRAM_BOT_TOKEN` | ✅ Ya | - | Token dari @BotFather |
| `AI_API_KEY` | Tidak | - | Kosongkan jika tidak memakai AI |
| `AI_MODEL` | Tidak | `gpt-4o-mini` | Nama model AI |
| `AI_PROVIDER` | Tidak | `openai` | `openai` atau `generic` |
| `AI_BASE_URL` | Tidak | `https://api.openai.com/v1` | Ganti jika pakai provider lain yang kompatibel format OpenAI |
| `DATABASE_URL` | Tidak | `sqlite:///scamguard.db` | Lokasi file database |
| `MAX_FILE_SIZE_MB` | Tidak | `10` | Batas ukuran foto yang diterima |
| `RATE_LIMIT_REQUESTS` | Tidak | `10` | Maks. request per window |
| `RATE_LIMIT_WINDOW_SECONDS` | Tidak | `600` | Durasi window rate limit (detik) |
| `URL_REPUTATION_PROVIDER` | Tidak | `none` | `none` atau `generic` |
| `URL_REPUTATION_API_KEY` | Tidak | - | API key layanan reputasi URL |
| `TESSERACT_CMD` | Tidak | - | Path binary tesseract (khususnya Windows) |
| `LOG_LEVEL` | Tidak | `INFO` | Level logging |

---

## Menjalankan Bot

Pastikan virtual environment sudah aktif, lalu:

```bash
python bot.py
```

Jika berhasil, Anda akan melihat log seperti:
```
INFO | __main__ | Database siap di: scamguard.db
INFO | __main__ | ScamGuard Bot siap berjalan.
INFO | __main__ | Menjalankan ScamGuard Bot (polling mode)...
```

Buka Telegram, cari bot Anda, lalu kirim `/start`.

---

## Contoh Penggunaan

**1. Analisis pesan teks:**
Kirim langsung ke bot:
```
Selamat Anda mendapatkan hadiah Rp50.000.000! Klik link berikut dan
masukkan OTP Anda sekarang: http://bit.ly/klaim-hadiah
```
Bot akan membalas dengan risk score, temuan, taktik, dan rekomendasi.

**2. Cek link:**
Kirim link apa pun, bot akan memvalidasi domain, HTTPS, IP-as-hostname,
penggunaan URL shortener, dan potensi peniruan brand.

**3. Analisis screenshot:**
Kirim foto/screenshot percakapan atau bukti transfer. Bot akan menjalankan
OCR, lalu menganalisis teks yang berhasil diekstrak.

**4. Forward pesan:**
Forward pesan mencurigakan dari chat/grup lain ke bot ini.

**5. Lihat riwayat:**
```
/history
```

**6. Hapus riwayat:**
```
/delete_history
```

---

## Troubleshooting

| Masalah | Solusi |
|---|---|
| `RuntimeError: TELEGRAM_BOT_TOKEN belum diisi` | Pastikan file `.env` ada dan berisi token yang benar |
| Bot tidak merespons sama sekali | Cek koneksi internet, pastikan token valid, cek log error di terminal |
| `TesseractNotFoundError` saat kirim foto | Install Tesseract OCR (lihat bagian instalasi) dan/atau set `TESSERACT_CMD` |
| Fitur AI tidak muncul di hasil analisis | Normal jika `AI_API_KEY` kosong — bot tetap jalan dengan rule-based saja |
| `ModuleNotFoundError` | Pastikan virtual environment aktif dan `pip install -r requirements.txt` sudah dijalankan |
| Database error saat start | Pastikan folder project memiliki izin tulis untuk membuat file `.db` |
| Rate limit terlalu ketat/longgar | Ubah `RATE_LIMIT_REQUESTS` dan `RATE_LIMIT_WINDOW_SECONDS` di `.env` |

---

## Menambahkan Fitur Baru

Struktur modular memudahkan penambahan fitur:

**Menambah signal deteksi baru:**
1. Tambahkan pattern regex baru di `services/scam_detector.py`
2. Tambahkan bobot skornya di `SIGNAL_WEIGHTS` (`services/risk_engine.py`)
3. Tambahkan deskripsinya di `SIGNAL_DESCRIPTIONS`

**Mengganti provider AI:**
1. Buat class baru yang mengimplementasikan `complete()` di `services/ai_analyzer.py`
2. Tambahkan cabang kondisi di `_get_provider()`

**Mengganti provider reputasi URL:**
1. Buat class baru yang mengimplementasikan `check()` di `services/url_checker.py`
2. Tambahkan cabang kondisi di `_get_reputation_provider()`

**Menambah command Telegram baru:**
1. Buat fungsi handler baru di file yang sesuai dalam `handlers/`
2. Daftarkan dengan `application.add_handler(CommandHandler(...))` di `bot.py`

**Menambah tabel/kolom database baru:**
1. Ubah `SCHEMA` di `database.py`
2. Tambahkan fungsi CRUD baru sesuai kebutuhan

---

## Privasi & Keamanan

- Bot **tidak menyimpan** password, OTP, PIN, token, atau data sensitif lain.
- Screenshot diproses sementara untuk OCR, lalu **file langsung dihapus**.
- Database hanya menyimpan metadata ringkas (waktu, jenis input, skor & level risiko)
  untuk keperluan fitur `/history`.
- Gunakan `/delete_history` kapan saja untuk menghapus seluruh riwayat Anda.
- Lihat `/privacy` di dalam bot untuk kebijakan lengkap.
- **Jangan pernah** membagikan OTP, password, atau PIN Anda ke bot, aplikasi,
  atau siapa pun yang tidak berwenang.
