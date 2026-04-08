# VulnScan Pro

> O'zbek tilida professional veb zaiflik skaneri — ruxsat berilgan penetratsion testlar uchun.

![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen?style=flat-square)

---

## ⚠️ Huquqiy Ogohlantirish

**Ushbu vosita FAQAT ruxsat berilgan xavfsizlik testlari uchun mo'ljallangan.**

Foydalanuvchi quyidagilarni tasdiqlaydi:
- Maqsadli tizimni tekshirish uchun **ega tomonidan yozma ruxsat** olingan
- Bu **qonuniy penetratsion test yoki xavfsizlik auditi** doirasida amalga oshirilmoqda
- **Ruxsatsiz skanerlash noqonuniy** ekanligini tushunadi

Muallif va hissadorlar ruxsatsiz yoki noqonuniy foydalanish uchun **hech qanday javobgarlik** ko'tarishmaydi.

---

## Imkoniyatlar

### 8 ta Zaiflik Moduli

| Modul | Texnika | Og'irlik |
|-------|---------|----------|
| 💉 SQL In'ektsiya | Error-based, Boolean-blind, Time-based, Union | Kritik |
| 🎭 XSS | Reflected, DOM-based, Bypass texnikalari | Yuqori / O'rta |
| 🛡️ Xavfsizlik Sarlavhalari | HSTS, CSP, X-Frame-Options, Referrer-Policy | Yuqori / O'rta |
| 🔒 SSL/TLS Tahlili | Protokol versiyasi, cipher kuchi, sertifikat muddati | Kritik – Past |
| 📁 Directory Listing | 500+ yo'l, sezgir fayllar (.env, .git, .bak) | Yuqori / O'rta |
| 🌐 CORS Checker | Origin reflection, null origin, suffix bypass | Kritik / Yuqori |
| ↪️ Open Redirect | 14 ta parametr, 8 ta payload varianti | O'rta |
| 🔌 Port Skaneri | Top 20 port, async TCP ulanish | Yuqori / Ma'lumot |

### Web UI

- **Real-vaqt Streaming** — SSE orqali skan natijalari jonli uzatiladi
- **O'zbek tilida tushuntirish** — har bir zaiflik haqida batafsil o'zbek matn
- **Skan profillari** — Quick / Full / Stealth
- **Tarix** — O'tgan skanlar SQLite da saqlanadi
- **5 ta sahifa** — Bosh sahifa, Skaner, Xizmatlar, Haqida, Aloqa

---

## O'rnatish

### Manba koddan

```bash
git clone https://github.com/YOUR_USERNAME/vulnscan-pro.git
cd vulnscan-pro

# Virtual muhit yaratish
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# yoki: .venv\Scripts\activate   # Windows

# Paketlarni o'rnatish
pip install -e ".[dev]"
```

### Docker orqali

```bash
docker build -t vulnscan .
docker run --rm vulnscan --help
```

---

## Ishga tushirish

### Web UI (Brauzer interfeysi)

```bash
# Web serverini ishga tushirish (port 8719)
vulnscan --web

# Yoki Python orqali to'g'ridan-to'g'ri
python -m vulnscan.web.app
```

Brauzer avtomatik ochiladi: `http://127.0.0.1:8719`

**Sahifalar:**
- `/`         — Bosh sahifa (loyiha haqida)
- `/scan`     — Skanerlash UI
- `/services` — Modullar va imkoniyatlar
- `/about`    — Loyiha haqida batafsil
- `/contact`  — Aloqa va FAQ

### Buyruq satri (CLI)

```bash
# Tez skan (~60 soniya)
vulnscan --target https://example.com

# To'liq skan (barcha modullar)
vulnscan --target https://example.com --scan full --format all

# Burp Suite proksi orqali
vulnscan --target https://example.com --scan full \
         --proxy http://127.0.0.1:8080 --ignore-ssl

# Yashirin skan (past yuklanish, WAF dan qochish)
vulnscan --target https://example.com --scan stealth

# Autentifikatsiyali skan
vulnscan --target https://example.com --scan full \
         --auth admin:password \
         --cookies "session=abc123; csrftoken=xyz"

# Faqat ma'lum modullar
vulnscan --target https://example.com \
         --scan full --modules sqli,xss,headers

# Barcha hisobot formatlarida saqlash
vulnscan --target https://example.com \
         --scan full --format all --output ./reports/scan
```

---

## CLI Opsiyalari

```
  --target       TEXT    Maqsad URL (shart, http:// yoki https://)
  --scan         TYPE    [quick|full|stealth] (standart: quick)
  --web                  Web UI rejimida ishga tushirish
  --modules      LIST    Vergul bilan: sqli,xss,headers,ssl,dirs,cors,redirect
  --threads      INT     Parallel ishchilar soni (standart: 30, max: 100)
  --rps          FLOAT   Soniyada so'rov soni (standart: 10.0)
  --timeout      INT     Har bir so'rov uchun kutish (standart: 10 son.)
  --depth        INT     Crawler chuqurligi (standart: 3)
  --output       PATH    Hisobot fayl yo'li (standart: report_{timestamp})
  --format       TYPE    [html|json|csv|all] (standart: html)
  --proxy        URL     masalan: http://127.0.0.1:8080 (Burp Suite)
  --cookies      TEXT    "nom=qiymat; nom2=qiymat2"
  --headers      TEXT    "Sarlavha: Qiymat" (takrorlanishi mumkin)
  --auth         TEXT    "foydalanuvchi:parol" (HTTP Basic auth)
  --ignore-ssl          SSL sertifikati tekshirishni o'tkazib yuborish
  --ignore-robots       robots.txt ni e'tiborsiz qoldirish
  --exclude      REGEX   Shu regex ga mos URL larni o'tkazib yuborish
  --verbose             Batafsil so'rov/javob loglari
```

---

## Skan Profillari

| Profil | Davomiylik | Modullar | RPS |
|--------|------------|----------|-----|
| `quick` | < 60 soniya | headers, SSL, top dirs | 10 |
| `full` | 2–20 daqiqa | barcha modullar, depth-3 crawl | 10 |
| `stealth` | o'zgaruvchan | barcha modullar (port skanersiz) | 1 |

---

## DVWA da Sinash

```bash
# DVWA ni ishga tushirish
docker compose -f docker-compose.dvwa.yml up -d

# Yoki qo'lda:
docker run -d -p 8080:80 vulnerables/web-dvwa

# To'liq skan
vulnscan --target http://localhost:8080 \
         --scan full --cookies "security=low" \
         --format all --output ./dvwa_report
```

---

## Rivojlantirish

```bash
# Dev paketlarini o'rnatish
make install

# Testlarni ishga tushirish (coverage bilan)
make test

# Lint va type-check
make lint

# Kodni formatlash
make format

# Build artefaktlarini tozalash
make clean
```

---

## Loyiha Tuzilmasi

```
vulnscan/
├── vulnscan/
│   ├── core/           # Rate limiter, HTTP client, base scanner, payload engine
│   ├── modules/        # Skan modullari (sqli, xss, headers, ssl, dirs, cors, redirect)
│   ├── storage/        # aiosqlite orqali saqlash
│   ├── reporting/      # HTML (Jinja2+Chart.js), JSON hisobotlar
│   ├── utils/          # Async crawler, URL utilities, structured logging
│   ├── web/            # FastAPI web server + UI
│   │   ├── app.py      # Routelar va SSE streaming
│   │   ├── templates/  # home, scan, services, about, contact sahifalari
│   │   └── static/     # CSS va JavaScript
│   └── wordlists/      # dirs.txt, sqli_payloads.txt, xss_payloads.txt
└── tests/              # pytest-asyncio + respx mock testlari
```

---

## Hisobotlar

VulnScan Pro uch xil hisobot formati yaratadi:

- **HTML** — Chart.js grafiklar, saralash imkoni, dalillar va tuzatish yo'li
- **JSON** — Mashina o'qiydigan to'liq skan natijasi (Pydantic serialized)

Har bir topilma: og'irlik darajasi, CVSS bali, CWE ID, OWASP yo'naltirish,
payload/dalil va tuzatish tavsiyasi bilan birga keladi.

---

## Chiqish Kodlari

| Kod | Ma'no |
|-----|-------|
| 0 | Skan tugadi, kritik/yuqori topilma yo'q |
| 2 | Skan tugadi, kritik yoki yuqori zaifliklar topildi |
| 130 | Foydalanuvchi to'xtatdi (Ctrl+C) |

---

## Arxitektura

- **Async-first**: barcha I/O `httpx.AsyncClient` + `aiosqlite` ishlatadi
- **Rate limiting**: token-bucket algoritmi, async-xavfsiz
- **Structured logging**: `structlog` JSON chiqishi stderr ga
- **Type-safe**: to'liq mypy strict mode
- **Pydantic v2**: barcha ma'lumot modellari validatsiya bilan
- **False-positive kamaytirish**: aktiv topilmalar uchun ikki bosqichli tasdiqlash

---

## Litsenziya

MIT License. Batafsil uchun `LICENSE` faylini ko'ring.
