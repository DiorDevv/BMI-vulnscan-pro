"""
HTTP security header analyzer.

Design principles:
- Each check only fires when there is *clear evidence* of a problem.
- Every Finding carries a full context block: purpose, current value,
  recommended value, and attack scenarios.
- Informational findings (server/tech disclosure) are kept separate from
  actual security misconfigurations.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

import httpx
import structlog

from ..core.base_scanner import BaseScanner
from ..models.enums import Severity, VulnType
from ..models.finding import Finding

logger = structlog.get_logger(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────

_MIN_HSTS_MAX_AGE = 31_536_000          # 1 year
_SEP = "─" * 60

_SAFE_REFERRER_VALUES = frozenset({
    "no-referrer",
    "strict-origin",
    "strict-origin-when-cross-origin",
})

_SAFE_XFO_VALUES = frozenset({"DENY", "SAMEORIGIN"})

_SAFE_XCTO_VALUE = "nosniff"

_CSP_UNSAFE_RE = re.compile(r"'unsafe-inline'|'unsafe-eval'", re.IGNORECASE)
_CSP_NONCE_RE  = re.compile(r"'nonce-[A-Za-z0-9+/=]+'")
_CSP_HASH_RE   = re.compile(r"'sha(256|384|512)-[A-Za-z0-9+/=]+'")

_SAFE_COOP_VALUES = frozenset({
    "same-origin",
    "same-origin-allow-popups",
})

_TECH_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-wp-total",          # WordPress
    "x-litespeed-cache",
)

_VERSION_RE = re.compile(r"\d+[\.\d]*")


# ─── Evidence builder ─────────────────────────────────────────────────────────

def _evidence(
    header: str,
    purpose: str,
    current: str,
    recommended: str,
    attacks: list[str],
    extra: str = "",
) -> str:
    lines = [
        _SEP,
        f"  [HEADER] {header}",
        _SEP,
        f"  Vazifasi    : {purpose}",
        f"  Joriy qiymat: {current}",
        f"  Tavsiya     : {recommended}",
    ]
    if attacks:
        lines.append("  Hujumlar    :")
        for a in attacks:
            lines.append(f"    • {a}")
    if extra:
        lines.append(f"  Izoh        : {extra}")
    lines.append(_SEP)
    return "\n".join(lines)


# ─── Header checks ────────────────────────────────────────────────────────────

def _check_hsts(url: str, h: dict[str, str]) -> list[Finding]:
    if not url.startswith("https"):
        return []

    hsts = h.get("strict-transport-security")

    if not hsts:
        return [Finding(
            vuln_type=VulnType.MISSING_HEADER,
            severity=Severity.HIGH,
            url=url,
            evidence=_evidence(
                header="Strict-Transport-Security (HSTS)",
                purpose=(
                    "Brauzerga faqat HTTPS orqali muloqot qilishni buyuradi. "
                    "SSL stripping va HTTP downgrade hujumlarini oldini oladi."
                ),
                current="(mavjud emas)",
                recommended="max-age=31536000; includeSubDomains; preload",
                attacks=[
                    "SSL stripping — Ettercap, SSLstrip tool",
                    "HTTP downgrade — foydalanuvchini HTTP ga yo'naltirish",
                    "MITM — plain-text trafik ushlanishi",
                    "Cookie o'g'irlash — Secure flag bo'lsa ham qaytarilish mumkin",
                ],
            ),
            cvss_score=7.4,
            cwe_id="CWE-319",
            owasp_ref="A05:2021",
            remediation=(
                "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
                "NGINX: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
                "Apache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\""
            ),
        )]

    findings: list[Finding] = []

    # max-age check
    ma = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
    if ma:
        age = int(ma.group(1))
        if age < _MIN_HSTS_MAX_AGE:
            findings.append(Finding(
                vuln_type=VulnType.MISSING_HEADER,
                severity=Severity.MEDIUM,
                url=url,
                evidence=_evidence(
                    header="Strict-Transport-Security — max-age juda qisqa",
                    purpose="max-age brauzer HSTS qoidasini qancha vaqt saqlashini belgilaydi.",
                    current=f"max-age={age} ({age // 86400} kun)",
                    recommended="max-age=31536000 (1 yil minimum)",
                    attacks=["Qisqa muddat tugagandan so'ng HTTP ga tushirish mumkin"],
                    extra=f"To'liq sarlavha: {hsts}",
                ),
                cvss_score=5.3,
                cwe_id="CWE-319",
                owasp_ref="A05:2021",
                remediation="max-age ni kamida 31536000 ga oshiring",
            ))

    # includeSubDomains check
    if "includesubdomains" not in hsts.lower():
        findings.append(Finding(
            vuln_type=VulnType.MISSING_HEADER,
            severity=Severity.LOW,
            url=url,
            evidence=_evidence(
                header="Strict-Transport-Security — includeSubDomains yo'q",
                purpose="Subdomenlar HSTS himoyasidan tashqarida qoladi.",
                current=hsts,
                recommended="max-age=31536000; includeSubDomains; preload",
                attacks=["Subdomen orqali cookie o'g'irlash (subdomain hijacking)"],
            ),
            cvss_score=3.7,
            cwe_id="CWE-319",
            owasp_ref="A05:2021",
            remediation="includeSubDomains direktivasini qo'shing",
        ))

    return findings


def _check_csp(url: str, h: dict[str, str]) -> list[Finding]:
    csp = h.get("content-security-policy")
    findings: list[Finding] = []

    if not csp:
        return [Finding(
            vuln_type=VulnType.MISSING_HEADER,
            severity=Severity.HIGH,
            url=url,
            evidence=_evidence(
                header="Content-Security-Policy (CSP)",
                purpose=(
                    "Brauzer qaysi manbalardan skript, stil, rasm yuklashi mumkinligini cheklaydi. "
                    "XSS hujumlarining asosiy mudofaa chizig'i."
                ),
                current="(mavjud emas)",
                recommended="default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
                attacks=[
                    "Reflected XSS — zararli skript kiritish",
                    "Stored XSS — ma'lumotlar bazasiga skript saqlash",
                    "DOM-based XSS — JavaScript orqali DOM o'zgartirish",
                    "Clickjacking — iframe ichida saytni ko'rsatish",
                    "Data exfiltration — foydalanuvchi ma'lumotlarini tashqi serverga yuborish",
                ],
            ),
            cvss_score=6.1,
            cwe_id="CWE-1021",
            owasp_ref="A05:2021",
            remediation=(
                "NGINX: add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;\n"
                "Meta tag (fallback): <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\">"
            ),
        )]

    csp_lower = csp.lower()

    # unsafe-inline / unsafe-eval without nonce or hash
    if _CSP_UNSAFE_RE.search(csp):
        has_nonce = bool(_CSP_NONCE_RE.search(csp))
        has_hash  = bool(_CSP_HASH_RE.search(csp))
        if not has_nonce and not has_hash:
            findings.append(Finding(
                vuln_type=VulnType.MISSING_HEADER,
                severity=Severity.MEDIUM,
                url=url,
                evidence=_evidence(
                    header="CSP — 'unsafe-inline' / 'unsafe-eval' mavjud",
                    purpose="Bu direktivalar CSP ni amalda ishlamasiz qilib qo'yadi.",
                    current=csp[:300],
                    recommended="Nonce yoki hash asosida CSP: script-src 'nonce-{random}'",
                    attacks=[
                        "unsafe-inline → inline <script> XSS ishlaydi",
                        "unsafe-eval → eval() orqali kod bajarish mumkin",
                    ],
                    extra="Agar inline skript kerak bo'lsa, 'nonce-{base64}' yoki 'sha256-{hash}' ishlatish kerak",
                ),
                cvss_score=5.4,
                cwe_id="CWE-1021",
                owasp_ref="A05:2021",
                remediation="unsafe-inline va unsafe-eval ni olib tashlang. Nonce yoki hash ishlatishga o'ting.",
            ))

    # missing default-src
    if "default-src" not in csp_lower:
        findings.append(Finding(
            vuln_type=VulnType.MISSING_HEADER,
            severity=Severity.MEDIUM,
            url=url,
            evidence=_evidence(
                header="CSP — default-src yo'q",
                purpose="default-src barcha boshqa direktivalar uchun zaxira qiymat.",
                current=csp[:300],
                recommended="default-src 'self' qo'shing",
                attacks=["Ko'rsatilmagan manbalar uchun cheklov yo'q — tashqi resurslar yuklanishi mumkin"],
            ),
            cvss_score=4.3,
            cwe_id="CWE-1021",
            owasp_ref="A05:2021",
            remediation="CSP ga default-src 'self' qo'shing",
        ))

    # object-src check — Flash, Java applet
    if "object-src" not in csp_lower and "default-src 'none'" not in csp_lower:
        findings.append(Finding(
            vuln_type=VulnType.MISSING_HEADER,
            severity=Severity.LOW,
            url=url,
            evidence=_evidence(
                header="CSP — object-src cheklanmagan",
                purpose="object-src Flash, Java applet va boshqa plugin-larni cheklaydi.",
                current=csp[:300],
                recommended="object-src 'none'",
                attacks=["Flash/plugin orqali XSS yoki kod bajarish (eski brauzerlar)"],
            ),
            cvss_score=3.1,
            cwe_id="CWE-1021",
            owasp_ref="A05:2021",
            remediation="object-src 'none' qo'shing",
        ))

    return findings


def _check_xcto(url: str, h: dict[str, str]) -> list[Finding]:
    value = h.get("x-content-type-options", "").strip().lower()
    if value == _SAFE_XCTO_VALUE:
        return []
    return [Finding(
        vuln_type=VulnType.MISSING_HEADER,
        severity=Severity.MEDIUM,
        url=url,
        evidence=_evidence(
            header="X-Content-Type-Options",
            purpose=(
                "Brauzerga MIME turini o'z-o'zicha aniqlashni taqiqlaydi (MIME sniffing). "
                "Noto'g'ri MIME bilan yuborilgan zararli fayllarni bajarishni oldini oladi."
            ),
            current=repr(value) if value else "(mavjud emas)",
            recommended="nosniff",
            attacks=[
                "MIME type confusion — zararli faylni boshqa tur sifatida render qilish",
                "Skript sifatida yuklangan rasm fayli (SVG, HTML)",
                "Content-type bypass orqali XSS",
            ],
        ),
        cvss_score=4.3,
        cwe_id="CWE-16",
        owasp_ref="A05:2021",
        remediation="X-Content-Type-Options: nosniff",
    )]


def _check_xfo(url: str, h: dict[str, str]) -> list[Finding]:
    value = h.get("x-frame-options", "").strip().upper()
    csp = h.get("content-security-policy", "")

    # CSP frame-ancestors is the modern equivalent — skip if present
    if "frame-ancestors" in csp.lower():
        return []

    if value in _SAFE_XFO_VALUES:
        return []

    return [Finding(
        vuln_type=VulnType.MISSING_HEADER,
        severity=Severity.MEDIUM,
        url=url,
        evidence=_evidence(
            header="X-Frame-Options",
            purpose=(
                "Saytingizni boshqa sayt iframe ichida ko'rsatishini taqiqlaydi. "
                "Clickjacking hujumidan himoya qiladi."
            ),
            current=repr(value) if value else "(mavjud emas)",
            recommended="DENY yoki SAMEORIGIN",
            attacks=[
                "Clickjacking — foydalanuvchi aslida boshqa narsani bosadi",
                "UI redressing — interfeys ustiga shaffof iframe qo'yish",
                "Like-jacking, share-jacking — ijtimoiy tarmoqda hujum",
                "One-click attack — bank transferini tasdiqlash",
            ],
            extra="Zamonaviy yechim: CSP frame-ancestors 'none' yoki 'self'",
        ),
        cvss_score=4.3,
        cwe_id="CWE-1021",
        owasp_ref="A05:2021",
        remediation=(
            "X-Frame-Options: DENY\n"
            "Yoki CSP: Content-Security-Policy: frame-ancestors 'none'"
        ),
    )]


def _check_referrer_policy(url: str, h: dict[str, str]) -> list[Finding]:
    value = h.get("referrer-policy", "").strip().lower()
    if value in _SAFE_REFERRER_VALUES:
        return []
    return [Finding(
        vuln_type=VulnType.MISSING_HEADER,
        severity=Severity.LOW,
        url=url,
        evidence=_evidence(
            header="Referrer-Policy",
            purpose=(
                "Foydalanuvchi havolani bosganida qaysi URL ma'lumoti "
                "Referer sarlavhasida yuborilishini boshqaradi."
            ),
            current=repr(value) if value else "(mavjud emas — brauzer default ishlatadi)",
            recommended="strict-origin-when-cross-origin",
            attacks=[
                "URL dagi token/sessiya ma'lumoti uchinchi tomon saytiga ketadi",
                "Internal URL tuzilmasi oshkor bo'lishi",
                "Analytics va tracking orqali ma'lumot nusxa ko'chirish",
            ],
        ),
        cvss_score=3.1,
        cwe_id="CWE-16",
        owasp_ref="A05:2021",
        remediation="Referrer-Policy: strict-origin-when-cross-origin",
    )]


def _check_permissions_policy(url: str, h: dict[str, str]) -> list[Finding]:
    # Eski nomi Feature-Policy ham bo'lgan
    value = h.get("permissions-policy") or h.get("feature-policy")
    if value:
        return []
    return [Finding(
        vuln_type=VulnType.MISSING_HEADER,
        severity=Severity.LOW,
        url=url,
        evidence=_evidence(
            header="Permissions-Policy (Feature-Policy)",
            purpose=(
                "Brauzer imkoniyatlarini (kamera, mikrofon, geolokatsiya, to'lov) "
                "cheklaydi. Ilovaning faqat kerakli imkoniyatlardan foydalanishini ta'minlaydi."
            ),
            current="(mavjud emas)",
            recommended="camera=(), microphone=(), geolocation=(), payment=()",
            attacks=[
                "Zararli iframe saytdan kamera/mikrofon ruxsat so'rashi",
                "Geolokatsiya orqali foydalanuvchi joylashuvini aniqlash",
                "Payment API suiiste'mol qilish",
            ],
        ),
        cvss_score=2.7,
        cwe_id="CWE-16",
        owasp_ref="A05:2021",
        remediation="Permissions-Policy: camera=(), microphone=(), geolocation=()",
    )]


def _check_coop(url: str, h: dict[str, str]) -> list[Finding]:
    if not url.startswith("https"):
        return []
    value = h.get("cross-origin-opener-policy", "").strip().lower()
    if value in _SAFE_COOP_VALUES:
        return []
    return [Finding(
        vuln_type=VulnType.MISSING_HEADER,
        severity=Severity.LOW,
        url=url,
        evidence=_evidence(
            header="Cross-Origin-Opener-Policy (COOP)",
            purpose=(
                "Brauzer sahifasini boshqa kelib chiqishdagi oynalardan ajratadi. "
                "Spectre kabi side-channel hujumlardan va popup-based hujumlardan himoya."
            ),
            current=repr(value) if value else "(mavjud emas)",
            recommended="same-origin",
            attacks=[
                "Cross-origin window reference abuse",
                "Spectre/Meltdown side-channel — SharedArrayBuffer orqali",
                "Popup-based CSRF va phishing",
            ],
        ),
        cvss_score=2.7,
        cwe_id="CWE-346",
        owasp_ref="A05:2021",
        remediation="Cross-Origin-Opener-Policy: same-origin",
    )]


def _check_cors(url: str, h: dict[str, str]) -> list[Finding]:
    acao = h.get("access-control-allow-origin", "").strip()
    acac = h.get("access-control-allow-credentials", "").strip().lower()
    acam = h.get("access-control-allow-methods", "").strip()

    if not acao:
        return []

    findings: list[Finding] = []

    if acao == "*":
        is_creds = acac == "true"
        sev   = Severity.CRITICAL if is_creds else Severity.HIGH
        cvss  = 9.1 if is_creds else 7.5
        extra = (
            "CRITICAL: * + credentials=true birgalikda brauzer tomonidan bloklanadi, "
            "lekin ba'zi eskiroq kutubxonalar qabul qilishi mumkin."
            if is_creds else ""
        )
        findings.append(Finding(
            vuln_type=VulnType.CORS,
            severity=sev,
            url=url,
            evidence=_evidence(
                header="Access-Control-Allow-Origin: *",
                purpose=(
                    "CORS — boshqa domenlardan JavaScript so'rovlariga ruxsat beradi. "
                    "Wildcard (*) BARCHA domenga ruxsat beradi."
                ),
                current=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                recommended="Aniq domen ko'rsating: Access-Control-Allow-Origin: https://trusted.example.com",
                attacks=[
                    "Har qanday sayt sizning API ga foydalanuvchi nomidan so'rov yuborishi mumkin",
                    "Cookie va session token o'g'irlash (credentials=true bilan)",
                    "CSRF-like attack — CORS orqali",
                    "Private API ma'lumotlarini uchinchi tomon saytidan o'qish",
                ],
                extra=extra,
            ),
            cvss_score=cvss,
            cwe_id="CWE-942",
            owasp_ref="A05:2021",
            remediation=(
                "Aniq domenlar ro'yxatini saqlang va dinamik tekshirish qiling:\n"
                "ALLOWED = {'https://app.example.com'}\n"
                "if origin in ALLOWED: response.headers['ACAO'] = origin"
            ),
        ))

    # Xavfli metodlar
    if acam and any(m.strip().upper() in ("DELETE", "PUT", "PATCH") for m in acam.split(",")):
        findings.append(Finding(
            vuln_type=VulnType.CORS,
            severity=Severity.MEDIUM,
            url=url,
            evidence=_evidence(
                header="Access-Control-Allow-Methods — xavfli metodlar",
                purpose="CORS preflight javobi qaysi HTTP metodlarga ruxsat berilishini ko'rsatadi.",
                current=f"Access-Control-Allow-Methods: {acam}",
                recommended="Faqat kerakli metodlar: GET, POST",
                attacks=["DELETE/PUT ruxsati bilan CORS orqali resurslarni o'chirish/o'zgartirish"],
            ),
            cvss_score=4.8,
            cwe_id="CWE-942",
            owasp_ref="A05:2021",
            remediation="Access-Control-Allow-Methods ni minimal to'plam bilan cheklang",
        ))

    return findings


def _check_xxss(url: str, h: dict[str, str]) -> list[Finding]:
    """X-XSS-Protection eskirgan — noto'g'ri qiymat xavf tug'diradi."""
    value = h.get("x-xss-protection", "").strip()
    if not value:
        return []   # yo'q bo'lsa muammo emas (zamonaviy brauzerlar CSP ishlatadi)

    # "1; mode=block" yoki "0" qabul qilinadi; "1" (block yo'q) xavfli
    if value == "1":
        return [Finding(
            vuln_type=VulnType.MISSING_HEADER,
            severity=Severity.LOW,
            url=url,
            evidence=_evidence(
                header="X-XSS-Protection: 1 (mode=block yo'q)",
                purpose=(
                    "Eskirgan IE/Chrome XSS filter. Zamonaviy brauzerlarda ishlamaydi. "
                    "mode=block bo'lmasa filter ba'zi hollarda XSS ga yo'l ochishi mumkin."
                ),
                current="X-XSS-Protection: 1",
                recommended="0 (o'chirib qo'ying, CSP ga ishoraning) yoki 1; mode=block",
                attacks=["XSS auditor bypass — filter noto'g'ri ishlashi XSS imkonini berishi mumkin"],
            ),
            cvss_score=2.4,
            cwe_id="CWE-16",
            owasp_ref="A05:2021",
            remediation=(
                "X-XSS-Protection: 0  (va kuchli CSP qo'shing)\n"
                "Yoki: X-XSS-Protection: 1; mode=block"
            ),
        )]
    return []


def _check_server_disclosure(url: str, h: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    tech_info: list[str] = []

    for hdr in _TECH_HEADERS:
        val = h.get(hdr, "").strip()
        if val:
            tech_info.append(f"{hdr}: {val}")

    if not tech_info:
        return []

    # Xavfli: versiya raqami oshkor bo'lsa
    version_leak = [t for t in tech_info if _VERSION_RE.search(t)]
    if version_leak:
        findings.append(Finding(
            vuln_type=VulnType.MISSING_HEADER,
            severity=Severity.LOW,
            url=url,
            evidence=_evidence(
                header="Server/Texnologiya versiyasi oshkorligi",
                purpose="Server sarlavhalari texnologiya stacki va versiyasini oshkor qiladi.",
                current="\n  ".join(version_leak),
                recommended="Versiya ma'lumotini yashiring",
                attacks=[
                    "Aniq versiyaga mos CVE qidirish (Shodan, Exploit-DB)",
                    "Maqsadli exploit tanlash — versiyaga qarab",
                    "Fingerprinting — to'liq stack aniqlash",
                ],
                extra="Bu o'z-o'zicha kritik emas, lekin boshqa zaifliklar bilan birgalikda xavfli.",
            ),
            cvss_score=2.7,
            cwe_id="CWE-200",
            owasp_ref="A05:2021",
            remediation=(
                "NGINX: server_tokens off;\n"
                "Apache: ServerTokens Prod; ServerSignature Off\n"
                "PHP: expose_php = Off (php.ini)"
            ),
        ))
    elif tech_info:
        # Versiyasiz texnologiya nomi — faqat INFO
        findings.append(Finding(
            vuln_type=VulnType.MISSING_HEADER,
            severity=Severity.INFO,
            url=url,
            evidence=_evidence(
                header="Texnologiya oshkorligi (versiyasiz)",
                purpose="Texnologiya nomi oshkor bo'lsa ham fingerprinting mumkin.",
                current="\n  ".join(tech_info),
                recommended="Barcha texnologiya sarlavhalarini yashiring",
                attacks=["Stack aniqlash — Apache vs Nginx vs IIS farqli exploit"],
            ),
            cvss_score=0.0,
            cwe_id="CWE-200",
            owasp_ref="A05:2021",
            remediation="Server sarlavhasini to'liq yashirish yoki umumiy qiymat ko'rsatish",
        ))

    return findings


def _check_cookies(url: str, h: dict[str, str]) -> list[Finding]:
    """Set-Cookie sarlavhalaridan xavfsizlik flaglarini tekshirish."""
    # httpx bir nechta Set-Cookie sarlavhasini birlashtiradi
    raw = h.get("set-cookie", "")
    if not raw:
        return []

    findings: list[Finding] = []
    # httpx'da multi-value headerlar vergul bilan birlashtirilib kelishi mumkin,
    # leun cookie qiymatlari ichida ham vergul bo'lishi mumkin. Biz `; ` orqali parse qilamiz.
    cookies = [c.strip() for c in re.split(r",(?=[^ ])", raw)]

    for cookie_str in cookies:
        parts = [p.strip().lower() for p in cookie_str.split(";")]
        name_part = cookie_str.split(";")[0].split("=")[0].strip()
        flags = set(parts[1:])  # skip name=value

        missing: list[str] = []
        if "httponly" not in flags:
            missing.append("HttpOnly — JavaScript cookie ni o'qiy oladi (XSS xavfi)")
        if url.startswith("https") and "secure" not in flags:
            missing.append("Secure — cookie HTTP orqali ham yuboriladi")
        if not any(f.startswith("samesite") for f in flags):
            missing.append("SameSite — cross-site so'rovlarda cookie yuboriladi (CSRF xavfi)")

        if missing:
            findings.append(Finding(
                vuln_type=VulnType.MISSING_HEADER,
                severity=Severity.MEDIUM,
                url=url,
                evidence=_evidence(
                    header=f"Cookie xavfsizlik flagi — {name_part}",
                    purpose=(
                        "Cookie flaglari cookie qachon va qanday yuborilishini boshqaradi. "
                        "Yo'qolgan flaglar XSS va CSRF hujumlariga yo'l ochadi."
                    ),
                    current=cookie_str[:200],
                    recommended=f"{name_part}=value; HttpOnly; Secure; SameSite=Strict",
                    attacks=missing,
                ),
                cvss_score=5.4,
                cwe_id="CWE-1004",
                owasp_ref="A05:2021",
                remediation=(
                    f"Set-Cookie: {name_part}=value; HttpOnly; Secure; SameSite=Strict; Path=/"
                ),
            ))

    return findings


# ─── Check registry (tartiblangan) ───────────────────────────────────────────

_CHECKS: list[Callable[[str, dict[str, str]], list[Finding]]] = [
    _check_hsts,
    _check_csp,
    _check_xcto,
    _check_xfo,
    _check_referrer_policy,
    _check_permissions_policy,
    _check_coop,
    _check_cors,
    _check_xxss,
    _check_server_disclosure,
    _check_cookies,
]


# ─── Grade calculator ─────────────────────────────────────────────────────────

def _grade(h: dict[str, str], is_https: bool) -> str:
    score = 0
    max_score = 0

    checks = [
        (is_https and bool(h.get("strict-transport-security")), 20),
        (bool(h.get("content-security-policy")), 20),
        (h.get("x-content-type-options", "").lower() == "nosniff", 15),
        (h.get("x-frame-options", "").upper() in _SAFE_XFO_VALUES
         or "frame-ancestors" in h.get("content-security-policy", "").lower(), 15),
        (h.get("referrer-policy", "").lower() in _SAFE_REFERRER_VALUES, 10),
        (bool(h.get("permissions-policy") or h.get("feature-policy")), 10),
        (h.get("cross-origin-opener-policy", "").lower() in _SAFE_COOP_VALUES, 10),
    ]

    for passed, weight in checks:
        max_score += weight
        if passed:
            score += weight

    pct = (score / max_score * 100) if max_score else 0
    if pct >= 95: return "A+"
    if pct >= 80: return "A"
    if pct >= 65: return "B"
    if pct >= 50: return "C"
    if pct >= 35: return "D"
    return "F"


# ─── Scanner class ────────────────────────────────────────────────────────────

class HeaderAnalyzer(BaseScanner):
    """
    HTTP security response header analyzer.

    Runs 11 distinct checks. Each finding includes: purpose, current value,
    recommended value, and concrete attack scenarios.
    """

    async def scan(self, url: str) -> list[Finding]:
        resp = await self._fetch(url)
        if resp is None:
            return []

        headers = {k.lower(): v for k, v in resp.headers.items()}
        is_https = url.startswith("https")
        findings: list[Finding] = []

        for check in _CHECKS:
            try:
                findings.extend(check(url, headers))
            except Exception as exc:
                logger.warning("header_check_error", check=check.__name__, error=str(exc))

        security_grade = _grade(headers, is_https)
        logger.info(
            "header_analysis_complete",
            url=url,
            grade=security_grade,
            findings=len(findings),
            status=resp.status_code,
        )
        return findings

    async def _fetch(self, url: str) -> httpx.Response | None:
        """HEAD first, GET as fallback — some servers ignore HEAD."""
        for method in ("HEAD", "GET"):
            try:
                return await self._request(method, url)
            except Exception as exc:
                logger.debug("header_fetch_failed", method=method, url=url, error=str(exc))
        return None
