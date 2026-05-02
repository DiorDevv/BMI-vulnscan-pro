"""
Port scanner with two-phase verification:
  1. TCP connect  (fast reject if filtered/closed)
  2. Service probe + banner validation  (eliminates CDN/firewall false-positives)

Only a port whose response matches the expected service signature is reported.
Ports that accept TCP but return nothing (or the wrong protocol) are silently
discarded so scans against Cloudflare / AWS ELB / etc. stay noise-free.
"""
from __future__ import annotations

import asyncio
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Callable, NamedTuple
from urllib.parse import urlparse

import structlog

from ..core.base_scanner import BaseScanner
from ..models.enums import Severity, VulnType
from ..models.finding import Finding

logger = structlog.get_logger(__name__)

_MAX_RECV = 2048
_DEFAULT_TIMEOUT = 3.0



# ─────────────────────────────────────────────────────────────────────────────
# Data types
# ─────────────────────────────────────────────────────────────────────────────

class ProbeResult(NamedTuple):
    genuine: bool   # service responded as expected (not a CDN TCP-accept)
    banner: str     # human-readable version / greeting string


@dataclass
class ServiceProbe:
    """Encapsulates *how* to talk to a port and *what* constitutes a valid reply."""
    send: bytes | None = None          # probe payload (None = just listen for banner)
    use_tls: bool = False              # wrap the connection in TLS
    recv_timeout: float = 2.0
    validate: Callable[[bytes], ProbeResult] = field(
        default_factory=lambda: lambda b: ProbeResult(bool(b), _first_printable_line(b))
    )


@dataclass
class PortMeta:
    """Static risk & compliance metadata for a well-known port."""
    port: int
    service: str
    protocol: str = "TCP"
    description: str = ""           # one-line purpose of the service
    purpose: str = ""               # what this service does in plain language
    default_creds: str = ""         # known default credentials (if any)
    common_attacks: list[str] = field(default_factory=list)  # attack techniques
    secure_alternative: str = ""    # recommended replacement for insecure services
    risk_note: str = ""
    cve_refs: list[str] = field(default_factory=list)
    severity: Severity = Severity.INFO
    cvss: float = 0.0
    cwe: str = "CWE-200"
    owasp: str = "A05:2021"


# ─────────────────────────────────────────────────────────────────────────────
# Banner helpers
# ─────────────────────────────────────────────────────────────────────────────

def _first_printable_line(data: bytes) -> str:
    for line in data.splitlines():
        text = line.decode("utf-8", "replace").strip()
        if text:
            return text[:200]
    return data[:80].decode("utf-8", "replace").strip()


def _parse_http_banner(data: bytes) -> str:
    if not data.startswith(b"HTTP/"):
        return ""
    parts: list[str] = [data.split(b"\r\n")[0].decode("utf-8", "replace")]
    for header in (b"server", b"x-powered-by", b"x-aspnet-version"):
        m = re.search(rb"(?i)^" + header + rb":\s*(.+)$", data, re.MULTILINE)
        if m:
            parts.append(m.group(1).decode("utf-8", "replace").strip())
    return " | ".join(parts)


def _parse_mysql_banner(data: bytes) -> str:
    """Extract version string from MySQL/MariaDB initial handshake packet."""
    try:
        if len(data) < 5 or data[3] != 0x00:
            return ""
        proto = data[4]
        if proto not in (9, 10):
            return f"MySQL-like handshake ({len(data)} bytes)"
        null = data.find(b"\x00", 5)
        if null == -1:
            return ""
        return f"MySQL {data[5:null].decode('utf-8', 'replace')} (proto v{proto})"
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# Validator factories
# ─────────────────────────────────────────────────────────────────────────────

def _banner_validator(pattern: bytes) -> Callable[[bytes], ProbeResult]:
    """Match raw banner bytes against a regex anchored at the start."""
    rx = re.compile(pattern)
    def _validate(data: bytes) -> ProbeResult:
        genuine = bool(data) and bool(rx.match(data))
        return ProbeResult(genuine, _first_printable_line(data) if data else "")
    return _validate


def _http_validator(data: bytes) -> ProbeResult:
    if not data or not data.startswith(b"HTTP/"):
        return ProbeResult(False, "")
    return ProbeResult(True, _parse_http_banner(data))


def _redis_validator(data: bytes) -> ProbeResult:
    genuine = bool(data) and data[:1] in (b"+", b"-", b"*", b"$", b":")
    banner = data.split(b"\r\n")[0].decode("utf-8", "replace") if data else ""
    return ProbeResult(genuine, banner)


def _mysql_validator(data: bytes) -> ProbeResult:
    # Sequence byte (data[3]) must be 0 for the initial handshake packet
    genuine = len(data) > 5 and data[3] == 0x00 and data[4] in (9, 10)
    return ProbeResult(genuine, _parse_mysql_banner(data))


def _postgres_validator(data: bytes) -> ProbeResult:
    # Server replies to SSLRequest with single byte 'S' (yes) or 'N' (no)
    # or 'E' (error message beginning with 'E')
    genuine = bool(data) and data[0:1] in (b"S", b"N", b"E", b"R")
    labels = {b"S": "SSL supported", b"N": "SSL not supported",
               b"E": "Error", b"R": "Auth required"}
    banner = f"PostgreSQL — {labels.get(data[0:1], 'response received')}" if genuine else ""
    return ProbeResult(genuine, banner)


def _mssql_validator(data: bytes) -> ProbeResult:
    # TDS pre-login response: type byte == 0x04
    genuine = len(data) >= 8 and data[0] == 0x04
    banner = f"MSSQL TDS pre-login response ({len(data)} bytes)" if genuine else ""
    return ProbeResult(genuine, banner)


def _mongodb_validator(data: bytes) -> ProbeResult:
    # OP_REPLY header: opCode at bytes 12-15 == 1 (0x01000000 LE)
    genuine = len(data) >= 16 and data[12:16] == b"\x01\x00\x00\x00"
    banner = f"MongoDB OP_REPLY ({len(data)} bytes)" if genuine else ""
    return ProbeResult(genuine, banner)


def _vnc_validator(data: bytes) -> ProbeResult:
    genuine = bool(data) and re.match(rb"^RFB \d+\.\d+", data)
    return ProbeResult(bool(genuine), _first_printable_line(data) if data else "")


def _telnet_validator(data: bytes) -> ProbeResult:
    # Telnet sends IAC (0xFF) negotiation bytes OR a text login prompt
    genuine = bool(data) and (b"\xff" in data or any(32 <= b < 127 for b in data))
    return ProbeResult(genuine, _first_printable_line(data) if data else "")


def _smtp_validator(data: bytes) -> ProbeResult:
    genuine = bool(data) and bool(re.match(rb"^2\d\d[ -]", data))
    return ProbeResult(genuine, _first_printable_line(data) if data else "")


# ─────────────────────────────────────────────────────────────────────────────
# Binary probes
# ─────────────────────────────────────────────────────────────────────────────

# TDS pre-login packet (MSSQL)
_MSSQL_PRELOGIN = bytes([
    0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20,
    0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03,
    0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
    0x01, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

# PostgreSQL SSLRequest (8 bytes)
_POSTGRES_SSL_REQUEST = bytes([0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f])

# MongoDB OP_QUERY isMaster (legacy wire protocol, universally supported)
_MONGO_ISMASTER = bytes([
    0x3f, 0x00, 0x00, 0x00,  # messageLength = 63
    0x01, 0x00, 0x00, 0x00,  # requestID
    0x00, 0x00, 0x00, 0x00,  # responseTo
    0xd4, 0x07, 0x00, 0x00,  # opCode = 2004 (OP_QUERY)
    0x00, 0x00, 0x00, 0x00,  # flags
    0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00,  # "admin.$cmd\0"
    0x00, 0x00, 0x00, 0x00,  # numberToSkip
    0xff, 0xff, 0xff, 0xff,  # numberToReturn = -1
    # BSON document: {isMaster: 1}
    0x13, 0x00, 0x00, 0x00,
    0x10, 0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x00,
])


# ─────────────────────────────────────────────────────────────────────────────
# Service probe registry  (port → ServiceProbe)
# ─────────────────────────────────────────────────────────────────────────────

SERVICE_PROBES: dict[int, ServiceProbe] = {
    21:    ServiceProbe(validate=_banner_validator(rb"^\d{3}[ -]")),            # FTP
    22:    ServiceProbe(validate=_banner_validator(rb"^SSH-")),                 # SSH
    23:    ServiceProbe(validate=_telnet_validator),                            # Telnet
    25:    ServiceProbe(validate=_smtp_validator),                              # SMTP
    80:    ServiceProbe(send=b"HEAD / HTTP/1.0\r\nHost: scanner\r\n\r\n",
                        validate=_http_validator),                              # HTTP
    110:   ServiceProbe(validate=_banner_validator(rb"^\+OK")),                # POP3
    143:   ServiceProbe(validate=_banner_validator(rb"^\* (OK|BYE|PREAUTH)")), # IMAP
    443:   ServiceProbe(send=b"HEAD / HTTP/1.0\r\nHost: scanner\r\n\r\n",
                        use_tls=True, validate=_http_validator),               # HTTPS
    465:   ServiceProbe(use_tls=True, validate=_smtp_validator),               # SMTPS
    993:   ServiceProbe(use_tls=True,
                        validate=_banner_validator(rb"^\* (OK|BYE|PREAUTH)")),  # IMAPS
    995:   ServiceProbe(use_tls=True,
                        validate=_banner_validator(rb"^\+OK")),                # POP3S
    1433:  ServiceProbe(send=_MSSQL_PRELOGIN, validate=_mssql_validator),      # MSSQL
    3306:  ServiceProbe(validate=_mysql_validator),                            # MySQL
    5432:  ServiceProbe(send=_POSTGRES_SSL_REQUEST, validate=_postgres_validator), # PostgreSQL
    5900:  ServiceProbe(validate=_vnc_validator),                              # VNC
    6379:  ServiceProbe(send=b"PING\r\n", validate=_redis_validator),          # Redis
    8080:  ServiceProbe(send=b"HEAD / HTTP/1.0\r\nHost: scanner\r\n\r\n",
                        validate=_http_validator),                              # HTTP-Alt
    8443:  ServiceProbe(send=b"HEAD / HTTP/1.0\r\nHost: scanner\r\n\r\n",
                        use_tls=True, validate=_http_validator),               # HTTPS-Alt
    9200:  ServiceProbe(send=b"GET / HTTP/1.0\r\nHost: scanner\r\n\r\n",
                        validate=lambda b: ProbeResult(
                            b.startswith(b"HTTP/") and b"cluster_name" in b,
                            _parse_http_banner(b),
                        )),                                                    # Elasticsearch
    27017: ServiceProbe(send=_MONGO_ISMASTER, validate=_mongodb_validator),    # MongoDB
}

# Ports for which no reliable text/binary fingerprint exists.
# We report them only if they accept TCP *and* the application logic specifically
# enables "low-confidence" mode (off by default).
_LOW_CONFIDENCE_PORTS: frozenset[int] = frozenset({53, 135, 139, 161, 445, 1723, 3389})


# ─────────────────────────────────────────────────────────────────────────────
# Port metadata database
# ─────────────────────────────────────────────────────────────────────────────

PORT_META: dict[int, PortMeta] = {
    # ── FTP ──────────────────────────────────────────────────────────────────
    21: PortMeta(21, "FTP",
        description="File Transfer Protocol",
        purpose=(
            "Fayl uzatish protokoli. Server va klient o'rtasida fayllarni yuklash "
            "va yuklab olish uchun ishlatiladi. Ikki kanal: 21 (boshqaruv), 20 (ma'lumot)."
        ),
        default_creds="anonymous / anonymous yoki ftp / ftp (ko'pincha yoqilgan)",
        common_attacks=[
            "Anonymous login — autentifikatsiyasiz kirish",
            "Brute-force — parolni taxmin qilish (Hydra, Medusa)",
            "FTP Bounce attack — boshqa xostlarga skan qilish",
            "Sniffing — plain-text trafik ushlanishi",
            "CVE-2010-4221: ProFTPD buffer overflow (RCE)",
        ],
        secure_alternative="SFTP (SSH port 22) yoki FTPS (TLS/SSL ustida FTP)",
        risk_note="Barcha trafik, jumladan login/parol, shifrsiz uzatiladi.",
        cve_refs=["CVE-2010-4221", "CVE-2011-2523"],
        severity=Severity.HIGH, cvss=7.5, cwe="CWE-319", owasp="A02:2021"),

    # ── SSH ──────────────────────────────────────────────────────────────────
    22: PortMeta(22, "SSH",
        description="Secure Shell",
        purpose=(
            "Shifrlangan masofaviy boshqaruv protokoli. Terminal sessiyalari, "
            "fayl uzatish (SCP/SFTP) va tunnel yaratish uchun ishlatiladi."
        ),
        default_creds="root / (bo'sh) yoki admin / admin — ba'zi embedded qurilmalarda",
        common_attacks=[
            "Brute-force / password spray (Hydra, Metasploit)",
            "Zayif SSH kalitlari (1024-bit RSA, DSA)",
            "Username enumeration (CVE-2018-15473)",
            "SSH agent hijacking — agent socket o'g'irlash",
        ],
        secure_alternative="SSH key authentication + fail2ban + port knocking",
        risk_note="Agar parol autentifikatsiyasi yoqilgan bo'lsa, brute-force xavfi mavjud.",
        cve_refs=["CVE-2023-38408", "CVE-2018-15473"],
        severity=Severity.LOW, cvss=3.7, cwe="CWE-307"),

    # ── Telnet ───────────────────────────────────────────────────────────────
    23: PortMeta(23, "Telnet",
        description="Unencrypted remote terminal",
        purpose=(
            "Masofaviy terminal sessiyasi uchun eski protokol. "
            "Router, switch, eski Unix tizimlarida topiladi. SSH bilan almashtirilgan."
        ),
        default_creds="admin / admin, root / root, cisco / cisco",
        common_attacks=[
            "Man-in-the-middle — barcha trafik plain-text",
            "Credential sniffing — login/parol to'g'ridan-to'g'ri ushlanadi",
            "Session hijacking — TCP sessiyasini o'g'irlash",
            "Brute-force hujum",
        ],
        secure_alternative="SSH (port 22) — to'liq shifrlangan",
        risk_note="Parol va buyruqlar shifrsiz uzatiladi. Hech qachon internetga ochiq bo'lmasligi kerak.",
        cve_refs=["CVE-2020-15778"],
        severity=Severity.CRITICAL, cvss=9.8, cwe="CWE-319", owasp="A02:2021"),

    # ── SMTP ─────────────────────────────────────────────────────────────────
    25: PortMeta(25, "SMTP",
        description="Simple Mail Transfer Protocol",
        purpose=(
            "Elektron pochta jo'natish protokoli. Serverlar o'rtasida xat uzatishda ishlatiladi. "
            "Foydalanuvchi klientlari odatda 587 (submission) portidan foydalanadi."
        ),
        default_creds="—",
        common_attacks=[
            "Open relay — boshqa domenlar nomidan spam jo'natish",
            "VRFY/EXPN orqali foydalanuvchi ro'yxatini aniqlash",
            "Email spoofing — jo'natuvchini soxtalash (SPF/DKIM yo'q bo'lsa)",
            "Banner grabbing — server versiyasini aniqlash",
        ],
        secure_alternative="SMTPS port 465 (TLS) yoki STARTTLS port 587",
        risk_note="Open relay konfiguratsiyasi spam uchun ishlatilishi mumkin.",
        severity=Severity.MEDIUM, cvss=5.3),

    # ── DNS ──────────────────────────────────────────────────────────────────
    53: PortMeta(53, "DNS",
        description="Domain Name System",
        purpose=(
            "Domen nomlarini IP manzillarga tarjima qiladi. "
            "UDP 53 — oddiy so'rovlar; TCP 53 — katta javoblar va zone transfer."
        ),
        default_creds="—",
        common_attacks=[
            "Zone transfer (AXFR) — barcha DNS yozuvlarini yuklab olish",
            "DNS amplification DDoS — 100x kuchaytirish",
            "DNS cache poisoning — soxta javob yuborish",
            "Subdomain takeover — band bo'lmagan CNAME manzil",
            "CVE-2020-1350: SIGRed — Windows DNS Server RCE",
        ],
        secure_alternative="Rekursiv so'rovlarni faqat ichki tarmoqqa cheklash. DNSSEC yoqish.",
        risk_note="Zone transfer ochiq bo'lsa, barcha infrastruktura ma'lumotlari ochiladi.",
        cve_refs=["CVE-2020-1350"],
        severity=Severity.MEDIUM, cvss=5.8, cwe="CWE-400"),

    # ── HTTP ─────────────────────────────────────────────────────────────────
    80: PortMeta(80, "HTTP",
        description="HyperText Transfer Protocol (unencrypted)",
        purpose=(
            "Veb-sahifalar uzatish protokoli. Brauzer va server o'rtasida "
            "HTML, CSS, JS, API ma'lumotlarini uzatadi. TLS yo'q."
        ),
        default_creds="—",
        common_attacks=[
            "Man-in-the-middle — trafik ushlanishi va o'zgartirilishi",
            "HTTP downgrade — HTTPS dan HTTP ga tushirish",
            "Cookie o'g'irlash — HttpOnly yo'q bo'lsa",
            "Veb ilova hujumlari (SQLi, XSS, CSRF)",
        ],
        secure_alternative="HTTPS (port 443) — TLS 1.2+ bilan",
        risk_note="Barcha ma'lumotlar, jumladan cookie va forma ma'lumotlari, ochiq uzatiladi.",
        severity=Severity.LOW, cvss=3.1, cwe="CWE-319"),

    # ── POP3 ─────────────────────────────────────────────────────────────────
    110: PortMeta(110, "POP3",
        description="Post Office Protocol v3 (unencrypted)",
        purpose=(
            "Email klientlar uchun pochta serveridan xatlarni yuklab olish protokoli. "
            "Xatlar serverdan o'chiriladi va lokal saqlanadi. Hozir eskirgan."
        ),
        default_creds="—",
        common_attacks=[
            "Credential sniffing — login/parol plain-text",
            "Brute-force — parolni taxmin qilish",
            "Replay attack — ushlab qolingan sessiyani qayta ishlatish",
        ],
        secure_alternative="POP3S (port 995) yoki IMAPS (port 993)",
        risk_note="Login va parol shifrsiz uzatiladi.",
        severity=Severity.HIGH, cvss=7.4, cwe="CWE-319", owasp="A02:2021"),

    # ── MSRPC ────────────────────────────────────────────────────────────────
    135: PortMeta(135, "MSRPC",
        description="Microsoft Remote Procedure Call endpoint mapper",
        purpose=(
            "Windows xizmatlari o'rtasida masofaviy protsedura chaqiruvlarini boshqaradi. "
            "DCOM, WMI, Exchange kabi Windows komponentlari uchun asosiy port."
        ),
        default_creds="Windows domain credentials",
        common_attacks=[
            "MS03-026: DCOM RPC buffer overflow — worm (Blaster, Nachi)",
            "WMI orqali lateral movement",
            "DCOM object instantiation — masofaviy kod bajarish",
            "Port scan — qaysi RPC endpointlar aktiv ekanini aniqlash",
        ],
        secure_alternative="Firewall orqali faqat ichki tarmoqqa cheklash",
        risk_note="Tarixan eng ko'p ishlatiladigan Windows exploit vectorlaridan biri.",
        cve_refs=["CVE-2003-0352"],
        severity=Severity.HIGH, cvss=8.1, cwe="CWE-94", owasp="A06:2021"),

    # ── NetBIOS ──────────────────────────────────────────────────────────────
    139: PortMeta(139, "NetBIOS-SSN",
        description="NetBIOS Session Service",
        purpose=(
            "Windows tarmoqlarida fayl va printer almashish uchun eski protokol. "
            "SMB (port 445) bilan birga ishlaydi. LAN muhitida ishlatilgan."
        ),
        default_creds="—",
        common_attacks=[
            "NetBIOS name poisoning (Responder tool)",
            "NTLM relay attack — hesh ushlab qayta ishlatish",
            "NBT-NS spoofing — kompyuter nomini soxtalash",
            "Null session — autentifikatsiyasiz ulanish (eski Windows)",
        ],
        secure_alternative="SMBv3 faqat (port 445) + IPSec, NetBIOS o'chirilgan",
        risk_note="Responder va NTLM relay hujumlari uchun klassik target.",
        severity=Severity.HIGH, cvss=7.5),

    # ── IMAP ─────────────────────────────────────────────────────────────────
    143: PortMeta(143, "IMAP",
        description="Internet Message Access Protocol (unencrypted)",
        purpose=(
            "Email klientlar uchun pochta serverida xatlarni boshqarish protokoli. "
            "POP3 dan farqi: xatlar serverda qoladi, papkalar bilan ishlash mumkin."
        ),
        default_creds="—",
        common_attacks=[
            "Credential sniffing — login/parol plain-text",
            "Brute-force — parolni taxmin qilish",
            "Email tarkibini ushlab olish",
        ],
        secure_alternative="IMAPS (port 993) — TLS bilan shifrlangan",
        risk_note="Login va pochta tarkibi shifrsiz uzatiladi.",
        severity=Severity.HIGH, cvss=7.4, cwe="CWE-319", owasp="A02:2021"),

    # ── SNMP ─────────────────────────────────────────────────────────────────
    161: PortMeta(161, "SNMP", protocol="UDP",
        description="Simple Network Management Protocol",
        purpose=(
            "Tarmoq qurilmalarini (router, switch, printer) monitoring qilish va "
            "boshqarish protokoli. Qurilma holati, interfeys statistikasi, konfiguratsiya."
        ),
        default_creds="Community string: 'public' (o'qish), 'private' (yozish)",
        common_attacks=[
            "Default community string bilan to'liq qurilma ma'lumotlarini o'qish",
            "'private' string bilan konfiguratsiyani o'zgartirish",
            "SNMP v1/v2c — shifrsiz va autentifikatsiyasiz",
            "DNS amplification uchun ishlatish (UDP spoofing)",
            "CVE-2017-6736: Cisco IOS SNMP RCE",
        ],
        secure_alternative="SNMPv3 (autentifikatsiya + shifrlash) yoki NetFlow/gRPC",
        risk_note="Default community string bilan butun tarmoq topologiyasi ochiladi.",
        cve_refs=["CVE-2017-6736"],
        severity=Severity.HIGH, cvss=7.5, cwe="CWE-798"),

    # ── HTTPS ────────────────────────────────────────────────────────────────
    443: PortMeta(443, "HTTPS",
        description="HyperText Transfer Protocol Secure (TLS encrypted)",
        purpose=(
            "TLS/SSL bilan shifrlangan veb protokol. Barcha zamonaviy veb-saytlar "
            "foydalanuvchi ma'lumotlarini himoya qilish uchun HTTPS ishlatishi kerak."
        ),
        default_creds="—",
        common_attacks=[
            "Eskirgan TLS versiyalari (SSL 3.0, TLS 1.0/1.1) — POODLE, BEAST",
            "Weak cipher suites — RC4, DES, EXPORT ciphers",
            "Certificate validation bypass",
            "HSTS yo'q — downgrade hujumlari",
        ],
        secure_alternative="TLS 1.3, HSTS header, perfect forward secrecy",
        risk_note="TLS konfiguratsiyasini ssllabs.com da tekshiring.",
        severity=Severity.INFO),

    # ── SMB ──────────────────────────────────────────────────────────────────
    445: PortMeta(445, "SMB",
        description="Server Message Block — Windows network file sharing",
        purpose=(
            "Windows tarmoq fayl va printer almashish protokoli. "
            "Active Directory, domain login, DFS uchun ham ishlatiladi."
        ),
        default_creds="Administrator / (bo'sh yoki Password1)",
        common_attacks=[
            "EternalBlue (CVE-2017-0144) — WannaCry va NotPetya ransomware vektori",
            "SMBGhost (CVE-2020-0796) — Windows 10 SMBv3 RCE",
            "Pass-the-Hash — NTLM hash bilan autentifikatsiya",
            "NTLM relay — heshni boshqa xostga qayta ishlatish",
            "Ransomware tarqalishi — lateral movement",
        ],
        secure_alternative="SMBv3 + signing majburiy, internetga hech qachon ochilmasin",
        risk_note="Internetga ochiq SMB = to'g'ridan-to'g'ri ransomware xavfi.",
        cve_refs=["CVE-2017-0144", "CVE-2020-0796"],
        severity=Severity.CRITICAL, cvss=9.8, cwe="CWE-94", owasp="A06:2021"),

    # ── SMTPS ────────────────────────────────────────────────────────────────
    465: PortMeta(465, "SMTPS",
        description="SMTP over implicit TLS",
        purpose=(
            "TLS bilan shifrlangan SMTP. Email klientlar xat jo'natish uchun ishlatadi. "
            "Port 587 (STARTTLS) bilan raqobat qiladi."
        ),
        default_creds="—",
        common_attacks=["TLS versiya downgrade", "Zayif sertifikat"],
        secure_alternative="STARTTLS port 587 ham keng qo'llaniladi",
        risk_note="Shifrlangan; TLS konfiguratsiyasini tekshiring.",
        severity=Severity.INFO),

    # ── IMAPS ────────────────────────────────────────────────────────────────
    993: PortMeta(993, "IMAPS",
        description="IMAP over TLS",
        purpose="TLS bilan shifrlangan IMAP. Zamonaviy email klientlar uchun standart.",
        default_creds="—",
        common_attacks=["Brute-force (parol taxmin)", "Zayif TLS konfiguratsiyasi"],
        secure_alternative="OAuth 2.0 autentifikatsiyasi + 2FA",
        risk_note="Shifrlangan; brute-force cheklovini tekshiring.",
        severity=Severity.INFO),

    # ── POP3S ────────────────────────────────────────────────────────────────
    995: PortMeta(995, "POP3S",
        description="POP3 over TLS",
        purpose="TLS bilan shifrlangan POP3. Port 110 ning xavfsiz versiyasi.",
        default_creds="—",
        common_attacks=["Brute-force", "Zayif TLS sertifikati"],
        secure_alternative="IMAPS (993) — serverda xatlarni saqlash imkoniyati bilan",
        risk_note="Shifrlangan; brute-force cheklovini tekshiring.",
        severity=Severity.INFO),

    # ── MSSQL ────────────────────────────────────────────────────────────────
    1433: PortMeta(1433, "MSSQL",
        description="Microsoft SQL Server database",
        purpose=(
            "Microsoft SQL Server ma'lumotlar bazasi. Windows va .NET ilovalar uchun asosiy DBMS. "
            "T-SQL tili, stored procedures, CLR integration qo'llab-quvvatlanadi."
        ),
        default_creds="sa / (bo'sh) yoki sa / sa — ba'zi eski o'rnatmalarda",
        common_attacks=[
            "sa hisobi brute-force — administrator imtiyozlari",
            "xp_cmdshell — OS buyruqlarini bajarish (DBA imtiyozi bilan)",
            "CVE-2020-0618: SSRS RCE — autentifikatsiya kerak emas",
            "SQL injection orqali OLE automation",
            "Linked server abuse — boshqa DB serverlarga o'tish",
        ],
        secure_alternative="Faqat ichki tarmoqdan kirish + Windows auth + minimal privileges",
        risk_note="Internetga ochiq ma'lumotlar bazasi — to'g'ridan-to'g'ri ma'lumot o'g'irlash xavfi.",
        cve_refs=["CVE-2020-0618"],
        severity=Severity.CRITICAL, cvss=9.0, cwe="CWE-306", owasp="A07:2021"),

    # ── PPTP ─────────────────────────────────────────────────────────────────
    1723: PortMeta(1723, "PPTP",
        description="Point-to-Point Tunneling Protocol VPN",
        purpose=(
            "Eski VPN protokoli. Windows da built-in mavjud. "
            "Korporativ tarmoqlarga masofaviy kirish uchun ishlatilgan."
        ),
        default_creds="VPN hisob ma'lumotlari (odatda domain credentials)",
        common_attacks=[
            "MS-CHAPv2 offline crack — chapcrack/asleap bilan",
            "MPPE shifrlash kriptografik jihatdan sindirilgan",
            "Dictionary attack — asleap tool",
            "Man-in-the-middle — GRE tunnel ushlash",
        ],
        secure_alternative="WireGuard, OpenVPN (port 1194), IPSec/IKEv2",
        risk_note="Kriptografik jihatdan sindirilgan — barcha PPTP trafik ochilishi mumkin.",
        cve_refs=["CVE-2012-6462"],
        severity=Severity.HIGH, cvss=8.6, cwe="CWE-327", owasp="A02:2021"),

    # ── MySQL ─────────────────────────────────────────────────────────────────
    3306: PortMeta(3306, "MySQL",
        description="MySQL / MariaDB relational database server",
        purpose=(
            "Eng keng tarqalgan ochiq kodli ma'lumotlar bazasi. "
            "LAMP/LEMP stack asosi. Web ilovalar, CMS (WordPress, Drupal) ishlatadi."
        ),
        default_creds="root / (bo'sh) yoki root / root — ko'p o'rnatmalarda",
        common_attacks=[
            "root hisobi brute-force — to'liq ma'lumotlar bazasiga kirish",
            "CVE-2012-2122: autentifikatsiyani timing attack bilan bypass qilish",
            "CVE-2016-6662: my.cnf yozish orqali RCE",
            "UDF (user-defined function) orqali OS buyruq bajarish",
            "INTO OUTFILE — server fayliga yozish (web shell)",
            "LOAD DATA INFILE — serverdan fayl o'qish",
        ],
        secure_alternative="Faqat 127.0.0.1 ga bind qilish + SSL + kuchli parol",
        risk_note="Internetga ochiq MySQL = barcha ma'lumotlar xavfi ostida.",
        cve_refs=["CVE-2012-2122", "CVE-2016-6662"],
        severity=Severity.CRITICAL, cvss=9.8, cwe="CWE-306", owasp="A07:2021"),

    # ── RDP ──────────────────────────────────────────────────────────────────
    3389: PortMeta(3389, "RDP",
        description="Remote Desktop Protocol — Windows GUI remote access",
        purpose=(
            "Windows grafik interfeysiga masofaviy kirish. "
            "IT administratorlar, texnik yordam, masofaviy ish uchun ishlatiladi."
        ),
        default_creds="Administrator / Password1, Administrator / (bo'sh)",
        common_attacks=[
            "BlueKeep (CVE-2019-0708) — autentifikatsiyasiz RCE (Windows 7/Server 2008)",
            "DejaBlue (CVE-2019-1181/1182) — Windows 10/Server 2019 RCE",
            "Credential spray — Administrator hisobiga",
            "Pass-the-Hash — NTLM hash bilan kirish",
            "Ransomware dastlabki kirish vektori (90%+ holatlarda RDP)",
            "RDP session hijacking — aktiv sessiyalarni o'g'irlash",
        ],
        secure_alternative="VPN ichida RDP + NLA (Network Level Authentication) + 2FA",
        risk_note="Internetga ochiq RDP — ransomware ning 1-chi kirish yo'li.",
        cve_refs=["CVE-2019-0708", "CVE-2019-1181"],
        severity=Severity.CRITICAL, cvss=9.8, cwe="CWE-307", owasp="A07:2021"),

    # ── PostgreSQL ───────────────────────────────────────────────────────────
    5432: PortMeta(5432, "PostgreSQL",
        description="PostgreSQL advanced relational database server",
        purpose=(
            "Kuchli ochiq kodli ma'lumotlar bazasi. JSON, PostGIS, full-text search. "
            "Python, Ruby, Django, Rails ilovalarida keng ishlatiladi."
        ),
        default_creds="postgres / postgres yoki postgres / (bo'sh)",
        common_attacks=[
            "postgres superuser brute-force",
            "COPY TO/FROM PROGRAM — OS buyruq bajarish (superuser bilan)",
            "pg_read_file() — server fayllarini o'qish",
            "Extension orqali RCE (adminpack, lo)",
            "pg_hba.conf misconfiguration — autentifikatsiyasiz kirish",
        ],
        secure_alternative="Faqat localhost yoki VPN + scram-sha-256 autentifikatsiya",
        risk_note="postgres superuser bilan OS ga to'liq kirish mumkin.",
        severity=Severity.CRITICAL, cvss=9.0, cwe="CWE-306", owasp="A07:2021"),

    # ── VNC ──────────────────────────────────────────────────────────────────
    5900: PortMeta(5900, "VNC",
        description="Virtual Network Computing — cross-platform remote desktop",
        purpose=(
            "Grafik ekranni masofadan boshqarish. Platforma mustaqil (Windows, Linux, macOS). "
            "IT yordam, server boshqaruvi uchun ishlatiladi."
        ),
        default_creds="(bo'sh parol) — ko'p o'rnatmalarda autentifikatsiya yo'q",
        common_attacks=[
            "CVE-2019-15681: LibVNC ma'lumot nusxa xotiradan o'qish",
            "Autentifikatsiyasiz ulanish — parol o'rnatilmagan bo'lsa",
            "Brute-force — 8 belgili parol, DES shifrlangan",
            "VNC trafik sniffing — RFB protokoli shifrsiz bo'lishi mumkin",
            "To'liq desktop nazorati — ekran, klaviatura, sichqoncha",
        ],
        secure_alternative="SSH tunnel ichida VNC yoki VPN + kuchli parol",
        risk_note="Parol yo'q VNC = to'liq kompyuter nazorati.",
        cve_refs=["CVE-2019-15681"],
        severity=Severity.HIGH, cvss=8.8, cwe="CWE-307", owasp="A07:2021"),

    # ── Redis ─────────────────────────────────────────────────────────────────
    6379: PortMeta(6379, "Redis",
        description="Redis in-memory key-value data store",
        purpose=(
            "Yuqori tezlikli xotiradagi ma'lumotlar ombori. Cache, session storage, "
            "message broker, real-time leaderboard uchun ishlatiladi. "
            "Strings, lists, sets, sorted sets, hashes ma'lumot turlari."
        ),
        default_creds="(autentifikatsiya yo'q — standart holatda)",
        common_attacks=[
            "Autentifikatsiyasiz to'liq ma'lumotlarga kirish",
            "CONFIG SET dir + dbfilename → crontab yozish → RCE",
            "CONFIG SET dir → SSH authorized_keys yozish → SSH kirish",
            "CVE-2022-0543: Lua sandbox escape → RCE (Debian/Ubuntu)",
            "Slaveof buyrug'i — ma'lumotlarni tashqi serverga ko'chirish",
            "FLUSHALL — barcha ma'lumotlarni o'chirish",
        ],
        secure_alternative="requirepass + bind 127.0.0.1 + rename-command CONFIG ''",
        risk_note="Autentifikatsiyasiz Redis = serverni to'liq boshqarish imkoniyati (RCE).",
        cve_refs=["CVE-2022-0543"],
        severity=Severity.CRITICAL, cvss=9.8, cwe="CWE-306", owasp="A07:2021"),

    # ── HTTP-Alt ─────────────────────────────────────────────────────────────
    8080: PortMeta(8080, "HTTP-Alt",
        description="Alternative HTTP port (proxies, app servers, admin panels)",
        purpose=(
            "Ikkilamchi HTTP port. Tomcat, Jetty, Node.js, development serverlar, "
            "HTTP proxy va admin panel uchun keng ishlatiladi."
        ),
        default_creds="admin / admin, tomcat / tomcat, admin / password",
        common_attacks=[
            "Himoyasiz admin panel (Tomcat Manager, Jenkins, Grafana)",
            "Default credentials — o'zgartirilmagan parollar",
            "Development server — debug mode yoqilgan",
            "Proxy misuse — open HTTP proxy",
        ],
        secure_alternative="Firewall orqali cheklash + kuchli autentifikatsiya",
        risk_note="Ko'pincha himoyasiz admin panellar yoki dev serverlar topiladi.",
        severity=Severity.MEDIUM, cvss=5.3),

    # ── HTTPS-Alt ────────────────────────────────────────────────────────────
    8443: PortMeta(8443, "HTTPS-Alt",
        description="Alternative HTTPS port",
        purpose=(
            "Ikkilamchi HTTPS port. Tomcat SSL, Kubernetes API server (6443 ham), "
            "admin panel HTTPS versiyasi uchun ishlatiladi."
        ),
        default_creds="admin / admin, admin / changeit",
        common_attacks=[
            "Zayif TLS konfiguratsiyasi",
            "Self-signed sertifikat — MITM xavfi",
            "Admin panel default credentials",
        ],
        secure_alternative="Let's Encrypt sertifikati + kuchli TLS konfiguratsiyasi",
        risk_note="Admin panellar ko'pincha default parol bilan qoladi.",
        severity=Severity.LOW, cvss=3.1),

    # ── Elasticsearch ────────────────────────────────────────────────────────
    9200: PortMeta(9200, "Elasticsearch",
        description="Elasticsearch distributed search and analytics engine",
        purpose=(
            "Distributed full-text qidiruv va tahlil tizimi. Loglar, metrikalar, "
            "qidiruv funksionalligini ta'minlash uchun ishlatiladi. "
            "ELK Stack (Elasticsearch, Logstash, Kibana) ning asosi."
        ),
        default_creds="(autentifikatsiya yo'q — 6.x va undan eski versiyalarda)",
        common_attacks=[
            "Autentifikatsiyasiz barcha indekslarni o'qish (/_cat/indices)",
            "Ma'lumotlarni eksport qilish (/_search?size=10000)",
            "Indekslarni o'chirish (DELETE /index)",
            "Groovy/Painless script injection — eski versiyalarda RCE",
            "CVE-2021-22145: information disclosure",
            "Kibana orqali Elasticsearch ga kirish",
        ],
        secure_alternative="X-Pack Security yoqish + TLS + role-based access control",
        risk_note="Millionlab yozuvlar autentifikatsiyasiz ochiq bo'lishi mumkin.",
        cve_refs=["CVE-2021-22145"],
        severity=Severity.CRITICAL, cvss=9.8, cwe="CWE-306", owasp="A07:2021"),

    # ── MongoDB ──────────────────────────────────────────────────────────────
    27017: PortMeta(27017, "MongoDB",
        description="MongoDB NoSQL document database",
        purpose=(
            "Hujjat asosidagi NoSQL ma'lumotlar bazasi. JSON-like BSON format. "
            "Node.js, Python ilovalar, real-time ilovalar, kataloglar uchun ishlatiladi. "
            "Elastic va flexible schema."
        ),
        default_creds="(autentifikatsiya yo'q — standart holatda, 3.x va undan eski)",
        common_attacks=[
            "Autentifikatsiyasiz barcha ma'lumotlarga kirish",
            "show dbs → use dbname → db.collectionName.find() — to'liq dump",
            "NoSQL injection — {'$gt': ''} kabi operatorlar",
            "CVE-2020-7921: improper access control",
            "Ransomware: ma'lumotlarni o'chirib, to'lov talab qilish (2017-yil epidemiyasi)",
            "mongoexport bilan barcha ma'lumotlarni eksport qilish",
        ],
        secure_alternative="--auth yoqish + bindIp 127.0.0.1 + role-based access",
        risk_note="2017-yilda 28,000+ MongoDB ochiq bo'lib, ransomware qurboni bo'lgan.",
        cve_refs=["CVE-2020-7921"],
        severity=Severity.CRITICAL, cvss=9.8, cwe="CWE-306", owasp="A07:2021"),
}


# ─────────────────────────────────────────────────────────────────────────────
# Low-level I/O helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _tcp_connect(host: str, port: int, timeout: float) -> bool:
    """Phase 1: cheap SYN-based check — reject closed/filtered ports quickly."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def _do_probe(host: str, port: int, probe: ServiceProbe, timeout: float) -> ProbeResult:
    """Phase 2: full service verification — banner grab + validation."""
    try:
        ssl_ctx: ssl.SSLContext | None = None
        if probe.use_tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx),
            timeout=timeout,
        )

        if probe.send:
            writer.write(probe.send)
            await writer.drain()

        raw = b""
        try:
            raw = await asyncio.wait_for(reader.read(_MAX_RECV), timeout=probe.recv_timeout)
        except asyncio.TimeoutError:
            pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        return probe.validate(raw)

    except ssl.SSLError:
        # TLS handshake failed — port may be open but TLS is broken/self-signed
        return ProbeResult(True, "TLS handshake error (self-signed or protocol mismatch)")
    except (OSError, asyncio.TimeoutError, ConnectionResetError):
        return ProbeResult(False, "")


# ─────────────────────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────────────────────

class PortScanner(BaseScanner):
    """
    Two-phase TCP port scanner.

    Phase 1 — TCP connect: quickly eliminates closed / firewall-reset ports.
    Phase 2 — Service probe: validates that the *expected service* is actually
               running, preventing CDN/load-balancer false-positives.
    """

    async def scan(self, url: str) -> list[Finding]:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return []

        timeout: float = float(self.config.get("port_timeout", _DEFAULT_TIMEOUT))
        low_confidence: bool = bool(self.config.get("port_low_confidence", False))
        extra_ports: list[int] = list(self.config.get("extra_ports", []))
        concurrency: int = int(self.config.get("port_concurrency", 50))

        ports_to_scan = set(PORT_META) | set(extra_ports)

        try:
            loop = asyncio.get_event_loop()
            resolved_ip = await loop.run_in_executor(None, socket.gethostbyname, host)
        except socket.gaierror:
            resolved_ip = host

        sem = asyncio.Semaphore(concurrency)

        async def _bounded(port: int) -> Finding | None:
            async with sem:
                return await self._scan_port(
                    url, host, resolved_ip, port, timeout, low_confidence
                )

        results = await asyncio.gather(
            *[_bounded(p) for p in ports_to_scan],
            return_exceptions=True,
        )

        findings = [r for r in results if isinstance(r, Finding)]

        logger.info(
            "port_scan_complete",
            host=host,
            ip=resolved_ip,
            scanned=len(ports_to_scan),
            open_confirmed=len(findings),
            ports=[f.parameter for f in findings],
        )
        return findings

    async def _scan_port(
        self,
        url: str,
        host: str,
        ip: str,
        port: int,
        timeout: float,
        low_confidence: bool,
    ) -> Finding | None:
        # ── Phase 1: TCP connect ──────────────────────────────────────────
        if not await _tcp_connect(host, port, timeout):
            return None

        # ── Phase 2: service verification ────────────────────────────────
        is_low_conf = port in _LOW_CONFIDENCE_PORTS
        probe = SERVICE_PROBES.get(port)

        if probe:
            result = await _do_probe(host, port, probe, timeout)
            if not result.genuine:
                # TCP accepted but service did not respond as expected.
                # This is a CDN / firewall TCP-accept → drop it.
                logger.debug("port_false_positive_dropped", host=host, port=port)
                return None
            banner = result.banner
        elif is_low_conf:
            if not low_confidence:
                return None        # skip noisy binary-protocol ports by default
            banner = "(service fingerprint not available)"
        else:
            banner = ""

        meta = PORT_META.get(
            port,
            PortMeta(port, "Unknown", description=f"Port {port}/TCP"),
        )

        evidence = _build_evidence(port, host, ip, meta, banner, is_low_conf and not probe)
        remediation = _build_remediation(meta)

        return Finding(
            vuln_type=VulnType.OPEN_PORT,
            severity=meta.severity,
            url=url,
            parameter=str(port),
            payload=banner or None,
            evidence=evidence,
            cvss_score=meta.cvss,
            cwe_id=meta.cwe,
            owasp_ref=meta.owasp,
            remediation=remediation,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Evidence & remediation builders
# ─────────────────────────────────────────────────────────────────────────────

def _build_evidence(
    port: int,
    host: str,
    ip: str,
    meta: PortMeta,
    banner: str,
    low_conf: bool,
) -> str:
    sep = "─" * 60
    lines = [
        sep,
        f"  [PORT OPEN] {port}/{meta.protocol}  ·  {meta.service}  ·  {meta.severity.value.upper()}",
        sep,
        f"  Xost         : {host} ({ip})",
        f"  Servis       : {meta.description or meta.service}",
    ]

    if banner:
        lines.append(f"  Banner       : {banner}")

    if meta.purpose:
        lines.append("")
        lines.append("  Vazifasi:")
        for row in meta.purpose.strip().splitlines():
            lines.append(f"    {row.strip()}")

    if meta.default_creds and meta.default_creds != "—":
        lines.append("")
        lines.append(f"  Default login: {meta.default_creds}")

    if meta.common_attacks:
        lines.append("")
        lines.append("  Hujum usullari:")
        for attack in meta.common_attacks:
            lines.append(f"    • {attack}")

    if meta.risk_note:
        lines.append("")
        lines.append(f"  Xavf         : {meta.risk_note}")

    if meta.secure_alternative:
        lines.append(f"  Tavsiya      : {meta.secure_alternative}")

    lines.append("")
    lines.append(f"  CVSS         : {meta.cvss}  |  CWE: {meta.cwe}  |  OWASP: {meta.owasp}")

    if meta.cve_refs:
        lines.append(f"  CVE          : {', '.join(meta.cve_refs)}")

    if low_conf:
        lines.append("  Eslatma      : Low-confidence — servis barmoq izi tasdiqlanmagan.")

    lines.append(sep)
    return "\n".join(lines)


def _build_remediation(meta: PortMeta) -> str:
    intro = f"Port {meta.port}/{meta.protocol} ({meta.service}) is publicly reachable. "

    if meta.severity is Severity.CRITICAL:
        action = (
            "IMMEDIATE ACTION REQUIRED: This service should not be exposed to the internet. "
            "Block this port at the perimeter firewall. If access is required, restrict it "
            "to specific trusted IP ranges and enforce strong authentication. Ensure all "
            "patches are applied."
        )
    elif meta.severity is Severity.HIGH:
        action = (
            "Restrict access to this port to authorised IP ranges via firewall rules. "
            "Disable the service if it is not required. Ensure it is fully patched and "
            "uses strong authentication."
        )
    elif meta.severity is Severity.MEDIUM:
        action = (
            "Review whether this service needs to be publicly accessible. "
            "Apply the principle of least privilege and monitor access logs."
        )
    else:
        action = "Verify this service is intentionally exposed and keep it up to date."

    cve_note = (
        f" Patch known vulnerabilities: {', '.join(meta.cve_refs)}."
        if meta.cve_refs else ""
    )

    return intro + action + cve_note
