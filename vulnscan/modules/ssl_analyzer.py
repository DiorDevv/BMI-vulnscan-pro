from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import structlog

from ..core.base_scanner import BaseScanner
from ..models.enums import Severity, VulnType
from ..models.finding import Finding

logger = structlog.get_logger(__name__)

WEAK_PROTOCOLS = {
    "SSLv2": Severity.CRITICAL,
    "SSLv3": Severity.CRITICAL,
    "TLSv1": Severity.CRITICAL,
    "TLSv1.1": Severity.HIGH,
}

WEAK_CIPHER_PATTERNS = (
    "RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ANON", "ADH", "AECDH",
)


def _cipher_is_weak(cipher_name: str) -> bool:
    for pattern in WEAK_CIPHER_PATTERNS:
        if pattern.upper() in cipher_name.upper():
            return True
    return False


class SSLAnalyzer(BaseScanner):
    """Analyze SSL/TLS configuration using native ssl + socket."""

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)

        if parsed.scheme != "https":
            return findings  # only analyze HTTPS targets

        host = parsed.hostname or ""
        port = parsed.port or 443

        if not host:
            return findings

        try:
            findings.extend(await self._analyze_ssl(url, host, port))
        except Exception as exc:
            logger.warning("ssl_analyzer_error", url=url, error=str(exc))

        return findings

    async def _analyze_ssl(self, url: str, host: str, port: int) -> list[Finding]:
        findings: list[Finding] = []

        # Use asyncio executor to avoid blocking event loop
        import asyncio
        loop = asyncio.get_event_loop()

        try:
            cert_info, proto, cipher = await loop.run_in_executor(
                None, self._get_tls_info, host, port
            )
        except ssl.SSLError as exc:
            findings.append(Finding(
                vuln_type=VulnType.SSL_WEAK,
                severity=Severity.CRITICAL,
                url=url,
                evidence=f"SSL handshake failed: {exc}",
                cvss_score=9.1,
                cwe_id="CWE-326",
                owasp_ref="A02:2021",
                remediation="Fix SSL/TLS configuration; ensure TLS 1.2+ is supported",
            ))
            return findings
        except (socket.error, OSError) as exc:
            logger.warning("ssl_connect_error", url=url, error=str(exc))
            return findings

        # Check protocol
        if proto in WEAK_PROTOCOLS:
            severity = WEAK_PROTOCOLS[proto]
            findings.append(Finding(
                vuln_type=VulnType.SSL_WEAK,
                severity=severity,
                url=url,
                evidence=f"Weak TLS protocol detected: {proto}",
                cvss_score=9.8 if severity == Severity.CRITICAL else 7.5,
                cwe_id="CWE-326",
                owasp_ref="A02:2021",
                remediation=f"Disable {proto}; use TLS 1.2 or TLS 1.3 only",
            ))

        # Check cipher suite
        if cipher and _cipher_is_weak(cipher):
            findings.append(Finding(
                vuln_type=VulnType.SSL_WEAK,
                severity=Severity.HIGH,
                url=url,
                evidence=f"Weak cipher suite: {cipher}",
                cvss_score=7.5,
                cwe_id="CWE-326",
                owasp_ref="A02:2021",
                remediation=f"Disable weak cipher: {cipher}; use ECDHE+AES-GCM",
            ))

        # Analyze certificate
        if cert_info:
            findings.extend(self._check_cert(url, host, cert_info))

        return findings

    def _get_tls_info(
        self, host: str, port: int
    ) -> tuple[dict[str, Any] | None, str, str]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version() or "unknown"
                cipher_info = ssock.cipher()
                cipher_name = cipher_info[0] if cipher_info else "unknown"
                return cert, proto, cipher_name

    def _check_cert(
        self, url: str, host: str, cert: dict[str, Any]
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Check expiry
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            try:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                not_after = not_after.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_remaining = (not_after - now).days

                if days_remaining < 0:
                    findings.append(Finding(
                        vuln_type=VulnType.SSL_WEAK,
                        severity=Severity.CRITICAL,
                        url=url,
                        evidence=f"SSL certificate EXPIRED on {not_after_str}",
                        cvss_score=9.1,
                        cwe_id="CWE-298",
                        owasp_ref="A02:2021",
                        remediation="Renew SSL certificate immediately",
                    ))
                elif days_remaining < 30:
                    findings.append(Finding(
                        vuln_type=VulnType.SSL_WEAK,
                        severity=Severity.HIGH,
                        url=url,
                        evidence=f"SSL certificate expires in {days_remaining} days ({not_after_str})",
                        cvss_score=7.4,
                        cwe_id="CWE-298",
                        owasp_ref="A02:2021",
                        remediation="Renew SSL certificate before expiry",
                    ))
            except ValueError:
                pass

        # Check self-signed (no issuer org different from subject)
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        if subject == issuer:
            findings.append(Finding(
                vuln_type=VulnType.SSL_WEAK,
                severity=Severity.HIGH,
                url=url,
                evidence="Self-signed certificate detected",
                cvss_score=7.4,
                cwe_id="CWE-295",
                owasp_ref="A02:2021",
                remediation="Replace self-signed certificate with one from a trusted CA",
            ))

        # Check hostname mismatch via SAN
        sans = cert.get("subjectAltName", [])
        valid_names = [v for t, v in sans if t == "DNS"]
        if valid_names and not self._hostname_matches(host, valid_names):
            findings.append(Finding(
                vuln_type=VulnType.SSL_WEAK,
                severity=Severity.HIGH,
                url=url,
                evidence=f"Hostname {host!r} not in cert SANs: {valid_names}",
                cvss_score=7.4,
                cwe_id="CWE-297",
                owasp_ref="A02:2021",
                remediation="Ensure certificate covers the target hostname",
            ))

        return findings

    @staticmethod
    def _hostname_matches(host: str, valid_names: list[str]) -> bool:
        for name in valid_names:
            if name.startswith("*."):
                suffix = name[2:]
                parts = host.split(".", 1)
                if len(parts) == 2 and parts[1] == suffix:
                    return True
            elif name == host:
                return True
        return False
