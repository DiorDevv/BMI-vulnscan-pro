from __future__ import annotations

import re
from typing import Any

import httpx
import structlog

from ..core.base_scanner import BaseScanner
from ..models.enums import Severity, VulnType
from ..models.finding import Finding

logger = structlog.get_logger(__name__)

# Minimum HSTS max-age: 1 year in seconds
MIN_HSTS_MAX_AGE = 31_536_000

# CSP directives that weaken security
CSP_UNSAFE_DIRECTIVES = re.compile(r"unsafe-inline|unsafe-eval", re.IGNORECASE)
CSP_NONCE_RE = re.compile(r"nonce-[A-Za-z0-9+/=]+")


class HeaderAnalyzer(BaseScanner):
    """Analyze HTTP security response headers for misconfigurations."""

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await self._request("HEAD", url)
        except Exception as exc:
            logger.warning("header_analyzer_error", url=url, error=str(exc))
            try:
                resp = await self._request("GET", url)
            except Exception as exc2:
                logger.error("header_analyzer_failed", url=url, error=str(exc2))
                return findings

        headers = {k.lower(): v for k, v in resp.headers.items()}

        findings.extend(self._check_hsts(url, headers))
        findings.extend(self._check_csp(url, headers))
        findings.extend(self._check_x_content_type(url, headers))
        findings.extend(self._check_x_frame(url, headers))
        findings.extend(self._check_referrer_policy(url, headers))
        findings.extend(self._check_cors(url, headers))
        findings.extend(self._check_server_leakage(url, headers))

        logger.info(
            "header_analysis_complete",
            url=url,
            findings=len(findings),
            grade=self._compute_grade(headers),
        )
        return findings

    # ── Individual header checks ──────────────────────────────────────────────

    def _check_hsts(self, url: str, headers: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        if not url.startswith("https"):
            return findings  # HSTS only applies to HTTPS

        hsts = headers.get("strict-transport-security")
        if not hsts:
            findings.append(Finding(
                vuln_type=VulnType.MISSING_HEADER,
                severity=Severity.HIGH,
                url=url,
                evidence="Strict-Transport-Security header absent",
                cvss_score=7.4,
                cwe_id="CWE-319",
                owasp_ref="A05:2021",
                remediation=(
                    "Add: Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains; preload"
                ),
            ))
            return findings

        # Check max-age
        ma_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if ma_match and int(ma_match.group(1)) < MIN_HSTS_MAX_AGE:
            findings.append(Finding(
                vuln_type=VulnType.MISSING_HEADER,
                severity=Severity.MEDIUM,
                url=url,
                evidence=f"HSTS max-age too short: {hsts}",
                cvss_score=5.3,
                cwe_id="CWE-319",
                owasp_ref="A05:2021",
                remediation="Increase max-age to at least 31536000 (1 year)",
            ))
        return findings

    def _check_csp(self, url: str, headers: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        csp = headers.get("content-security-policy")
        if not csp:
            findings.append(Finding(
                vuln_type=VulnType.MISSING_HEADER,
                severity=Severity.HIGH,
                url=url,
                evidence="Content-Security-Policy header absent",
                cvss_score=6.1,
                cwe_id="CWE-1021",
                owasp_ref="A05:2021",
                remediation=(
                    "Add a strict CSP: Content-Security-Policy: "
                    "default-src 'self'; script-src 'self'"
                ),
            ))
            return findings

        # Check for unsafe directives without nonce
        if CSP_UNSAFE_DIRECTIVES.search(csp) and not CSP_NONCE_RE.search(csp):
            findings.append(Finding(
                vuln_type=VulnType.MISSING_HEADER,
                severity=Severity.MEDIUM,
                url=url,
                evidence=f"CSP contains unsafe directives: {csp[:200]}",
                cvss_score=5.4,
                cwe_id="CWE-1021",
                owasp_ref="A05:2021",
                remediation="Remove unsafe-inline/unsafe-eval or use nonces",
            ))

        if "default-src" not in csp.lower():
            findings.append(Finding(
                vuln_type=VulnType.MISSING_HEADER,
                severity=Severity.MEDIUM,
                url=url,
                evidence=f"CSP missing default-src directive: {csp[:200]}",
                cvss_score=4.3,
                cwe_id="CWE-1021",
                owasp_ref="A05:2021",
                remediation="Add default-src 'self' to CSP",
            ))
        return findings

    def _check_x_content_type(self, url: str, headers: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        value = headers.get("x-content-type-options", "")
        if value.lower() != "nosniff":
            findings.append(Finding(
                vuln_type=VulnType.MISSING_HEADER,
                severity=Severity.MEDIUM,
                url=url,
                evidence=f"X-Content-Type-Options: {value!r} (expected 'nosniff')",
                cvss_score=4.3,
                cwe_id="CWE-16",
                owasp_ref="A05:2021",
                remediation="Add: X-Content-Type-Options: nosniff",
            ))
        return findings

    def _check_x_frame(self, url: str, headers: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        value = headers.get("x-frame-options", "").upper()
        if value not in ("DENY", "SAMEORIGIN"):
            findings.append(Finding(
                vuln_type=VulnType.MISSING_HEADER,
                severity=Severity.MEDIUM,
                url=url,
                evidence=f"X-Frame-Options: {value!r} (expected DENY or SAMEORIGIN)",
                cvss_score=4.3,
                cwe_id="CWE-1021",
                owasp_ref="A05:2021",
                remediation="Add: X-Frame-Options: DENY",
            ))
        return findings

    def _check_referrer_policy(self, url: str, headers: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        value = headers.get("referrer-policy", "").lower()
        safe_values = ("strict-origin", "no-referrer", "strict-origin-when-cross-origin")
        if value not in safe_values:
            findings.append(Finding(
                vuln_type=VulnType.MISSING_HEADER,
                severity=Severity.LOW,
                url=url,
                evidence=f"Referrer-Policy: {value!r} (expected strict-origin or no-referrer)",
                cvss_score=3.1,
                cwe_id="CWE-16",
                owasp_ref="A05:2021",
                remediation="Add: Referrer-Policy: strict-origin-when-cross-origin",
            ))
        return findings

    def _check_cors(self, url: str, headers: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()

        if acao == "*":
            severity = Severity.CRITICAL if acac == "true" else Severity.HIGH
            findings.append(Finding(
                vuln_type=VulnType.CORS,
                severity=severity,
                url=url,
                evidence=f"Access-Control-Allow-Origin: * (credentials={acac})",
                cvss_score=9.1 if acac == "true" else 7.5,
                cwe_id="CWE-942",
                owasp_ref="A05:2021",
                remediation=(
                    "Restrict CORS to specific trusted origins; "
                    "never combine wildcard ACAO with credentials"
                ),
            ))
        return findings

    def _check_server_leakage(self, url: str, headers: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        server = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")
        if server and re.search(r"\d", server):
            findings.append(Finding(
                vuln_type=VulnType.MISSING_HEADER,
                severity=Severity.INFO,
                url=url,
                evidence=f"Server header reveals version: {server}",
                cvss_score=0.0,
                cwe_id="CWE-200",
                owasp_ref="A05:2021",
                remediation="Configure server to hide version information",
            ))
        if x_powered:
            findings.append(Finding(
                vuln_type=VulnType.MISSING_HEADER,
                severity=Severity.INFO,
                url=url,
                evidence=f"X-Powered-By reveals technology: {x_powered}",
                cvss_score=0.0,
                cwe_id="CWE-200",
                owasp_ref="A05:2021",
                remediation="Remove the X-Powered-By header from server configuration",
            ))
        return findings

    def _compute_grade(self, headers: dict[str, str]) -> str:
        score = 0
        if "strict-transport-security" in headers:
            score += 5
        if "content-security-policy" in headers:
            score += 5
        if headers.get("x-content-type-options", "").lower() == "nosniff":
            score += 5
        if headers.get("x-frame-options", "").upper() in ("DENY", "SAMEORIGIN"):
            score += 5
        if headers.get("referrer-policy", "").lower() in (
            "strict-origin", "no-referrer", "strict-origin-when-cross-origin"
        ):
            score += 5

        pct = score * 4  # max 100
        if pct >= 100:
            return "A+"
        elif pct >= 80:
            return "A"
        elif pct >= 60:
            return "B"
        elif pct >= 40:
            return "C"
        elif pct >= 20:
            return "D"
        return "F"
