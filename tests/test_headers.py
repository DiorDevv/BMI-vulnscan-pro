"""Header analyzer tests."""
from __future__ import annotations

import pytest
import respx
import httpx

from vulnscan.models.enums import Severity, VulnType
from vulnscan.modules.header_analyzer import HeaderAnalyzer


# ── Missing HSTS on HTTPS ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_missing_hsts_flagged(header_analyzer: HeaderAnalyzer) -> None:
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.head("https://secure.local/").mock(
            return_value=httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
            )
        )
        findings = await header_analyzer.scan("https://secure.local/")

    hsts_findings = [
        f for f in findings
        if f.vuln_type == VulnType.MISSING_HEADER
        and "strict-transport-security" in f.evidence.lower()
    ]
    assert len(hsts_findings) >= 1
    assert hsts_findings[0].severity == Severity.HIGH


# ── No findings on fully secure headers ──────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_headers_no_critical(
    header_analyzer: HeaderAnalyzer,
    clean_app: respx.MockRouter,
) -> None:
    with clean_app:
        findings = await header_analyzer.scan("http://testapp.local/")

    critical_high = [
        f for f in findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    assert len(critical_high) == 0


# ── CSP with unsafe-inline flagged ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_csp_unsafe_inline_flagged(header_analyzer: HeaderAnalyzer) -> None:
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.head("http://csptest.local/").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "strict-origin",
                },
            )
        )
        findings = await header_analyzer.scan("http://csptest.local/")

    csp_findings = [
        f for f in findings
        if "unsafe" in f.evidence.lower() or "csp" in f.evidence.lower()
    ]
    assert len(csp_findings) >= 1


# ── CORS wildcard flagged ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cors_wildcard_flagged(header_analyzer: HeaderAnalyzer) -> None:
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.head("http://corstest.local/api").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Content-Type": "application/json",
                },
            )
        )
        findings = await header_analyzer.scan("http://corstest.local/api")

    cors_findings = [f for f in findings if f.vuln_type == VulnType.CORS]
    assert len(cors_findings) >= 1
    assert cors_findings[0].severity in (Severity.HIGH, Severity.CRITICAL)


# ── Missing CSP is flagged ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_missing_csp_flagged(header_analyzer: HeaderAnalyzer) -> None:
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.head("https://nocsp.local/").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "Strict-Transport-Security": "max-age=31536000",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "strict-origin",
                },
            )
        )
        findings = await header_analyzer.scan("https://nocsp.local/")

    csp_findings = [
        f for f in findings
        if f.vuln_type == VulnType.MISSING_HEADER and "content-security-policy" in f.evidence.lower()
    ]
    assert len(csp_findings) >= 1
