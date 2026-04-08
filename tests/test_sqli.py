"""SQL injection scanner tests."""
from __future__ import annotations

import re

import httpx
import pytest
import respx

from vulnscan.models.enums import Severity, VulnType
from vulnscan.modules.sql_injection import SQLiScanner


TARGET_SEARCH = "http://vulnapp.local/search?q=test"
CLEAN_SEARCH = "http://testapp.local/search?q=test"


# ── Error-based detection ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_error_based_detection(
    sqli_scanner: SQLiScanner,
    vulnerable_app: respx.MockRouter,
) -> None:
    """Scanner must detect MySQL error response as SQLi."""
    with vulnerable_app:
        findings = await sqli_scanner.scan(TARGET_SEARCH)

    sqli_findings = [f for f in findings if f.vuln_type == VulnType.SQLI]
    assert len(sqli_findings) >= 1
    assert sqli_findings[0].severity == Severity.CRITICAL
    assert sqli_findings[0].cvss_score >= 9.0
    assert sqli_findings[0].cwe_id == "CWE-89"
    assert sqli_findings[0].parameter == "q"


@pytest.mark.asyncio
async def test_error_based_evidence_contains_pattern(
    sqli_scanner: SQLiScanner,
    vulnerable_app: respx.MockRouter,
) -> None:
    """Evidence snippet must reference the SQL error pattern."""
    with vulnerable_app:
        findings = await sqli_scanner.scan(TARGET_SEARCH)

    sqli_findings = [f for f in findings if f.vuln_type == VulnType.SQLI]
    assert sqli_findings
    evidence_lower = sqli_findings[0].evidence.lower()
    assert any(kw in evidence_lower for kw in ["mysql", "sql", "syntax", "error"])


# ── False-positive test ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_false_positive_on_clean_app(
    sqli_scanner: SQLiScanner,
    clean_app: respx.MockRouter,
) -> None:
    """No SQLi findings on a clean application returning normal responses."""
    with clean_app:
        findings = await sqli_scanner.scan(CLEAN_SEARCH)

    sqli_findings = [f for f in findings if f.vuln_type == VulnType.SQLI]
    assert len(sqli_findings) == 0


# ── Boolean-blind detection ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_boolean_blind_detection(
    sqli_scanner: SQLiScanner,
) -> None:
    """Boolean blind: detects significant length difference between TRUE/FALSE payloads."""
    with respx.MockRouter(assert_all_called=False) as mock:
        call_count = 0

        def side_effect(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            url = str(request.url)
            if "1%3D1" in url or "1=1" in url:
                return httpx.Response(200, text="<html>" + "X" * 1000 + "</html>")
            if "1%3D2" in url or "1=2" in url:
                return httpx.Response(200, text="<html>empty</html>")
            # error-based payloads: return clean response so we fall through to boolean
            return httpx.Response(200, text="<html>safe</html>")

        mock.get(re.compile(r"http://blindapp\.local/search")).mock(
            side_effect=side_effect
        )

        findings = await sqli_scanner._boolean_blind(
            "http://blindapp.local/search?id=1", "id"
        )

    assert len(findings) == 1
    assert findings[0].vuln_type == VulnType.SQLI
    assert "boolean blind" in findings[0].evidence.lower()


# ── Time-based blind: baseline measurement ───────────────────────────────────

@pytest.mark.asyncio
async def test_time_based_no_false_positive(
    sqli_scanner: SQLiScanner,
) -> None:
    """Time-based: fast responses must NOT produce findings."""
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.get(re.compile(r"http://fastapp\.local/search")).mock(
            return_value=httpx.Response(200, text="<html>ok</html>")
        )

        findings = await sqli_scanner._time_based(
            "http://fastapp.local/search?id=1", "id"
        )

    assert len(findings) == 0


# ── Scan with no params: must return empty ────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_no_params_returns_empty(sqli_scanner: SQLiScanner) -> None:
    findings = await sqli_scanner.scan("http://example.local/noparams")
    assert findings == []


# ── OWASP reference is correct ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_finding_owasp_ref(
    sqli_scanner: SQLiScanner,
    vulnerable_app: respx.MockRouter,
) -> None:
    with vulnerable_app:
        findings = await sqli_scanner.scan(TARGET_SEARCH)

    sqli_findings = [f for f in findings if f.vuln_type == VulnType.SQLI]
    if sqli_findings:
        assert sqli_findings[0].owasp_ref == "A03:2021"


# ── Confirmation via second request ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_confirm_finding_true(
    sqli_scanner: SQLiScanner,
    vulnerable_app: respx.MockRouter,
) -> None:
    """_confirm_finding returns True when evidence is still present."""
    from vulnscan.models.finding import Finding
    from vulnscan.models.enums import VulnType, Severity

    finding = Finding(
        vuln_type=VulnType.SQLI,
        severity=Severity.CRITICAL,
        url="http://vulnapp.local/search",
        parameter="q",
        payload="'",
        evidence="mysql_fetch",
        cvss_score=9.8,
        cwe_id="CWE-89",
        owasp_ref="A03:2021",
        remediation="Use parameterized queries.",
    )
    with vulnerable_app:
        confirmed = await sqli_scanner._confirm_finding(finding)

    assert confirmed is True
