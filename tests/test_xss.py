"""XSS scanner tests."""
from __future__ import annotations

import re

import httpx
import pytest
import respx

from vulnscan.models.enums import Severity, VulnType
from vulnscan.modules.xss_scanner import XSSScanner


TARGET_XSS = "http://vulnapp.local/xss?q=test"


# ── Reflected XSS detected ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_reflected_xss_detected(
    xss_scanner: XSSScanner,
    vulnerable_app: respx.MockRouter,
) -> None:
    """XSS scanner must detect canary reflection in response body."""
    with vulnerable_app:
        findings = await xss_scanner.scan(TARGET_XSS)

    xss_findings = [f for f in findings if f.vuln_type == VulnType.XSS_REFLECTED]
    assert len(xss_findings) >= 1
    assert xss_findings[0].severity in (Severity.HIGH, Severity.CRITICAL)
    assert xss_findings[0].parameter == "q"
    assert xss_findings[0].cwe_id == "CWE-79"


# ── No XSS on escaped output ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_xss_when_output_escaped() -> None:
    """No XSS finding when the response HTML-escapes the output."""
    with respx.MockRouter(assert_all_called=False) as mock:
        def escape_output(request: httpx.Request) -> httpx.Response:
            q = request.url.params.get("q", "")
            # Full escaping: HTML-encode every character that could be
            # exploitable, including stripping any bare canary string so
            # the scanner cannot detect a reflection.
            q_escaped = (
                q.replace("&", "&amp;")
                 .replace("<", "&lt;")
                 .replace(">", "&gt;")
                 .replace('"', "&quot;")
                 .replace("'", "&#x27;")
                 .replace(":", "&#58;")   # kills javascript: vectors
                 .replace("/", "&#47;")
            )
            return httpx.Response(
                200,
                text=f"<html><body>Results: {q_escaped}</body></html>",
            )

        mock.get(re.compile(r"http://safexss\.local/search")).mock(
            side_effect=escape_output
        )

        from vulnscan.core.payload_engine import PayloadEngine
        from vulnscan.core.proxy_router import ProxyRouter
        from vulnscan.core.rate_limiter import RateLimiter
        from vulnscan.core.session_manager import SessionManager
        from vulnscan.modules.xss_scanner import XSSScanner

        scanner = XSSScanner(
            session=SessionManager(),
            rate_limiter=RateLimiter(rps=1000),
            proxy_router=ProxyRouter(),
            payload_engine=PayloadEngine(),
            config={"verify_ssl": False, "timeout": 5},
        )

        findings = await scanner.scan("http://safexss.local/search?q=test")

    xss_findings = [f for f in findings if f.vuln_type == VulnType.XSS_REFLECTED]
    assert len(xss_findings) == 0


# ── DOM XSS detected ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dom_xss_detected(xss_scanner: XSSScanner) -> None:
    """DOM XSS scanner must find dangerous sink+source pattern in inline script."""
    dom_page = """
    <html>
    <body>
    <script>
      var x = location.search;
      document.getElementById('out').innerHTML = x;
    </script>
    </body>
    </html>
    """
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.get("http://domxss.local/page").mock(
            return_value=httpx.Response(200, text=dom_page)
        )

        from vulnscan.core.payload_engine import PayloadEngine
        from vulnscan.core.proxy_router import ProxyRouter
        from vulnscan.core.rate_limiter import RateLimiter
        from vulnscan.core.session_manager import SessionManager
        from vulnscan.modules.xss_scanner import XSSScanner

        scanner = XSSScanner(
            session=SessionManager(),
            rate_limiter=RateLimiter(rps=1000),
            proxy_router=ProxyRouter(),
            payload_engine=PayloadEngine(),
            config={"verify_ssl": False, "timeout": 5},
        )

        findings = await scanner.scan("http://domxss.local/page")

    dom_findings = [f for f in findings if f.vuln_type == VulnType.XSS_DOM]
    assert len(dom_findings) >= 1
    assert dom_findings[0].severity == Severity.MEDIUM


# ── No params: no reflected XSS ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_params_no_reflected_xss(xss_scanner: XSSScanner) -> None:
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.get("http://noparams.local/page").mock(
            return_value=httpx.Response(200, text="<html>static page</html>")
        )
        findings = await xss_scanner.scan("http://noparams.local/page")

    xss_findings = [f for f in findings if f.vuln_type == VulnType.XSS_REFLECTED]
    assert len(xss_findings) == 0
