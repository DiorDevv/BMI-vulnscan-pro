"""pytest fixtures and mock HTTP server using respx."""
from __future__ import annotations

import re

import httpx
import pytest
import respx

from vulnscan.core.http_client import build_client
from vulnscan.core.payload_engine import PayloadEngine
from vulnscan.core.proxy_router import ProxyRouter
from vulnscan.core.rate_limiter import RateLimiter
from vulnscan.core.session_manager import SessionManager
from vulnscan.modules.header_analyzer import HeaderAnalyzer
from vulnscan.modules.sql_injection import SQLiScanner
from vulnscan.modules.xss_scanner import XSSScanner
from vulnscan.utils.crawler import AsyncCrawler


TARGET = "http://testapp.local"
TARGET_VULN = "http://vulnapp.local"


# ── Rate limiter fixture (high RPS for tests) ─────────────────────────────────
@pytest.fixture
def rate_limiter() -> RateLimiter:
    return RateLimiter(rps=1000.0)


@pytest.fixture
def session() -> SessionManager:
    return SessionManager()


@pytest.fixture
def proxy_router() -> ProxyRouter:
    return ProxyRouter()


@pytest.fixture
def payload_engine() -> PayloadEngine:
    return PayloadEngine()


@pytest.fixture
def scanner_config() -> dict[str, object]:
    return {"verify_ssl": False, "timeout": 5, "follow_redirects": True}


# ── SQLi scanner fixture ──────────────────────────────────────────────────────
@pytest.fixture
def sqli_scanner(
    session: SessionManager,
    rate_limiter: RateLimiter,
    proxy_router: ProxyRouter,
    payload_engine: PayloadEngine,
    scanner_config: dict[str, object],
) -> SQLiScanner:
    return SQLiScanner(
        session=session,
        rate_limiter=rate_limiter,
        proxy_router=proxy_router,
        payload_engine=payload_engine,
        config=scanner_config,
    )


# ── XSS scanner fixture ───────────────────────────────────────────────────────
@pytest.fixture
def xss_scanner(
    session: SessionManager,
    rate_limiter: RateLimiter,
    proxy_router: ProxyRouter,
    payload_engine: PayloadEngine,
    scanner_config: dict[str, object],
) -> XSSScanner:
    return XSSScanner(
        session=session,
        rate_limiter=rate_limiter,
        proxy_router=proxy_router,
        payload_engine=payload_engine,
        config=scanner_config,
    )


# ── Header analyzer fixture ───────────────────────────────────────────────────
@pytest.fixture
def header_analyzer(
    session: SessionManager,
    rate_limiter: RateLimiter,
    proxy_router: ProxyRouter,
    payload_engine: PayloadEngine,
    scanner_config: dict[str, object],
) -> HeaderAnalyzer:
    return HeaderAnalyzer(
        session=session,
        rate_limiter=rate_limiter,
        proxy_router=proxy_router,
        payload_engine=payload_engine,
        config=scanner_config,
    )


# ── "Vulnerable app" mock: simulates SQLi errors, XSS reflection, bad headers ─
@pytest.fixture
def vulnerable_app() -> respx.MockRouter:  # type: ignore[type-arg]
    router = respx.MockRouter(assert_all_called=False)

    # SQLi error: any request to /search that contains a quote triggers error
    def sqli_side_effect(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "'" in url or "%27" in url:
            return httpx.Response(
                200,
                text=(
                    "Warning: mysql_fetch_array() expects parameter 1 to be resource\n"
                    "You have an error in your SQL syntax; check the manual that "
                    "corresponds to your MySQL server version"
                ),
            )
        return httpx.Response(200, text="<html>Normal results</html>")

    router.get(re.compile(r"http://vulnapp\.local/search")).mock(side_effect=sqli_side_effect)
    router.get(re.compile(r"http://vulnapp\.local/search.*AND 1=1")).mock(
        return_value=httpx.Response(200, text="<html>" + "A" * 500 + "</html>")
    )
    router.get(re.compile(r"http://vulnapp\.local/search.*AND 1=2")).mock(
        return_value=httpx.Response(200, text="<html>No results</html>")
    )

    # XSS reflection: echoes query param 'q' raw into the response
    def xss_side_effect(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        return httpx.Response(
            200,
            text=f"<html><body>Search results for: {q}</body></html>",
        )

    router.get(re.compile(r"http://vulnapp\.local/xss")).mock(side_effect=xss_side_effect)

    # Missing security headers
    router.head(re.compile(r"http://vulnapp\.local")).mock(
        return_value=httpx.Response(200, headers={"Content-Type": "text/html"})
    )
    router.get(re.compile(r"http://vulnapp\.local$")).mock(
        return_value=httpx.Response(200, text="<html><body>Home</body></html>",
                                     headers={"Content-Type": "text/html"})
    )

    return router


# ── "Clean app" mock: secure headers, no vulns ────────────────────────────────
@pytest.fixture
def clean_app() -> respx.MockRouter:  # type: ignore[type-arg]
    router = respx.MockRouter(assert_all_called=False)

    secure_headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Type": "text/html",
    }

    router.head(re.compile(r"http://testapp\.local")).mock(
        return_value=httpx.Response(200, headers=secure_headers)
    )
    router.get(re.compile(r"http://testapp\.local/search")).mock(
        return_value=httpx.Response(
            200,
            text="<html><body>Safe results</body></html>",
            headers=secure_headers,
        )
    )
    router.get(re.compile(r"http://testapp\.local")).mock(
        return_value=httpx.Response(
            200,
            text="<html><body>Home</body></html>",
            headers=secure_headers,
        )
    )

    return router
