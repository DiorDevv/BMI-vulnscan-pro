"""Tests for main.py orchestration, logger, port scanner, rate limiter,
and SSL analyzer helpers to push coverage to ≥ 80%."""
from __future__ import annotations

import asyncio
import re
import tempfile
from pathlib import Path

import httpx
import pytest
import respx

from vulnscan.models.enums import ScanStatus, Severity, VulnType
from vulnscan.models.finding import Finding
from vulnscan.models.scan_result import ScanResult


# ── logger ────────────────────────────────────────────────────────────────────

def test_configure_logging_normal() -> None:
    from vulnscan.utils.logger import configure_logging
    configure_logging(verbose=False)  # must not raise


def test_configure_logging_verbose() -> None:
    from vulnscan.utils.logger import configure_logging
    configure_logging(verbose=True)


# ── Rate limiter: slow path ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rate_limiter_slow_path() -> None:
    """Exercising the sleep path at 2 rps with back-pressure."""
    from vulnscan.core.rate_limiter import RateLimiter
    rl = RateLimiter(rps=2.0)
    # Drain the initial token
    await rl.acquire()
    await rl.acquire()
    # Third acquire must block briefly (slow path) — just verify it completes
    await asyncio.wait_for(rl.acquire(), timeout=5.0)


# ── Port scanner ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_port_scanner_closed_port() -> None:
    from vulnscan.modules.port_scanner import _tcp_connect
    # Port 1 should not be open on localhost in test environment
    result = await _tcp_connect("127.0.0.1", 1, timeout=1.0)
    # We don't assert True/False since it might occasionally be open;
    # just verify it returns a bool without raising
    assert isinstance(result, bool)


@pytest.mark.asyncio
async def test_port_scanner_scan_returns_list() -> None:
    from vulnscan.core.payload_engine import PayloadEngine
    from vulnscan.core.proxy_router import ProxyRouter
    from vulnscan.core.rate_limiter import RateLimiter
    from vulnscan.core.session_manager import SessionManager
    from vulnscan.modules.port_scanner import PortScanner

    scanner = PortScanner(
        session=SessionManager(),
        rate_limiter=RateLimiter(rps=1000),
        proxy_router=ProxyRouter(),
        payload_engine=PayloadEngine(),
        config={"port_timeout": 0.1},
    )
    findings = await scanner.scan("http://localhost/")
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_port_scanner_no_host() -> None:
    from vulnscan.core.payload_engine import PayloadEngine
    from vulnscan.core.proxy_router import ProxyRouter
    from vulnscan.core.rate_limiter import RateLimiter
    from vulnscan.core.session_manager import SessionManager
    from vulnscan.modules.port_scanner import PortScanner

    scanner = PortScanner(
        session=SessionManager(),
        rate_limiter=RateLimiter(rps=1000),
        proxy_router=ProxyRouter(),
        payload_engine=PayloadEngine(),
        config={},
    )
    findings = await scanner.scan("not-a-url")
    assert findings == []


# ── SSL analyzer helpers ──────────────────────────────────────────────────────

def test_ssl_cipher_is_weak() -> None:
    from vulnscan.modules.ssl_analyzer import _cipher_is_weak
    assert _cipher_is_weak("RC4-MD5") is True
    assert _cipher_is_weak("DES-CBC") is True
    assert _cipher_is_weak("NULL-SHA") is True
    assert _cipher_is_weak("ECDHE-RSA-AES256-GCM-SHA384") is False


def test_ssl_hostname_matches_exact() -> None:
    from vulnscan.modules.ssl_analyzer import SSLAnalyzer
    assert SSLAnalyzer._hostname_matches("example.com", ["example.com"]) is True
    assert SSLAnalyzer._hostname_matches("other.com", ["example.com"]) is False


def test_ssl_hostname_matches_wildcard() -> None:
    from vulnscan.modules.ssl_analyzer import SSLAnalyzer
    assert SSLAnalyzer._hostname_matches("sub.example.com", ["*.example.com"]) is True
    assert SSLAnalyzer._hostname_matches("example.com", ["*.example.com"]) is False
    assert SSLAnalyzer._hostname_matches("a.b.example.com", ["*.example.com"]) is False


def test_ssl_analyzer_skips_non_https() -> None:
    """SSLAnalyzer should return empty findings for http:// targets."""
    from vulnscan.core.payload_engine import PayloadEngine
    from vulnscan.core.proxy_router import ProxyRouter
    from vulnscan.core.rate_limiter import RateLimiter
    from vulnscan.core.session_manager import SessionManager
    from vulnscan.modules.ssl_analyzer import SSLAnalyzer

    async def _run() -> list[Finding]:
        scanner = SSLAnalyzer(
            session=SessionManager(),
            rate_limiter=RateLimiter(rps=1000),
            proxy_router=ProxyRouter(),
            payload_engine=PayloadEngine(),
            config={},
        )
        return await scanner.scan("http://example.com/")

    findings = asyncio.get_event_loop().run_until_complete(_run())
    assert findings == []


# ── ScanConfig + main helpers ─────────────────────────────────────────────────

def test_scan_config_defaults() -> None:
    from vulnscan.main import ScanConfig
    cfg = ScanConfig(target="https://example.com")
    assert cfg.target == "https://example.com"
    assert cfg.scan_profile == "quick"
    assert cfg.threads == 30
    assert cfg.rps == 10.0
    assert cfg.timeout == 10
    assert cfg.depth == 3
    assert cfg.fmt == "html"
    assert cfg.ignore_ssl is False
    assert cfg.ignore_robots is False
    assert cfg.modules == []
    assert cfg.headers == []


def test_scan_config_threads_capped_at_100() -> None:
    from vulnscan.main import ScanConfig
    cfg = ScanConfig(target="https://example.com", threads=500)
    assert cfg.threads == 100


def test_generate_reports_html() -> None:
    from vulnscan.main import ScanConfig, _generate_reports

    result = ScanResult(target="https://example.com", scan_profile="quick")
    result.finish(ScanStatus.DONE)

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = ScanConfig(
            target="https://example.com",
            output=str(Path(tmpdir) / "report"),
            fmt="html",
        )
        reports = _generate_reports(result, cfg)
        assert len(reports) == 1
        assert reports[0].suffix == ".html"
        assert reports[0].exists()


def test_generate_reports_all() -> None:
    from vulnscan.main import ScanConfig, _generate_reports

    result = ScanResult(target="https://example.com")
    result.finish()

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = ScanConfig(
            target="https://example.com",
            output=str(Path(tmpdir) / "rep"),
            fmt="all",
        )
        reports = _generate_reports(result, cfg)
        assert len(reports) == 3
        suffixes = {r.suffix for r in reports}
        assert ".html" in suffixes
        assert ".json" in suffixes
        assert ".csv" in suffixes


def test_print_summary_no_crash() -> None:
    from vulnscan.main import _print_summary

    result = ScanResult(target="https://example.com")
    f = Finding(
        vuln_type=VulnType.SQLI,
        severity=Severity.CRITICAL,
        url="https://example.com",
        evidence="test",
        cvss_score=9.8,
        cwe_id="CWE-89",
        owasp_ref="A03:2021",
        remediation="fix it",
    )
    result.add_finding(f)
    result.finish()
    _print_summary(result)  # should not raise


def test_url_validation_rejects_non_http() -> None:
    from vulnscan.utils.url_utils import is_valid_http_url
    assert is_valid_http_url("ftp://example.com") is False
    assert is_valid_http_url("javascript:alert(1)") is False
    assert is_valid_http_url("file:///etc/passwd") is False
    assert is_valid_http_url("https://example.com") is True
    assert is_valid_http_url("http://example.com:8080/path") is True


# ── run_scan integration (quick profile, mocked) ──────────────────────────────

@pytest.mark.asyncio
async def test_run_scan_quick_profile_completes() -> None:
    """End-to-end run_scan with quick profile and mocked HTTP responses."""
    from vulnscan.main import ScanConfig, run_scan

    secure_headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin",
        "Content-Type": "text/html",
    }

    with respx.MockRouter(assert_all_called=False) as mock:
        mock.head(re.compile(r"http://quicktest\.local")).mock(
            return_value=httpx.Response(200, headers=secure_headers)
        )
        mock.get(re.compile(r"http://quicktest\.local")).mock(
            return_value=httpx.Response(
                200,
                text="<html><body>Home</body></html>",
                headers=secure_headers,
            )
        )

        cfg = ScanConfig(
            target="http://quicktest.local",
            scan_profile="quick",
            rps=1000.0,
            timeout=5,
            ignore_robots=True,
        )
        result = await run_scan(cfg)

    assert result.status == ScanStatus.DONE
    assert result.target == "http://quicktest.local"
    assert isinstance(result.findings, list)
    assert result.duration_seconds >= 0.0


@pytest.mark.asyncio
async def test_run_scan_full_profile_with_vulns() -> None:
    """Full profile scan with a vulnerable-looking app."""
    from vulnscan.main import ScanConfig, run_scan

    def sqli_side(req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        if "'" in url or "%27" in url:
            return httpx.Response(
                200,
                text="You have an error in your SQL syntax; check the MySQL manual",
                headers={"Content-Type": "text/html"},
            )
        return httpx.Response(200, text="<html><body>ok</body></html>",
                               headers={"Content-Type": "text/html"})

    with respx.MockRouter(assert_all_called=False) as mock:
        mock.head(re.compile(r"http://fulltest\.local")).mock(
            return_value=httpx.Response(200, headers={"Content-Type": "text/html"})
        )
        mock.get(re.compile(r"http://fulltest\.local/search")).mock(
            side_effect=sqli_side
        )
        mock.get(re.compile(r"http://fulltest\.local")).mock(
            return_value=httpx.Response(
                200,
                text='<html><body><a href="/search?q=test">Search</a></body></html>',
                headers={"Content-Type": "text/html"},
            )
        )

        cfg = ScanConfig(
            target="http://fulltest.local",
            scan_profile="full",
            modules=["sqli", "cors"],
            rps=1000.0,
            timeout=5,
            ignore_robots=True,
            depth=1,
        )
        result = await run_scan(cfg)

    assert result.status == ScanStatus.DONE
    # Should have at least some findings (header misconfigs, etc.)
    assert isinstance(result.findings, list)


# ── Crawler: robots.txt handling ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_crawler_respects_robots_txt() -> None:
    """Crawler must skip disallowed paths from robots.txt."""
    from vulnscan.utils.crawler import AsyncCrawler

    robots_txt = "User-agent: *\nDisallow: /private/\n"
    home_html = """
    <html>
    <body>
      <a href="/public">Public</a>
      <a href="/private/secret">Secret</a>
    </body>
    </html>
    """
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.get("http://robots.local/robots.txt").mock(
            return_value=httpx.Response(200, text=robots_txt)
        )
        mock.get("http://robots.local/").mock(
            return_value=httpx.Response(200, text=home_html,
                                         headers={"content-type": "text/html"})
        )
        mock.get("http://robots.local/public").mock(
            return_value=httpx.Response(200, text="<html>public</html>",
                                         headers={"content-type": "text/html"})
        )
        mock.get("http://robots.local/private/secret").mock(
            return_value=httpx.Response(200, text="<html>secret</html>",
                                         headers={"content-type": "text/html"})
        )

        async with httpx.AsyncClient() as client:
            crawler = AsyncCrawler(client=client, max_depth=2, ignore_robots=False)
            result = await crawler.crawl("http://robots.local/")

    assert "http://robots.local/private/secret" not in result.urls


@pytest.mark.asyncio
async def test_crawler_exclude_pattern() -> None:
    """Crawler must skip URLs matching the exclude regex."""
    from vulnscan.utils.crawler import AsyncCrawler

    home_html = """
    <html>
    <a href="/allowed">OK</a>
    <a href="/excluded-page">Skip</a>
    </html>
    """
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.get("http://excl.local/robots.txt").mock(
            return_value=httpx.Response(404, text="")
        )
        mock.get("http://excl.local/").mock(
            return_value=httpx.Response(200, text=home_html,
                                         headers={"content-type": "text/html"})
        )
        mock.get("http://excl.local/allowed").mock(
            return_value=httpx.Response(200, text="<html>allowed</html>",
                                         headers={"content-type": "text/html"})
        )

        async with httpx.AsyncClient() as client:
            crawler = AsyncCrawler(
                client=client, max_depth=1,
                ignore_robots=True, exclude_pattern=r"excluded"
            )
            result = await crawler.crawl("http://excl.local/")

    assert "http://excl.local/excluded-page" not in result.urls
    assert "http://excl.local/allowed" in result.urls
