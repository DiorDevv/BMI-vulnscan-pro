"""Additional tests for cors_checker, open_redirect, port_scanner,
dir_bruteforce, reporting, storage, and model helpers."""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

import httpx
import pytest
import respx

from vulnscan.core.payload_engine import PayloadEngine
from vulnscan.core.proxy_router import ProxyRouter
from vulnscan.core.rate_limiter import RateLimiter
from vulnscan.core.session_manager import SessionManager
from vulnscan.models.enums import Severity, ScanStatus, VulnType
from vulnscan.models.finding import Finding
from vulnscan.models.scan_result import ScanResult
from vulnscan.modules.cors_checker import CORSChecker
from vulnscan.modules.dir_bruteforce import DirBruteforcer
from vulnscan.modules.open_redirect import OpenRedirectScanner
from vulnscan.reporting.html_reporter import HTMLReporter
from vulnscan.reporting.json_reporter import JSONReporter
from vulnscan.storage.db import Database
from vulnscan.utils.url_utils import (
    extract_params,
    get_base_url,
    inject_param,
    is_valid_http_url,
    normalize_url,
    same_origin,
)


# ── Helpers ───────────────────────────────────────────────────────────────────
def _make_scanner(cls: type, config: dict | None = None):  # type: ignore[type-arg]
    return cls(
        session=SessionManager(),
        rate_limiter=RateLimiter(rps=1000),
        proxy_router=ProxyRouter(),
        payload_engine=PayloadEngine(),
        config=config or {"verify_ssl": False, "timeout": 5},
    )


def _sample_finding(**kwargs: object) -> Finding:
    defaults = dict(
        vuln_type=VulnType.SQLI,
        severity=Severity.CRITICAL,
        url="https://example.com/page",
        parameter="id",
        payload="'",
        evidence="mysql error",
        cvss_score=9.8,
        cwe_id="CWE-89",
        owasp_ref="A03:2021",
        remediation="Use parameterized queries.",
    )
    defaults.update(kwargs)  # type: ignore[arg-type]
    return Finding(**defaults)  # type: ignore[arg-type]


# ── url_utils ─────────────────────────────────────────────────────────────────

def test_normalize_url_relative() -> None:
    result = normalize_url("/page", base="http://example.com/")
    assert result == "http://example.com/page"


def test_normalize_url_drops_fragment() -> None:
    result = normalize_url("http://example.com/page#section")
    assert result == "http://example.com/page"


def test_normalize_url_skips_image() -> None:
    result = normalize_url("http://example.com/logo.png")
    assert result is None


def test_normalize_url_skips_non_http() -> None:
    result = normalize_url("ftp://example.com/file")
    assert result is None


def test_same_origin_true() -> None:
    assert same_origin("http://example.com/a", "http://example.com/b") is True


def test_same_origin_false_different_host() -> None:
    assert same_origin("http://example.com/a", "http://other.com/a") is False


def test_extract_params() -> None:
    params = extract_params("http://example.com/search?q=test&page=1")
    assert "q" in params
    assert "page" in params


def test_is_valid_http_url() -> None:
    assert is_valid_http_url("https://example.com") is True
    assert is_valid_http_url("ftp://example.com") is False
    assert is_valid_http_url("not-a-url") is False


def test_get_base_url() -> None:
    assert get_base_url("https://example.com/path?q=1") == "https://example.com"


def test_inject_param() -> None:
    url = inject_param("http://example.com/page?a=1", "a", "evil")
    assert "a=evil" in url


# ── CORS checker ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cors_arbitrary_origin_reflected() -> None:
    scanner = _make_scanner(CORSChecker)
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.get("https://api.target.com/data").mock(
            return_value=httpx.Response(
                200,
                headers={
                    "Access-Control-Allow-Origin": "https://evil.com",
                    "Access-Control-Allow-Credentials": "true",
                },
            )
        )
        findings = await scanner.scan("https://api.target.com/data")

    cors = [f for f in findings if f.vuln_type == VulnType.CORS]
    assert len(cors) >= 1
    assert cors[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_cors_no_acao_no_finding() -> None:
    scanner = _make_scanner(CORSChecker)
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.get("https://safe.target.com/data").mock(
            return_value=httpx.Response(200, headers={"Content-Type": "application/json"})
        )
        findings = await scanner.scan("https://safe.target.com/data")

    cors = [f for f in findings if f.vuln_type == VulnType.CORS]
    assert len(cors) == 0


# ── Open redirect ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_open_redirect_detected() -> None:
    scanner = _make_scanner(OpenRedirectScanner)
    import re as _re
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.get(_re.compile(r"http://redir\.local/login")).mock(
            return_value=httpx.Response(
                302,
                headers={"Location": "https://evil.com"},
            )
        )
        findings = await scanner.scan("http://redir.local/login?redirect=home")

    redir = [f for f in findings if f.vuln_type == VulnType.OPEN_REDIRECT]
    assert len(redir) >= 1
    assert redir[0].severity == Severity.MEDIUM
    assert redir[0].cwe_id == "CWE-601"


@pytest.mark.asyncio
async def test_open_redirect_no_redirect_no_finding() -> None:
    scanner = _make_scanner(OpenRedirectScanner)
    import re as _re
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.get(_re.compile(r"http://safe\.local/login")).mock(
            return_value=httpx.Response(200, text="<html>ok</html>")
        )
        findings = await scanner.scan("http://safe.local/login?redirect=home")

    assert len(findings) == 0


# ── Directory bruteforce ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dir_bruteforce_finds_sensitive_file() -> None:
    import re as _re
    scanner = _make_scanner(DirBruteforcer)
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.get(_re.compile(r"http://dirtest\.local")).mock(
            side_effect=lambda req: (
                httpx.Response(200, text="SECRET_KEY=supersecret\nDB_PASSWORD=pass123")
                if ".env" in str(req.url)
                else httpx.Response(404, text="not found")
            )
        )
        findings = await scanner._probe(
            "http://dirtest.local",
            "/.env",
            asyncio.Semaphore(10),
            "404 not found page content xyz unique123",
        )

    assert findings is not None
    assert findings.vuln_type == VulnType.SENSITIVE_FILE
    assert findings.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_dir_bruteforce_403_is_low_severity() -> None:
    import re as _re
    scanner = _make_scanner(DirBruteforcer)
    with respx.MockRouter(assert_all_called=False) as mock:
        mock.get(_re.compile(r"http://dirtest2\.local")).mock(
            return_value=httpx.Response(403, text="forbidden")
        )
        finding = await scanner._probe(
            "http://dirtest2.local",
            "/admin",
            asyncio.Semaphore(10),
            "not found page",
        )

    assert finding is not None
    assert finding.severity == Severity.LOW


# ── Models ────────────────────────────────────────────────────────────────────

def test_scan_result_risk_score() -> None:
    result = ScanResult(target="https://example.com")
    result.add_finding(_sample_finding(severity=Severity.CRITICAL))
    result.add_finding(_sample_finding(severity=Severity.HIGH))
    result.add_finding(_sample_finding(severity=Severity.MEDIUM))
    assert result.risk_score > 0


def test_scan_result_severity_counts() -> None:
    result = ScanResult(target="https://example.com")
    result.add_finding(_sample_finding(severity=Severity.CRITICAL))
    result.add_finding(_sample_finding(severity=Severity.HIGH))
    result.add_finding(_sample_finding(severity=Severity.HIGH))
    counts = result.severity_counts
    assert counts["critical"] == 1
    assert counts["high"] == 2


def test_scan_result_finish() -> None:
    result = ScanResult(target="https://example.com")
    result.finish(ScanStatus.DONE)
    assert result.status == ScanStatus.DONE
    assert result.finished_at is not None


def test_scan_result_false_positives_excluded_from_score() -> None:
    result = ScanResult(target="https://example.com")
    fp = _sample_finding(severity=Severity.CRITICAL, false_positive=True)
    result.add_finding(fp)
    assert result.risk_score == 0


def test_scan_result_duration() -> None:
    result = ScanResult(target="https://example.com")
    result.finish()
    assert result.duration_seconds >= 0.0


# ── Rate limiter ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rate_limiter_acquires() -> None:
    rl = RateLimiter(rps=1000.0)
    # Should complete immediately
    for _ in range(5):
        await rl.acquire()


# ── Session manager ───────────────────────────────────────────────────────────

def test_session_manager_cookies() -> None:
    sm = SessionManager(cookies_str="a=1; b=2")
    assert sm.cookies == {"a": "1", "b": "2"}


def test_session_manager_auth_sets_header() -> None:
    sm = SessionManager(auth="user:pass")
    assert "Authorization" in sm.headers
    assert sm.headers["Authorization"].startswith("Basic ")


def test_session_manager_extra_headers() -> None:
    sm = SessionManager(extra_headers=["X-Custom: myvalue"])
    assert sm.headers.get("X-Custom") == "myvalue"


def test_session_manager_repr_hides_credentials() -> None:
    sm = SessionManager(auth="admin:secret")
    r = repr(sm)
    assert "secret" not in r


# ── Payload engine ────────────────────────────────────────────────────────────

def test_payload_engine_mutate_url() -> None:
    pe = PayloadEngine()
    variants = pe.mutate("<script>", "url")
    assert len(variants) >= 2
    assert "%3Cscript%3E" in variants


def test_payload_engine_mutate_double_url() -> None:
    pe = PayloadEngine()
    variants = pe.mutate("<", "double_url")
    assert any("%25" in v for v in variants)


def test_payload_engine_mutate_html() -> None:
    pe = PayloadEngine()
    variants = pe.mutate("<script>", "html")
    assert any("&lt;" in v for v in variants)


def test_payload_engine_sqli_payloads_string() -> None:
    pe = PayloadEngine()
    payloads = pe.sqli_payloads(context="string")
    assert len(payloads) >= 5
    assert any("'" in p for p in payloads)


def test_payload_engine_sqli_payloads_numeric() -> None:
    pe = PayloadEngine()
    payloads = pe.sqli_payloads(context="numeric")
    assert len(payloads) >= 5


def test_payload_engine_xss_payloads() -> None:
    pe = PayloadEngine()
    payloads = pe.xss_payloads("mycanary")
    assert all("mycanary" in p for p in payloads)


def test_payload_engine_load_nonexistent() -> None:
    pe = PayloadEngine()
    result = pe.load_wordlist("nonexistent_file.txt")
    assert result == []


# ── Reporting ─────────────────────────────────────────────────────────────────

def _sample_result() -> ScanResult:
    result = ScanResult(
        target="https://example.com",
        scan_profile="full",
        total_requests=150,
    )
    result.add_finding(_sample_finding(severity=Severity.CRITICAL))
    result.add_finding(_sample_finding(severity=Severity.HIGH, vuln_type=VulnType.XSS_REFLECTED))
    result.add_finding(_sample_finding(severity=Severity.MEDIUM, vuln_type=VulnType.MISSING_HEADER))
    result.finish(ScanStatus.DONE)
    return result


def test_json_reporter_generates_file() -> None:
    result = _sample_result()
    with tempfile.TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "report.json"
        reporter = JSONReporter()
        path = reporter.generate_json(result, output)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["target"] == "https://example.com"
        assert len(data["findings"]) == 3


def test_csv_reporter_generates_file() -> None:
    result = _sample_result()
    with tempfile.TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "report.csv"
        reporter = JSONReporter()
        path = reporter.generate_csv(result, output)
        assert path.exists()
        content = path.read_text()
        assert "severity" in content
        assert "cvss_score" in content


def test_html_reporter_generates_file() -> None:
    result = _sample_result()
    with tempfile.TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "report.html"
        reporter = HTMLReporter()
        path = reporter.generate(result, output)
        assert path.exists()
        html = path.read_text()
        assert "VulnScan Pro" in html
        assert "https://example.com" in html
        assert "Chart.js" in html or "chart.js" in html.lower()


# ── Database / storage ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_db_save_and_retrieve_scan() -> None:
    result = _sample_result()
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(path=db_path)
        await db.connect()
        await db.save_scan(result)

        retrieved = await db.get_scan(result.id)
        await db.close()

    assert retrieved is not None
    assert retrieved.target == "https://example.com"
    assert len(retrieved.findings) == 3


@pytest.mark.asyncio
async def test_db_get_nonexistent_scan() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        db = Database(path=Path(tmpdir) / "test.db")
        await db.connect()
        result = await db.get_scan("nonexistent-id")
        await db.close()

    assert result is None


# ── ProxyRouter ───────────────────────────────────────────────────────────────

def test_proxy_router_no_proxy() -> None:
    pr = ProxyRouter()
    assert pr.httpx_proxies is None
    assert pr.is_configured is False


def test_proxy_router_with_proxy() -> None:
    pr = ProxyRouter(proxy_url="http://127.0.0.1:8080")
    assert pr.is_configured is True
    assert pr.httpx_proxies is not None


def test_proxy_router_invalid_scheme() -> None:
    with pytest.raises(ValueError, match="Unsupported proxy scheme"):
        ProxyRouter(proxy_url="xyz://127.0.0.1:8080")
