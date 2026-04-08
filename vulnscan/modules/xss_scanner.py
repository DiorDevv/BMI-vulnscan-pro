from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from uuid import uuid4

import httpx
import structlog
from bs4 import BeautifulSoup

from ..core.base_scanner import BaseScanner
from ..models.enums import Severity, VulnType
from ..models.finding import Finding

logger = structlog.get_logger(__name__)

# Dangerous DOM sinks
DOM_SINKS = re.compile(
    r"(document\.write|innerHTML|outerHTML|"
    r"eval\s*\(|setTimeout\s*\(|location\.href|"
    r"document\.cookie|insertAdjacentHTML)",
    re.IGNORECASE,
)

# Dangerous DOM sources
DOM_SOURCES = re.compile(
    r"(location\.search|location\.hash|document\.URL|"
    r"document\.referrer|window\.location)",
    re.IGNORECASE,
)

# Context detection patterns
CONTEXT_IN_SCRIPT = re.compile(r"<script[^>]*>[^<]*CANARY", re.IGNORECASE | re.DOTALL)
CONTEXT_IN_ATTR = re.compile(r'["\'][^"\']*CANARY[^"\']*["\']', re.IGNORECASE)


def _inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, "",
    ))


class XSSScanner(BaseScanner):
    """XSS scanner: reflected, DOM-based, with bypass techniques."""

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if params:
            for param in params:
                findings.extend(await self._scan_reflected(url, param))

        # DOM-based XSS — fetch page once
        dom_findings = await self._scan_dom(url)
        findings.extend(dom_findings)

        return findings

    # ── Reflected XSS ─────────────────────────────────────────────────────────

    async def _scan_reflected(self, url: str, param: str) -> list[Finding]:
        canary = f"xss_{uuid4().hex[:8]}"
        payloads = self.payload_engine.xss_payloads(canary)

        for payload in payloads:
            try:
                test_url = _inject_param(url, param, payload)
                resp = await self._request("GET", test_url, follow_redirects=True)
                body = resp.text

                # Check if canary is reflected unescaped
                if canary in body and "&lt;" not in body[max(0, body.index(canary) - 20): body.index(canary)]:
                    context = self._detect_context(body, canary)
                    finding = Finding(
                        vuln_type=VulnType.XSS_REFLECTED,
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=(
                            f"Canary {canary!r} reflected unescaped in {context} context. "
                            f"Snippet: {self._extract_snippet(body, canary)}"
                        ),
                        cvss_score=7.4,
                        cwe_id="CWE-79",
                        owasp_ref="A03:2021",
                        remediation=(
                            "HTML-encode all user-supplied output. "
                            "Use a Content Security Policy to restrict script execution."
                        ),
                    )
                    if await self._confirm_finding(finding):
                        logger.info(
                            "xss_reflected_found",
                            url=url,
                            param=param,
                            context=context,
                        )
                        return [finding]
            except (httpx.TimeoutException, httpx.ConnectError, Exception) as exc:
                logger.debug("xss_reflected_request_failed", url=url, error=str(exc))

        # Try bypass payloads if basic didn't work
        return await self._scan_reflected_bypasses(url, param)

    async def _scan_reflected_bypasses(self, url: str, param: str) -> list[Finding]:
        canary = f"xss_{uuid4().hex[:8]}"
        bypass_payloads = [
            f"<ScRiPt>console.log('{canary}')</ScRiPt>",
            f"&lt;script&gt;console.log('{canary}')&lt;/script&gt;",
            f"%253Cscript%253Econsole.log('{canary}')%253C%2Fscript%253E",
            f"<scr\x00ipt>console.log('{canary}')</scr\x00ipt>",
            f"<svg><animate onbegin=alert('{canary}') attributeName=x dur=1s>",
        ]
        for payload in bypass_payloads:
            try:
                test_url = _inject_param(url, param, payload)
                resp = await self._request("GET", test_url, follow_redirects=True)
                # Only flag if canary appears AND HTML entities are NOT present
                # in the surrounding window (guards against escaped reflection)
                body = resp.text
                if canary in body:
                    idx = body.index(canary)
                    window = body[max(0, idx - 60): idx + len(canary) + 60]
                    is_escaped = any(ent in window for ent in ("&lt;", "&gt;", "&#x27;", "&#39;", "&quot;"))
                if canary in body and not is_escaped:
                    finding = Finding(
                        vuln_type=VulnType.XSS_REFLECTED,
                        severity=Severity.HIGH,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=(
                            f"XSS bypass payload reflected with canary {canary!r}. "
                            f"Snippet: {self._extract_snippet(resp.text, canary)}"
                        ),
                        cvss_score=7.4,
                        cwe_id="CWE-79",
                        owasp_ref="A03:2021",
                        remediation=(
                            "HTML-encode all user-supplied output. "
                            "Implement a strict Content Security Policy."
                        ),
                    )
                    return [finding]
            except Exception as exc:
                logger.debug("xss_bypass_failed", url=url, error=str(exc))
        return []

    # ── DOM-based XSS ─────────────────────────────────────────────────────────

    async def _scan_dom(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await self._request("GET", url, follow_redirects=True)
            soup = BeautifulSoup(resp.text, "lxml")

            scripts = soup.find_all("script")
            for script in scripts:
                src_text = script.string or ""
                if not src_text:
                    continue

                has_sink = DOM_SINKS.search(src_text)
                has_source = DOM_SOURCES.search(src_text)

                if has_sink and has_source:
                    sink_match = DOM_SINKS.search(src_text)
                    source_match = DOM_SOURCES.search(src_text)
                    findings.append(Finding(
                        vuln_type=VulnType.XSS_DOM,
                        severity=Severity.MEDIUM,
                        url=url,
                        evidence=(
                            f"DOM sink {sink_match.group(0)!r} receives data from "  # type: ignore[union-attr]
                            f"source {source_match.group(0)!r}"  # type: ignore[union-attr]
                        ),
                        cvss_score=6.1,
                        cwe_id="CWE-79",
                        owasp_ref="A03:2021",
                        remediation=(
                            "Avoid passing user-controlled data (location.search, "
                            "location.hash) to dangerous DOM sinks. "
                            "Use textContent instead of innerHTML."
                        ),
                    ))
                    break  # one DOM finding per page is sufficient
        except Exception as exc:
            logger.debug("xss_dom_failed", url=url, error=str(exc))

        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _detect_context(self, body: str, canary: str) -> str:
        idx = body.find(canary)
        if idx == -1:
            return "unknown"
        snippet = body[max(0, idx - 200): idx + 50]
        if "<script" in snippet.lower():
            return "script"
        if re.search(r'<[a-z]+[^>]+=["\'][^"\']*$', snippet, re.IGNORECASE):
            return "attribute"
        return "html"

    @staticmethod
    def _extract_snippet(body: str, canary: str, width: int = 150) -> str:
        idx = body.find(canary)
        if idx == -1:
            return ""
        start = max(0, idx - 60)
        end = min(len(body), idx + width)
        return repr(body[start:end])
