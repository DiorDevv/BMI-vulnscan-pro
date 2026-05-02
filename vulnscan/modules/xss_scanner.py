from __future__ import annotations

import re
from urllib.parse import parse_qs, urljoin, urlparse
from uuid import uuid4

import httpx
import structlog
from bs4 import BeautifulSoup

from ..core.base_scanner import BaseScanner
from ..models.enums import Severity, VulnType
from ..models.finding import Finding
from ..utils.form_utils import extract_forms
from ..utils.url_utils import inject_param

logger = structlog.get_logger(__name__)

# Context detection patterns
CONTEXT_IN_SCRIPT = re.compile(r"<script[^>]*>[^<]*CANARY", re.IGNORECASE | re.DOTALL)
CONTEXT_IN_ATTR = re.compile(r'["\'][^"\']*CANARY[^"\']*["\']', re.IGNORECASE)

# HTML encoding markers that indicate the canary was safely escaped
_ENCODING_MARKERS = ("&lt;", "&gt;", "&#", "\\u003c", "\\u003e", "%3c", "%3e")

# Sanitization functions that break the source→sink data flow
_SANITIZERS = re.compile(
    r"(?:DOMPurify\.sanitize|escapeHtml|htmlEscape|sanitize|encode|"
    r"encodeURIComponent|encodeURI|escape|stripTags|xssFilter)\s*\(",
    re.IGNORECASE,
)

# DOM XSS sources and sinks — matched separately so we can check proximity
_DOM_SOURCES_RE = re.compile(
    r"location\.(?:search|hash|href)|document\.(?:URL|referrer)|window\.location",
    re.IGNORECASE,
)
_DOM_SINKS_RE = re.compile(
    r"innerHTML|outerHTML|document\.write\s*\(|eval\s*\(|"
    r"setTimeout\s*\(|location\.href\s*=|insertAdjacentHTML",
    re.IGNORECASE,
)
# Max chars between source and sink to be considered a direct data flow
_DOM_PROXIMITY = 400

# CDN/vendor JS prefixes — skip these to avoid false positives in minified libs
_VENDOR_URL_RE = re.compile(
    r"(?:jquery|bootstrap|angular|react|vue|lodash|moment|axios|cdn\.|"
    r"googleapis\.com|cloudflare\.com|jsdelivr\.net|unpkg\.com)",
    re.IGNORECASE,
)


class XSSScanner(BaseScanner):
    """XSS scanner: reflected (URL params + HTML forms), DOM-based (inline + external JS)."""

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if params:
            for param in params:
                findings.extend(await self._scan_reflected(url, param))

        # DOM-based XSS — inline scripts + external JS files
        findings.extend(await self._scan_dom(url))

        # Form-based XSS — GET and POST forms
        findings.extend(await self._scan_forms(url))

        return findings

    # ── Reflected XSS (URL params) ────────────────────────────────────────────

    async def _scan_reflected(self, url: str, param: str) -> list[Finding]:
        canary = f"xss_{uuid4().hex[:8]}"
        payloads = self.payload_engine.xss_payloads(canary)

        for payload in payloads:
            try:
                test_url = inject_param(url, param, payload)
                resp = await self._request("GET", test_url, follow_redirects=True)
                body = resp.text

                if canary in body and not self._canary_is_encoded(body, canary):
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
                        logger.info("xss_reflected_found", url=url, param=param, context=context)
                        return [finding]
            except (httpx.TimeoutException, httpx.ConnectError, Exception) as exc:
                logger.debug("xss_reflected_request_failed", url=url, error=str(exc))

        return await self._scan_reflected_bypasses(url, param)

    async def _scan_reflected_bypasses(self, url: str, param: str) -> list[Finding]:
        canary = f"xss_{uuid4().hex[:8]}"
        bypass_payloads = [
            f"<ScRiPt>console.log('{canary}')</ScRiPt>",
            f"</title><script>console.log('{canary}')</script>",
            f"%253Cscript%253Econsole.log('{canary}')%253C%2Fscript%253E",
            f"<scr\x00ipt>console.log('{canary}')</scr\x00ipt>",
            f"<svg><animate onbegin=alert('{canary}') attributeName=x dur=1s>",
        ]
        for payload in bypass_payloads:
            try:
                test_url = inject_param(url, param, payload)
                resp = await self._request("GET", test_url, follow_redirects=True)
                body = resp.text
                if canary in body:
                    idx = body.index(canary)
                    window = body[max(0, idx - 60): idx + len(canary) + 60]
                    is_escaped = any(
                        ent in window
                        for ent in ("&lt;", "&gt;", "&#x27;", "&#39;", "&quot;")
                    )
                    if not is_escaped:
                        return [Finding(
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
                        )]
            except Exception as exc:
                logger.debug("xss_bypass_failed", url=url, error=str(exc))
        return []

    # ── Form-based XSS (GET + POST) ───────────────────────────────────────────

    async def _scan_forms(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await self._request("GET", url, follow_redirects=True)
            forms = extract_forms(resp.text, url)
        except Exception:
            return findings

        for form in forms:
            action = form["action"]
            method = form["method"]
            base_data = form["inputs"]
            injectable = form["injectable"]

            for field in injectable:
                canary = f"xss_{uuid4().hex[:8]}"
                for payload in self.payload_engine.xss_payloads(canary):
                    data = {**base_data, field: payload}
                    try:
                        if method == "POST":
                            resp = await self._request(
                                "POST", action, data=data, follow_redirects=True
                            )
                        else:
                            resp = await self._request(
                                "GET", action, params=data, follow_redirects=True
                            )
                        body = resp.text
                        if canary in body and not self._canary_is_encoded(body, canary):
                            context = self._detect_context(body, canary)
                            findings.append(Finding(
                                vuln_type=VulnType.XSS_REFLECTED,
                                severity=Severity.HIGH,
                                url=action,
                                parameter=field,
                                payload=payload,
                                evidence=(
                                    f"Form XSS ({method}): canary {canary!r} reflected "
                                    f"unescaped in {context} context. "
                                    f"Snippet: {self._extract_snippet(body, canary)}"
                                ),
                                cvss_score=7.4,
                                cwe_id="CWE-79",
                                owasp_ref="A03:2021",
                                remediation=(
                                    "HTML-encode all user-supplied output. "
                                    "Use a Content Security Policy."
                                ),
                            ))
                            logger.info(
                                "xss_form_found",
                                url=action,
                                field=field,
                                method=method,
                                context=context,
                            )
                            break
                    except Exception as exc:
                        logger.debug("xss_form_failed", url=action, field=field, error=str(exc))
                else:
                    continue
                break  # one finding per form

        return findings

    # ── DOM-based XSS ─────────────────────────────────────────────────────────

    async def _scan_dom(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            resp = await self._request("GET", url, follow_redirects=True)
            soup = BeautifulSoup(resp.text, "lxml")

            # 1. Inline scripts
            for script in soup.find_all("script"):
                src_text = script.string or ""
                if len(src_text) < 20:
                    continue
                finding = self._check_dom_taint(src_text, url)
                if finding:
                    findings.append(finding)
                    break

            # 2. External JS files (skip vendor/CDN, limit to 5)
            if not findings:
                external_js = [
                    tag.get("src", "")
                    for tag in soup.find_all("script", src=True)
                    if tag.get("src") and not _VENDOR_URL_RE.search(tag.get("src", ""))
                ]
                for js_src in external_js[:5]:
                    js_url = urljoin(url, js_src)
                    try:
                        js_resp = await self._request("GET", js_url, follow_redirects=True)
                        finding = self._check_dom_taint(js_resp.text, js_url)
                        if finding:
                            findings.append(finding)
                            break
                    except Exception:
                        continue

        except Exception as exc:
            logger.debug("xss_dom_failed", url=url, error=str(exc))

        return findings

    @staticmethod
    def _check_dom_taint(src_text: str, url: str) -> Finding | None:
        """Check a JS snippet for direct source→sink data flow within proximity window."""
        source_matches = list(_DOM_SOURCES_RE.finditer(src_text))
        sink_matches = list(_DOM_SINKS_RE.finditer(src_text))
        if not source_matches or not sink_matches:
            return None

        for src_m in source_matches:
            for sink_m in sink_matches:
                distance = abs(src_m.start() - sink_m.start())
                if distance > _DOM_PROXIMITY:
                    continue
                start = min(src_m.start(), sink_m.start())
                end = max(src_m.end(), sink_m.end())
                span = src_text[start:end]
                if _SANITIZERS.search(span):
                    continue
                snippet = span[:300].replace("\n", " ")
                return Finding(
                    vuln_type=VulnType.XSS_DOM,
                    severity=Severity.MEDIUM,
                    url=url,
                    evidence=f"Direct source→sink data flow detected: {snippet!r}",
                    cvss_score=6.1,
                    cwe_id="CWE-79",
                    owasp_ref="A03:2021",
                    remediation=(
                        "Avoid passing user-controlled data (location.search, "
                        "location.hash) directly to dangerous DOM sinks. "
                        "Use textContent instead of innerHTML, or sanitize with DOMPurify."
                    ),
                )
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _canary_is_encoded(body: str, canary: str) -> bool:
        idx = body.index(canary)
        window = body[max(0, idx - 50): idx + len(canary) + 50]
        return any(m in window for m in _ENCODING_MARKERS)

    @staticmethod
    def _detect_context(body: str, canary: str) -> str:
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
