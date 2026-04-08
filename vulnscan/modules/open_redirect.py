from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
import structlog

from ..core.base_scanner import BaseScanner
from ..models.enums import Severity, VulnType
from ..models.finding import Finding

logger = structlog.get_logger(__name__)

REDIRECT_PARAMS = (
    "redirect", "url", "next", "return", "goto", "dest",
    "destination", "redir", "redirect_url", "return_url",
    "forward", "location", "target", "to",
)

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "/%09/evil.com",
    "https://target.com@evil.com",
    "https://evil.com%2F",
    "//evil.com/%2F..",
    "\tevil.com",
]

EVIL_DOMAIN = "evil.com"


def _inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, "",
    ))


def _is_offsite_redirect(location: str) -> bool:
    """Return True if Location header redirects to evil.com."""
    loc_lower = location.lower()
    return (
        EVIL_DOMAIN in loc_lower
        or loc_lower.startswith("//evil")
        or loc_lower.startswith("/\\evil")
    )


class OpenRedirectScanner(BaseScanner):
    """Test for open redirect vulnerabilities in redirect-like parameters."""

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        existing_params = set(parse_qs(parsed.query, keep_blank_values=True).keys())

        # Test known redirect params that are already present in the URL
        params_to_test = existing_params.intersection(set(p.lower() for p in REDIRECT_PARAMS))
        # Also inject common redirect params not already in URL
        params_to_test.update(REDIRECT_PARAMS)

        for param in params_to_test:
            for payload in REDIRECT_PAYLOADS:
                finding = await self._test_redirect(url, param, payload)
                if finding:
                    findings.append(finding)
                    break  # one finding per param is enough

        return findings

    async def _test_redirect(
        self, url: str, param: str, payload: str
    ) -> Finding | None:
        test_url = _inject_param(url, param, payload)
        try:
            resp = await self._request(
                "GET",
                test_url,
                follow_redirects=False,
            )
        except (httpx.TimeoutException, httpx.ConnectError, Exception) as exc:
            logger.debug(
                "open_redirect_request_failed",
                url=url, param=param, error=str(exc),
            )
            return None

        if resp.status_code not in (301, 302, 303, 307, 308):
            return None

        location = resp.headers.get("location", "")
        if not location:
            return None

        if _is_offsite_redirect(location):
            logger.info(
                "open_redirect_found",
                url=url, param=param, payload=payload, location=location,
            )
            return Finding(
                vuln_type=VulnType.OPEN_REDIRECT,
                severity=Severity.MEDIUM,
                url=url,
                parameter=param,
                payload=payload,
                evidence=(
                    f"HTTP {resp.status_code} → Location: {location!r} "
                    f"(payload={payload!r})"
                ),
                cvss_score=6.1,
                cwe_id="CWE-601",
                owasp_ref="A01:2021",
                remediation=(
                    "Validate redirect destinations against a whitelist of "
                    "allowed URLs/domains. Never redirect to user-supplied URLs."
                ),
            )
        return None
