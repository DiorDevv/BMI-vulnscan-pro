from __future__ import annotations

from urllib.parse import urlparse

import httpx
import structlog

from ..core.base_scanner import BaseScanner
from ..models.enums import Severity, VulnType
from ..models.finding import Finding

logger = structlog.get_logger(__name__)


class CORSChecker(BaseScanner):
    """Test for CORS misconfiguration using crafted Origin headers."""

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        target_host = parsed.netloc

        test_cases: list[tuple[str, str]] = [
            ("https://evil.com", "arbitrary origin reflection"),
            ("null", "null origin (iframe sandbox bypass)"),
            (f"https://{target_host}.evil.com", "suffix bypass"),
            (f"https://evil{target_host}", "prefix bypass"),
        ]

        for origin, description in test_cases:
            result = await self._test_origin(url, origin, description)
            if result:
                findings.append(result)

        return findings

    async def _test_origin(
        self, url: str, origin: str, description: str
    ) -> Finding | None:
        try:
            resp = await self._request(
                "GET",
                url,
                headers={"Origin": origin},
            )
        except (httpx.TimeoutException, httpx.ConnectError, Exception) as exc:
            logger.debug("cors_request_failed", url=url, origin=origin, error=str(exc))
            return None

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()
        acam = resp.headers.get("access-control-allow-methods", "")

        if not acao:
            return None

        # Case 1: Server reflects arbitrary origin
        origin_reflected = (acao == origin and origin not in ("*",))
        wildcard = acao == "*"

        if not (origin_reflected or wildcard):
            return None

        # Determine severity
        credentials_allowed = acac == "true"
        if origin_reflected and credentials_allowed:
            severity = Severity.CRITICAL
            cvss = 9.6
            desc = (
                f"CORS: Origin {origin!r} is reflected in ACAO AND "
                f"Access-Control-Allow-Credentials: true ({description}). "
                "Attacker can make credentialed cross-origin requests."
            )
        elif origin == "null" and credentials_allowed:
            severity = Severity.HIGH
            cvss = 8.1
            desc = (
                "CORS: null origin accepted with credentials=true. "
                "Exploitable via sandboxed iframe."
            )
        elif origin_reflected:
            severity = Severity.HIGH
            cvss = 7.5
            desc = (
                f"CORS: Origin {origin!r} reflected in ACAO ({description}). "
                "Sensitive data may be accessible cross-origin."
            )
        else:
            severity = Severity.HIGH
            cvss = 7.5
            desc = f"CORS wildcard (*) present: {description}"

        return Finding(
            vuln_type=VulnType.CORS,
            severity=severity,
            url=url,
            evidence=(
                f"{desc} | ACAO={acao!r} ACAC={acac!r} ACAM={acam!r}"
            ),
            cvss_score=cvss,
            cwe_id="CWE-942",
            owasp_ref="A05:2021",
            remediation=(
                "Restrict Access-Control-Allow-Origin to a whitelist of trusted origins. "
                "Never combine wildcard ACAO with credentials. "
                "Validate Origin headers server-side."
            ),
        )
