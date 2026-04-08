from __future__ import annotations

import asyncio
from difflib import SequenceMatcher
from urllib.parse import urljoin

import httpx
import structlog

from ..core.base_scanner import BaseScanner
from ..models.enums import Severity, VulnType
from ..models.finding import Finding

logger = structlog.get_logger(__name__)

SENSITIVE_PATHS = frozenset({
    "/.env", "/config.yml", "/config.yaml", "/database.yml",
    "/.git/config", "/backup.zip", "/backup.tar.gz",
    "/db.sql", "/dump.sql", "/wp-config.php", "/phpinfo.php",
    "/server-status", "/server-info", "/actuator/health",
    "/actuator/env", "/.htpasswd", "/.htaccess",
    "/web.config", "/app.config", "/settings.py",
    "/config.php", "/configuration.php", "/.DS_Store",
    "/composer.json", "/package.json", "/yarn.lock",
    "/Gemfile", "/requirements.txt",
})


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a[:2000], b[:2000]).ratio()


class DirBruteforcer(BaseScanner):
    """Async concurrent directory/file discovery with 404 baseline detection."""

    async def scan(self, url: str) -> list[Finding]:
        base_url = url.rstrip("/")
        findings: list[Finding] = []

        # Establish 404 baseline
        baseline_text = await self._get_404_baseline(base_url)

        # Load wordlist
        paths = self.payload_engine.load_wordlist("dirs.txt")
        if not paths:
            logger.warning("dir_wordlist_empty", base_url=base_url)
            return findings

        # Add sensitive file paths (always probe these)
        all_paths = list(dict.fromkeys(paths + list(SENSITIVE_PATHS)))

        semaphore = asyncio.Semaphore(50)
        tasks = [
            self._probe(base_url, path, semaphore, baseline_text)
            for path in all_paths
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Finding):
                findings.append(result)
            elif isinstance(result, Exception):
                logger.debug("dir_probe_error", error=str(result))

        logger.info(
            "dir_bruteforce_complete",
            base_url=base_url,
            paths_tested=len(all_paths),
            findings=len(findings),
        )
        return findings

    async def _probe(
        self,
        base_url: str,
        path: str,
        semaphore: asyncio.Semaphore,
        baseline_text: str,
    ) -> Finding | None:
        if not path.startswith("/"):
            path = "/" + path
        target_url = urljoin(base_url + "/", path.lstrip("/"))

        async with semaphore:
            try:
                resp = await self._request(
                    "GET",
                    target_url,
                    follow_redirects=False,
                )
            except (httpx.TimeoutException, httpx.ConnectError):
                return None
            except Exception as exc:
                logger.debug("dir_probe_exception", url=target_url, error=str(exc))
                return None

            is_sensitive = any(path.lower() == s.lower() for s in SENSITIVE_PATHS)

            if resp.status_code == 200:
                # Verify it's not a catch-all 200
                similarity = _similarity(resp.text, baseline_text)
                if similarity >= 0.85 and not is_sensitive:
                    return None  # likely catch-all

                severity = Severity.HIGH if is_sensitive else Severity.MEDIUM
                vuln_type = VulnType.SENSITIVE_FILE if is_sensitive else VulnType.DIR_LISTING

                return Finding(
                    vuln_type=vuln_type,
                    severity=severity,
                    url=target_url,
                    evidence=(
                        f"HTTP 200 response ({len(resp.content)} bytes). "
                        f"{'Sensitive file exposed.' if is_sensitive else 'Directory accessible.'}"
                    ),
                    cvss_score=7.5 if is_sensitive else 5.3,
                    cwe_id="CWE-538" if is_sensitive else "CWE-548",
                    owasp_ref="A01:2021",
                    remediation=(
                        "Remove or restrict access to this resource. "
                        "Ensure sensitive files are not in the web root."
                    ),
                )

            elif resp.status_code == 403:
                # Resource exists but is forbidden — still noteworthy
                return Finding(
                    vuln_type=VulnType.DIR_LISTING,
                    severity=Severity.LOW,
                    url=target_url,
                    evidence=f"HTTP 403 — resource exists but is forbidden",
                    cvss_score=2.6,
                    cwe_id="CWE-548",
                    owasp_ref="A01:2021",
                    remediation=(
                        "Verify this resource should exist. "
                        "If not needed, remove it entirely."
                    ),
                )

        return None

    async def _get_404_baseline(self, base_url: str) -> str:
        """Fetch a definitely-non-existent URL to establish 404 baseline."""
        fake_path = f"/vulnscan_probe_{id(self)}_notexist"
        try:
            resp = await self._request(
                "GET",
                urljoin(base_url + "/", fake_path.lstrip("/")),
                follow_redirects=True,
            )
            return resp.text
        except Exception:
            return ""
