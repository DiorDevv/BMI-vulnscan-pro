from __future__ import annotations

import asyncio
import re
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

# Content signatures for sensitive files — if the body doesn't match, it's a catch-all
_CONTENT_SIGS: dict[str, re.Pattern[str]] = {
    ".env":            re.compile(r"^[A-Z_][A-Z0-9_]*\s*=", re.MULTILINE),
    ".git/config":     re.compile(r"\[core\]|repositoryformatversion", re.IGNORECASE),
    "wp-config.php":   re.compile(r"DB_NAME|DB_PASSWORD|ABSPATH", re.IGNORECASE),
    "phpinfo.php":     re.compile(r"PHP Version|phpinfo\(\)", re.IGNORECASE),
    ".htpasswd":       re.compile(r":\$(?:apr1|2[ay])\$|:[./A-Za-z0-9]{13}\b"),
    "package.json":    re.compile(r'"name"\s*:', re.IGNORECASE),
    "composer.json":   re.compile(r'"require"\s*:|"name"\s*:', re.IGNORECASE),
    "actuator/env":    re.compile(r'"propertySources"|"activeProfiles"', re.IGNORECASE),
    "server-status":   re.compile(r"Apache|Server Version|requests/sec", re.IGNORECASE),
}


def _content_matches_expectation(path: str, body: str) -> bool:
    """Return False if the response body looks like a generic error page."""
    path_lower = path.lower()
    for key, pattern in _CONTENT_SIGS.items():
        if key in path_lower:
            return bool(pattern.search(body[:3000]))
    # For binary-like paths (zips, tarballs, sql dumps) check content-type externally
    return True


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
                # Guard 1: catch-all 200 detection via body similarity
                similarity = _similarity(resp.text, baseline_text)
                if similarity >= 0.85 and not is_sensitive:
                    return None

                # Guard 2: for sensitive files, verify the body actually looks
                # like the expected file type (not an HTML error page)
                if is_sensitive and not _content_matches_expectation(path, resp.text):
                    # Body doesn't match expected format → likely a catch-all
                    logger.debug(
                        "sensitive_file_content_mismatch",
                        url=target_url,
                        path=path,
                    )
                    return None

                severity = Severity.HIGH if is_sensitive else Severity.MEDIUM
                vuln_type = VulnType.SENSITIVE_FILE if is_sensitive else VulnType.DIR_LISTING

                return Finding(
                    vuln_type=vuln_type,
                    severity=severity,
                    url=target_url,
                    evidence=(
                        f"HTTP 200 — {len(resp.content)} bytes. "
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

            elif resp.status_code == 403 and is_sensitive:
                # 403 only flagged for SENSITIVE paths — for regular dirs it's
                # expected (nginx/Apache default behavior) and too noisy
                return Finding(
                    vuln_type=VulnType.SENSITIVE_FILE,
                    severity=Severity.MEDIUM,
                    url=target_url,
                    evidence="HTTP 403 — sensitive resource exists but access is restricted",
                    cvss_score=4.3,
                    cwe_id="CWE-538",
                    owasp_ref="A01:2021",
                    remediation=(
                        "Remove this sensitive file from the web root entirely. "
                        "A 403 still confirms the resource exists."
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
