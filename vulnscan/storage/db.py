from __future__ import annotations

import json
from pathlib import Path

import aiosqlite
import structlog

from ..models.finding import Finding
from ..models.scan_result import ScanResult

logger = structlog.get_logger(__name__)

CREATE_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    status      TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    profile     TEXT,
    total_reqs  INTEGER DEFAULT 0,
    risk_score  INTEGER DEFAULT 0,
    errors      TEXT DEFAULT '[]'
)
"""

CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id             TEXT PRIMARY KEY,
    scan_id        TEXT NOT NULL,
    vuln_type      TEXT NOT NULL,
    severity       TEXT NOT NULL,
    url            TEXT NOT NULL,
    parameter      TEXT,
    payload        TEXT,
    evidence       TEXT NOT NULL,
    cvss_score     REAL NOT NULL,
    cwe_id         TEXT NOT NULL,
    owasp_ref      TEXT NOT NULL,
    remediation    TEXT NOT NULL,
    discovered     TEXT NOT NULL,
    false_positive INTEGER DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
)
"""


class Database:
    """aiosqlite-backed findings persistence."""

    def __init__(self, path: str | Path = "vulnscan.db") -> None:
        self._path = str(path)
        self._db: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._db = await aiosqlite.connect(self._path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute(CREATE_SCANS)
        await self._db.execute(CREATE_FINDINGS)
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)")
        await self._db.commit()
        logger.info("db_connected", path=self._path)

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    async def save_scan(self, result: ScanResult) -> None:
        if not self._db:
            raise RuntimeError("Database not connected")
        await self._db.execute(
            """INSERT OR REPLACE INTO scans
               (id, target, status, started_at, finished_at, profile,
                total_reqs, risk_score, errors)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                result.id,
                result.target,
                result.status.value,
                result.started_at.isoformat(),
                result.finished_at.isoformat() if result.finished_at else None,
                result.scan_profile,
                result.total_requests,
                result.risk_score,
                json.dumps(result.errors),
            ),
        )
        for finding in result.findings:
            await self._save_finding(result.id, finding)
        await self._db.commit()
        logger.info("scan_saved", scan_id=result.id, findings=len(result.findings))

    async def _save_finding(self, scan_id: str, finding: Finding) -> None:
        if not self._db:
            return
        await self._db.execute(
            """INSERT OR REPLACE INTO findings
               (id, scan_id, vuln_type, severity, url, parameter, payload,
                evidence, cvss_score, cwe_id, owasp_ref, remediation,
                discovered, false_positive)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                finding.id,
                scan_id,
                finding.vuln_type.value,
                finding.severity.value,
                finding.url,
                finding.parameter,
                finding.payload,
                finding.evidence[:2000],
                finding.cvss_score,
                finding.cwe_id,
                finding.owasp_ref,
                finding.remediation,
                finding.discovered.isoformat(),
                int(finding.false_positive),
            ),
        )

    async def list_recent_scans(self, limit: int = 20) -> list[dict]:
        """Return a lightweight list of recent scans (no findings)."""
        if not self._db:
            raise RuntimeError("Database not connected")
        rows = []
        async with self._db.execute(
            "SELECT id, target, status, started_at, finished_at, profile, risk_score "
            "FROM scans ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ) as cursor:
            async for row in cursor:
                rows.append({
                    "id": row["id"],
                    "target": row["target"],
                    "status": row["status"],
                    "started_at": row["started_at"],
                    "finished_at": row["finished_at"],
                    "profile": row["profile"],
                    "risk_score": row["risk_score"],
                })
        return rows

    async def get_scan(self, scan_id: str) -> ScanResult | None:
        if not self._db:
            raise RuntimeError("Database not connected")
        async with self._db.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None

        findings = await self._get_findings_for_scan(scan_id)
        from datetime import datetime
        from ..models.enums import ScanStatus

        result = ScanResult(
            id=row["id"],
            target=row["target"],
            status=ScanStatus(row["status"]),
            started_at=datetime.fromisoformat(row["started_at"]),
            finished_at=datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None,
            findings=findings,
            total_requests=row["total_reqs"] or 0,
            scan_profile=row["profile"] or "quick",
            errors=json.loads(row["errors"] or "[]"),
        )
        return result

    async def _get_findings_for_scan(self, scan_id: str) -> list[Finding]:
        if not self._db:
            return []
        findings: list[Finding] = []
        async with self._db.execute(
            "SELECT * FROM findings WHERE scan_id = ?", (scan_id,)
        ) as cursor:
            async for row in cursor:
                from datetime import datetime
                from ..models.enums import Severity, VulnType
                findings.append(Finding(
                    id=row["id"],
                    vuln_type=VulnType(row["vuln_type"]),
                    severity=Severity(row["severity"]),
                    url=row["url"],
                    parameter=row["parameter"],
                    payload=row["payload"],
                    evidence=row["evidence"],
                    cvss_score=row["cvss_score"],
                    cwe_id=row["cwe_id"],
                    owasp_ref=row["owasp_ref"],
                    remediation=row["remediation"],
                    discovered=datetime.fromisoformat(row["discovered"]),
                    false_positive=bool(row["false_positive"]),
                ))
        return findings
