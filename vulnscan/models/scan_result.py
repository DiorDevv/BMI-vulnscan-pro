from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field, computed_field

from .enums import ScanStatus, Severity
from .finding import Finding


class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    target: str
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    findings: list[Finding] = Field(default_factory=list)
    total_requests: int = 0
    scan_profile: str = "quick"
    modules_run: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def duration_seconds(self) -> float:
        if self.finished_at is None:
            return (datetime.now(timezone.utc) - self.started_at).total_seconds()
        return (self.finished_at - self.started_at).total_seconds()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def risk_score(self) -> int:
        """Compute 0-100 risk score based on finding severities."""
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 7,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
        total = sum(weights.get(f.severity, 0) for f in self.findings if not f.false_positive)
        return min(100, total)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            if not f.false_positive:
                counts[f.severity.value] += 1
        return counts

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def finish(self, status: ScanStatus = ScanStatus.DONE) -> None:
        self.status = status
        self.finished_at = datetime.now(timezone.utc)
