from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field

from .enums import Severity, VulnType


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    vuln_type: VulnType
    severity: Severity
    url: str
    parameter: str | None = None
    payload: str | None = None
    evidence: str  # truncated response snippet proving the vuln
    cvss_score: float
    cwe_id: str  # e.g. "CWE-89"
    owasp_ref: str  # e.g. "A03:2021"
    remediation: str
    discovered: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    false_positive: bool = False

    model_config = {"frozen": False}
