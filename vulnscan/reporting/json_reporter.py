from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from ..models.scan_result import ScanResult


class JSONReporter:
    """Generate JSON and CSV reports."""

    def generate_json(self, result: ScanResult, output_path: str | Path) -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = result.model_dump(mode="json")
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return path

    def generate_csv(self, result: ScanResult, output_path: str | Path) -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "id", "severity", "vuln_type", "url", "parameter",
            "payload", "cvss_score", "cwe_id", "owasp_ref",
            "evidence", "remediation", "discovered", "false_positive",
        ]

        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()

        for f in result.findings:
            writer.writerow({
                "id": f.id,
                "severity": f.severity.value,
                "vuln_type": f.vuln_type.value,
                "url": f.url,
                "parameter": f.parameter or "",
                "payload": f.payload or "",
                "cvss_score": f.cvss_score,
                "cwe_id": f.cwe_id,
                "owasp_ref": f.owasp_ref,
                "evidence": f.evidence[:500],
                "remediation": f.remediation,
                "discovered": f.discovered.isoformat(),
                "false_positive": f.false_positive,
            })

        path.write_text(buf.getvalue(), encoding="utf-8")
        return path
