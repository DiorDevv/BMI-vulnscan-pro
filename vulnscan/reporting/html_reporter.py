from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models.scan_result import ScanResult


class HTMLReporter:
    """Generate a rich HTML report using Jinja2."""

    def __init__(self) -> None:
        templates_dir = Path(__file__).parent / "templates"
        self._env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self._env.filters["tojson"] = self._to_json_filter

    @staticmethod
    def _to_json_filter(value: object) -> str:
        import json
        return json.dumps(value)

    def generate(self, result: ScanResult, output_path: str | Path) -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        active_findings = [f for f in result.findings if not f.false_positive]

        # Category chart data
        cat_counts: Counter[str] = Counter(
            f.vuln_type.value.replace("_", " ").title() for f in active_findings
        )
        category_labels = list(cat_counts.keys())
        category_data = list(cat_counts.values())

        # Timeline data — bucket by minute
        timeline: dict[str, int] = defaultdict(int)
        for f in active_findings:
            minute_key = f.discovered.strftime("%H:%M")
            timeline[minute_key] += 1
        sorted_tl = sorted(timeline.items())
        timeline_labels = [k for k, _ in sorted_tl]
        timeline_data = [v for _, v in sorted_tl]

        template = self._env.get_template("report.html.j2")
        html = template.render(
            result=result,
            active_findings=active_findings,
            now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            category_labels=category_labels,
            category_data=category_data,
            timeline_labels=timeline_labels,
            timeline_data=timeline_data,
        )

        path.write_text(html, encoding="utf-8")
        return path
