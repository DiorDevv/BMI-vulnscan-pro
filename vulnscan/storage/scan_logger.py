"""
ScanLogger — har bir scan natijasini avtomatik faylga saqlaydi.

Fayl tuzilmasi:
  {base_dir}/
  ├── index.jsonl            ← append-only log (har bir scan 1 qator)
  └── {hostname}/
      └── {date}_{scan_id[:8]}.json   ← to'liq scan ma'lumoti

Keyinchalik ma'lumot olish uchun:
  - index.jsonl ni grep qilish yoki JSON reader bilan o'qish
  - Aniq hostname papkasidan JSON faylni ochish
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import structlog

from ..models.scan_result import ScanResult

logger = structlog.get_logger(__name__)

_SAFE_NAME_RE = re.compile(r"[^\w\-.]")   # faylga xavfli belgilarni tozalash


def _safe(name: str) -> str:
    return _SAFE_NAME_RE.sub("_", name)[:80]


class ScanLogger:
    """
    Scan natijalarini fayl tizimiga avtomatik saqlaydi.

    Ishlatilishi:
        sl = ScanLogger()                     # default: ./vulnscan_reports
        sl = ScanLogger("/my/reports")        # maxsus papka

        path = sl.save(scan_result)
        print(f"Saqlandi: {path}")
    """

    def __init__(self, base_dir: str | Path | None = None) -> None:
        if base_dir is None:
            base_dir = Path.cwd() / "vulnscan_reports"
        self.base_dir = Path(base_dir)
        self.index_path = self.base_dir / "index.jsonl"

    # ── Public API ─────────────────────────────────────────────────────────

    def save(self, result: ScanResult) -> Path:
        """
        ScanResult ni JSON faylga yozadi va index ga qo'shadi.
        Returns: yaratilgan JSON faylning path i.
        """
        path = self._resolve_path(result)
        path.parent.mkdir(parents=True, exist_ok=True)

        self._write_json(path, result)
        self._append_index(result, path)

        logger.info(
            "scan_saved_to_file",
            path=str(path),
            scan_id=result.id,
            target=result.target,
            findings=len(result.findings),
            risk_score=result.risk_score,
        )
        return path

    def list_scans(self, hostname: str | None = None, limit: int = 50) -> list[dict]:
        """
        index.jsonl dan oxirgi N scanlarni qaytaradi.
        hostname berilsa faqat o'sha xostga oidlarni qaytaradi.
        """
        if not self.index_path.exists():
            return []

        lines = self.index_path.read_text(encoding="utf-8").splitlines()
        entries: list[dict] = []
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if hostname and entry.get("hostname") != hostname:
                continue
            entries.append(entry)
            if len(entries) >= limit:
                break
        return entries

    def load(self, path: str | Path) -> dict:
        """Saqlangan JSON faylni dict sifatida qaytaradi."""
        return json.loads(Path(path).read_text(encoding="utf-8"))

    # ── Internal ───────────────────────────────────────────────────────────

    def _resolve_path(self, result: ScanResult) -> Path:
        hostname = _safe(self._hostname(result.target))
        ts = result.started_at.strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{ts}_{result.id[:8]}.json"
        return self.base_dir / hostname / filename

    @staticmethod
    def _hostname(target: str) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        return parsed.hostname or parsed.path or target

    def _write_json(self, path: Path, result: ScanResult) -> None:
        data = result.model_dump(mode="json")
        # datetime obyektlarini ISO string ga aylantirish
        path.write_text(
            json.dumps(data, indent=2, default=str, ensure_ascii=False),
            encoding="utf-8",
        )

    def _append_index(self, result: ScanResult, saved_path: Path) -> None:
        """index.jsonl ga bir qator qo'shadi — grep va stream-read uchun qulay."""
        entry = {
            "scan_id":    result.id,
            "target":     result.target,
            "hostname":   self._hostname(result.target),
            "status":     result.status.value,
            "started_at": result.started_at.isoformat(),
            "finished_at": result.finished_at.isoformat() if result.finished_at else None,
            "duration_s": round(result.duration_seconds, 2),
            "risk_score": result.risk_score,
            "findings":   len(result.findings),
            "severity_counts": result.severity_counts,
            "modules":    result.modules_run,
            "file":       str(saved_path),
        }
        self.base_dir.mkdir(parents=True, exist_ok=True)
        with self.index_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
