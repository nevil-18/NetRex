"""Saved risk reports, kept on disk until purged so a page is only scored once."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "reports.json"
_lock = threading.Lock()


def _read() -> dict[str, dict[str, Any]]:
    try:
        with DATA_PATH.open("r", encoding="utf-8") as f:
            reports = json.load(f).get("reports", {})
    except (FileNotFoundError, json.JSONDecodeError, AttributeError):
        return {}
    return reports if isinstance(reports, dict) else {}


def _write(reports: dict[str, dict[str, Any]]) -> None:
    DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_path = DATA_PATH.with_suffix(".tmp")
    with temp_path.open("w", encoding="utf-8") as f:
        json.dump({"reports": reports}, f, indent=2)
        f.write("\n")
    os.replace(temp_path, DATA_PATH)  # a crash mid-write can't truncate saved reports


def get(url: str) -> dict[str, Any] | None:
    with _lock:
        return _read().get(url)


def save(url: str, report: dict[str, Any]) -> None:
    with _lock:
        reports = _read()
        reports[url] = report
        _write(reports)


def list_reports() -> list[dict[str, Any]]:
    """Report summaries, newest first."""
    with _lock:
        reports = _read()
    summaries = [
        {
            "url": url,
            "domain": report.get("domain", ""),
            "severity": report.get("severity"),
            "level": report.get("level", "unknown"),
            "summary": report.get("summary", ""),
            "generated_at": report.get("generated_at", ""),
            "model": report.get("model", ""),
        }
        for url, report in reports.items()
    ]
    summaries.sort(key=lambda s: s["generated_at"], reverse=True)
    return summaries


def purge(url: str) -> bool:
    with _lock:
        reports = _read()
        if url not in reports:
            return False
        del reports[url]
        _write(reports)
        return True


def purge_all() -> int:
    with _lock:
        reports = _read()
        if reports:
            _write({})
        return len(reports)
