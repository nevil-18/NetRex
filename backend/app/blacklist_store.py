from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "blacklist.json"
_lock = threading.Lock()

_HOSTNAME_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}|\d{1,3}(?:\.\d{1,3}){3}")
_IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
# Second-level labels used as public suffixes under country codes, as in co.uk.
_COUNTRY_SECOND_LEVELS = {"co", "com", "net", "org", "gov", "ac", "edu"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize(domain: str) -> str:
    """Reduce a domain or pasted URL to its bare hostname."""
    d = domain.strip().lower()
    try:
        d = urlsplit(d if "://" in d else f"https://{d}").hostname or ""
    except ValueError:
        return ""
    if d.startswith("www."):
        d = d[4:]
    return d.rstrip(".")


def registered_domain(hostname: str) -> str:
    """Best-effort registrable domain, e.g. a.b.example.co.uk -> example.co.uk."""
    if _IP_RE.fullmatch(hostname) or ":" in hostname:
        return hostname
    labels = hostname.split(".")
    if len(labels) < 2:
        return hostname
    keep = 3 if len(labels[-1]) == 2 and labels[-2] in _COUNTRY_SECOND_LEVELS else 2
    return ".".join(labels[-keep:])


def _is_public_suffix(hostname: str) -> bool:
    labels = hostname.split(".")
    return len(labels) == 2 and len(labels[1]) == 2 and labels[0] in _COUNTRY_SECOND_LEVELS


def _read() -> dict[str, Any]:
    if not DATA_PATH.exists():
        return {"domains": []}
    with DATA_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def _write(data: dict[str, Any]) -> None:
    DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DATA_PATH.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def list_domains() -> list[dict[str, Any]]:
    with _lock:
        return list(_read().get("domains", []))


def get_domain(domain: str) -> dict[str, Any] | None:
    target = _normalize(domain)
    for entry in list_domains():
        if entry.get("domain") == target:
            return entry
    return None


def is_blocked(domain: str) -> dict[str, Any] | None:
    """Return blacklist entry if domain or any parent matches."""
    target = _normalize(domain)
    entries = {e["domain"]: e for e in list_domains()}
    parts = target.split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in entries:
            return entries[candidate]
    return None


def add_domain(
    domain: str,
    reason: str = "",
    severity: str = "high",
) -> dict[str, Any]:
    normalized = _normalize(domain)
    if not _HOSTNAME_RE.fullmatch(normalized):
        raise ValueError("Enter a valid domain, such as evil-domain.com")
    if _is_public_suffix(normalized):
        raise ValueError(f"{normalized} is a public suffix; blocking it would block every site under it")
    severity = severity.lower().strip() or "high"
    if severity not in {"low", "medium", "high", "critical"}:
        severity = "high"

    with _lock:
        data = _read()
        domains = data.setdefault("domains", [])
        for entry in domains:
            if entry.get("domain") == normalized:
                entry["reason"] = reason or entry.get("reason", "")
                entry["severity"] = severity
                entry["updated_at"] = _utc_now()
                _write(data)
                return entry
        entry = {
            "domain": normalized,
            "reason": reason or "Manually added",
            "added_at": _utc_now(),
            "severity": severity,
        }
        domains.append(entry)
        _write(data)
        return entry


def remove_domain(domain: str) -> bool:
    normalized = _normalize(domain)
    with _lock:
        data = _read()
        before = len(data.get("domains", []))
        data["domains"] = [
            e for e in data.get("domains", []) if e.get("domain") != normalized
        ]
        if len(data["domains"]) == before:
            return False
        _write(data)
        return True


def stats() -> dict[str, Any]:
    domains = list_domains()
    by_severity: dict[str, int] = {}
    for entry in domains:
        sev = entry.get("severity", "medium")
        by_severity[sev] = by_severity.get(sev, 0) + 1
    return {
        "total": len(domains),
        "by_severity": by_severity,
    }
