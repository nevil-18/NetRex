from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from . import blacklist_store

DOMAIN_RE = re.compile(
    r"(?:https?://)?(?:www\.)?"
    r"([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)",
    re.IGNORECASE,
)


def extract_hostname(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    try:
        host = urlparse(raw).hostname or ""
    except ValueError:  # malformed links such as http://[ must not abort a scan
        return ""
    if host.startswith("www."):
        host = host[4:]
    return host.lower()


def _domain_pattern(domain: str) -> re.Pattern[str]:
    """Match a domain on label boundaries: not rabbit.ly or bit.ly.evil.com for bit.ly."""
    return re.compile(rf"(?<![a-z0-9-]){re.escape(domain.lower())}(?![a-z0-9-]|\.[a-z0-9])")


def _context_around(text: str, start: int, end: int, pad: int = 48) -> str:
    left = max(0, start - pad)
    right = min(len(text), end + pad)
    snippet = text[left:right].replace("\n", " ").strip()
    if left > 0:
        snippet = "…" + snippet
    if right < len(text):
        snippet = snippet + "…"
    return snippet


def find_domain_mentions(html: str, page_url: str = "") -> list[dict[str, Any]]:
    """Find blacklist domain mentions in HTML and return highlight payloads."""
    blacklist = {e["domain"]: e for e in blacklist_store.list_domains()}
    if not blacklist:
        return []

    soup = BeautifulSoup(html or "", "lxml")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    text = soup.get_text(" ", strip=True)
    hrefs: list[str] = []
    for a in soup.find_all("a", href=True):
        hrefs.append(a["href"])
    for tag in soup.find_all(["img", "script", "iframe", "link", "form"]):
        for attr in ("src", "action", "href"):
            val = tag.get(attr)
            if val:
                hrefs.append(val)

    page_host = extract_hostname(page_url)
    hits: dict[str, dict[str, Any]] = {}

    def record(domain: str, source: str, context: str) -> None:
        entry = blacklist.get(domain)
        if not entry:
            # also check parent matches in extracted domain
            for blocked in blacklist:
                if domain == blocked or domain.endswith("." + blocked):
                    entry = blacklist[blocked]
                    domain = blocked
                    break
        if not entry:
            return
        bucket = hits.setdefault(
            domain,
            {
                "domain": domain,
                "reason": entry.get("reason", ""),
                "severity": entry.get("severity", "high"),
                "count": 0,
                "sources": set(),
                "contexts": [],
            },
        )
        bucket["count"] += 1
        bucket["sources"].add(source)
        if context and len(bucket["contexts"]) < 5:
            bucket["contexts"].append(context)

    # Exact string search for each blacklisted domain (case-insensitive)
    lower_html = (html or "").lower()
    lower_text = text.lower()
    for domain, entry in blacklist.items():
        pattern = _domain_pattern(domain)
        for found in pattern.finditer(lower_text):
            record(domain, "text", _context_around(text, found.start(), found.end()))

        for found in pattern.finditer(lower_html):
            # only count HTML attribute hits that aren't already text-counted heavily
            record(domain, "html", _context_around(html or "", found.start(), found.end()))
            if hits.get(domain, {}).get("count", 0) > 40:
                break

    for href in hrefs:
        host = extract_hostname(href)
        if not host:
            continue
        matched = blacklist_store.is_blocked(host)
        if matched:
            record(matched["domain"], "link", href[:200])

    # Also catch free-form domains in text that map to blacklist parents
    for match in DOMAIN_RE.finditer(text):
        host = match.group(1).lower()
        if host == page_host:
            continue
        matched = blacklist_store.is_blocked(host)
        if matched:
            record(
                matched["domain"],
                "text",
                _context_around(text, match.start(), match.end()),
            )

    results: list[dict[str, Any]] = []
    for item in hits.values():
        results.append(
            {
                "domain": item["domain"],
                "reason": item["reason"],
                "severity": item["severity"],
                "count": item["count"],
                "sources": sorted(item["sources"]),
                "contexts": item["contexts"],
            }
        )
    results.sort(key=lambda x: (-{"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x["severity"], 0), -x["count"]))
    return results


def highlight_selectors(matches: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Return domain strings the extension should highlight in the DOM."""
    return [
        {
            "domain": m["domain"],
            "severity": m["severity"],
            "reason": m["reason"],
        }
        for m in matches
    ]
