from __future__ import annotations

import asyncio
import json
import re
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from . import blacklist_store, gemini
from .scanner import extract_hostname, find_domain_mentions

SUSPICIOUS_TLDS = {
    "xyz", "tk", "ml", "ga", "cf", "gq", "top", "buzz", "work", "click",
    "country", "stream", "download", "loan", "win", "review", "zip", "mov",
}

BRAND_KEYWORDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook",
    "instagram", "chase", "wellsfargo", "bankofamerica", "citibank", "irs",
    "dhl", "ups", "fedex", "coinbase", "binance", "metamask", "whatsapp",
]

URGENCY_PATTERNS = [
    r"act\s+now",
    r"urgent(ly)?",
    r"account\s+(suspended|locked|compromised)",
    r"verify\s+(your\s+)?(account|identity)",
    r"confirm\s+(your\s+)?(password|identity|account)",
    r"limited\s+time",
    r"click\s+here\s+(immediately|now)",
    r"unusual\s+activity",
    r"security\s+alert",
    r"password\s+expir",
    r"won\s+a\s+prize",
    r"claim\s+(your\s+)?(reward|prize)",
]

LLM_TIMEOUT_SECONDS = 30.0

IP_HOST_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _clamp(score: int) -> int:
    return max(0, min(100, score))


def _level(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "safe"


def _recommendations(score: int, factors: list[str], blocked: bool) -> list[str]:
    tips: list[str] = []
    if blocked:
        tips.append("Do not enter credentials or download files from this site.")
        tips.append("Close the tab and report the domain if it was unexpected.")
    if score >= 65:
        tips.append("Avoid clicking links or opening attachments tied to this domain.")
        tips.append("Navigate only by typing trusted URLs yourself, never from emails.")
    elif score >= 40:
        tips.append("Double-check the domain spelling against the official brand site.")
        tips.append("Prefer bookmarks for banking and email logins.")
    else:
        tips.append("Stay alert for unexpected login prompts or payment requests.")
        tips.append("Keep your browser and extensions up to date.")
    if any("shortener" in f.lower() or "shortened" in f.lower() for f in factors):
        tips.append("Expand shortened URLs before visiting them.")
    if any("urgency" in f.lower() for f in factors):
        tips.append("Pressure language is a common phishing tactic — slow down.")
    return tips[:5]


async def _llm_enrich(domain: str, html_excerpt: str, base: dict[str, Any]) -> dict[str, Any] | None:
    """Optional Gemini enrichment. Returns None when unavailable."""
    if not gemini.api_key():
        return None
    try:
        prompt = (
            "You are a cybersecurity analyst. Score phishing/malware risk 0-100 for this domain. "
            "Reply ONLY with compact JSON keys: score (int), summary (string), factors (string array max 4). "
            f"Domain: {domain}\n"
            f"Heuristic score: {base.get('score')}\n"
            f"Heuristic factors: {base.get('factors')}\n"
            f"Page excerpt:\n{html_excerpt[:2500]}"
        )
        reply = await asyncio.to_thread(
            gemini.generate_json, "Return JSON only.", prompt, LLM_TIMEOUT_SECONDS
        )
        parsed = json.loads(reply.text)
        score = _clamp(int(parsed.get("score", base["score"])))
        factors = list(parsed.get("factors") or [])[:4]
        summary = str(parsed.get("summary") or "").strip()
        return {
            "score": score,
            "factors": factors,
            "summary": summary,
            "llm": True,
        }
    except Exception:
        return None


def heuristic_analyze(url: str, html: str | None = None) -> dict[str, Any]:
    domain = extract_hostname(url)
    factors: list[str] = []
    score = 8  # baseline internet noise

    blocked_entry = blacklist_store.is_blocked(domain) if domain else None
    blocked = blocked_entry is not None

    if not domain:
        return {
            "domain": "",
            "url": url,
            "blocked": False,
            "score": 0,
            "level": "safe",
            "factors": ["No domain provided"],
            "summary": "Nothing to analyze.",
            "recommendations": _recommendations(0, [], False),
            "blacklist": None,
            "mentions": [],
            "llm": False,
        }

    if blocked_entry:
        sev = blocked_entry.get("severity", "high")
        bump = {"critical": 98, "high": 88, "medium": 72, "low": 55}.get(sev, 88)
        score = max(score, bump)
        factors.append(
            f"Domain is on the NetRex blacklist ({sev}): {blocked_entry.get('reason', '')}"
        )

    # IP literal host
    if IP_HOST_RE.match(domain):
        score += 35
        factors.append("Uses a raw IP address instead of a domain name")

    labels = domain.split(".")
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        score += 22
        factors.append(f"Suspicious top-level domain .{tld}")

    if len(labels) >= 4:
        score += 12
        factors.append("Unusually deep subdomain chain")

    # Brand impersonation cues in domain
    compact = domain.replace("-", "").replace(".", "")
    for brand in BRAND_KEYWORDS:
        if brand in compact and brand not in domain.split(".")[0]:
            # brand appears but not as exact registrable feel
            score += 28
            factors.append(f"Domain appears to impersonate “{brand}”")
            break
        if brand in domain and not domain.endswith(f"{brand}.com") and brand not in {
            "google", "amazon", "microsoft", "apple", "paypal", "facebook", "instagram", "netflix"
        }:
            pass
        # hyphenated brand bait: paypal-secure.example
        if re.search(rf"(^|[.-]){brand}([.-]|$)", domain) and not domain.endswith(
            (f"{brand}.com", f"{brand}.net", f"{brand}.org")
        ):
            if f"impersonate “{brand}”" not in " ".join(factors):
                score += 30
                factors.append(f"Brand keyword “{brand}” used in a non-official domain")
            break

    if any(token in domain for token in ("login", "verify", "secure", "update", "account", "support", "wallet")):
        if not blocked_entry:
            score += 14
            factors.append("Domain contains common phishing bait words (login/verify/secure)")

    parsed = urlparse(url if "://" in url else f"https://{url}")
    if parsed.scheme == "http":
        score += 10
        factors.append("Page is served over insecure HTTP")

    mentions: list[dict[str, Any]] = []
    if html:
        mentions = find_domain_mentions(html, url)
        if mentions:
            top = mentions[0]
            score += min(40, 12 + top["count"] * 2)
            factors.append(
                f"Page references blacklisted domain {top['domain']} ({top['count']} hits)"
            )

        soup = BeautifulSoup(html, "lxml")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text(" ", strip=True).lower()

        urgency_hits = 0
        for pattern in URGENCY_PATTERNS:
            if re.search(pattern, text, re.I):
                urgency_hits += 1
        if urgency_hits:
            score += min(24, 8 * urgency_hits)
            factors.append(f"Detected {urgency_hits} urgency/phishing language pattern(s)")

        password_inputs = soup.find_all("input", {"type": "password"})
        if password_inputs and parsed.scheme != "https":
            score += 25
            factors.append("Password form on a non-HTTPS page")
        elif password_inputs and blocked_entry:
            score += 10
            factors.append("Credential form present on a blacklisted domain")

        # external form actions
        for form in soup.find_all("form", action=True):
            action_host = extract_hostname(form["action"])
            if action_host and action_host != domain:
                score += 18
                factors.append(f"Form submits data to a different host ({action_host})")
                break

    score = _clamp(score)
    # if nothing alarming found, keep score modest
    if not factors:
        factors.append("No strong phishing indicators detected by heuristics")
        score = min(score, 15)

    summary = _summary(domain, score, blocked_entry, factors)
    return {
        "domain": domain,
        "url": url,
        "blocked": blocked,
        "score": score,
        "level": _level(score),
        "factors": factors[:8],
        "summary": summary,
        "recommendations": _recommendations(score, factors, blocked),
        "blacklist": blocked_entry,
        "mentions": mentions,
        "llm": False,
    }


def _summary(domain: str, score: int, blocked_entry: dict | None, factors: list[str]) -> str:
    level = _level(score)
    if blocked_entry:
        return (
            f"{domain} is blocked by NetRex ({blocked_entry.get('severity', 'high')}). "
            f"{blocked_entry.get('reason', '')}".strip()
        )
    if level in {"critical", "high"}:
        return f"{domain} looks high-risk. {factors[0] if factors else ''}"
    if level == "medium":
        return f"{domain} shows mixed signals — proceed with caution."
    if level == "low":
        return f"{domain} appears mostly ordinary, with minor caveats."
    return f"{domain} looks relatively safe based on available signals."


async def analyze(url: str, html: str | None = None, use_llm: bool = True) -> dict[str, Any]:
    base = heuristic_analyze(url, html)
    if use_llm and html:
        excerpt = BeautifulSoup(html, "lxml").get_text(" ", strip=True)[:2500]
        enriched = await _llm_enrich(base["domain"], excerpt, base)
        if enriched:
            # blend: take max of heuristic and llm, merge factors
            blended = max(base["score"], enriched["score"])
            factors = []
            for f in enriched.get("factors") or []:
                if f not in factors:
                    factors.append(f)
            for f in base["factors"]:
                if f not in factors:
                    factors.append(f)
            base["score"] = _clamp(blended)
            base["level"] = _level(base["score"])
            base["factors"] = factors[:8]
            if enriched.get("summary"):
                base["summary"] = enriched["summary"]
            base["recommendations"] = _recommendations(
                base["score"], base["factors"], base["blocked"]
            )
            base["llm"] = True
    return base
