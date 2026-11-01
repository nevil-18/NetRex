"""AI risk report for web pages: fills in prompts/risk-scoring-prompt.md, calls the model
and computes the final percentage on the server, so page text can't set it directly.
Also holds the prompt loading and scoring helpers that email_report.py shares."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from bs4 import BeautifulSoup

from . import blacklist_store, gemini, report_store
from .scanner import extract_hostname

PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "risk-scoring-prompt.md"

WEIGHTS = {
    "lookalike_domain": 0.35,
    "malicious_scripts": 0.30,
    "ai_judgement": 0.20,
    "domain_extension": 0.15,
}
CRITERION_LABELS = {
    "lookalike_domain": "Lookalike domain",
    "malicious_scripts": "Malicious ads and scripts",
    "ai_judgement": "Analyst judgement",
    "domain_extension": "Domain extension",
}

MAX_VISIBLE_TEXT = 20_000
MAX_INLINE_SCRIPTS = 4_000
MAX_LIST_ITEMS = 40
MODEL_TIMEOUT_SECONDS = 45.0

class ModelOutputError(ValueError):
    """The model replied, but not with the JSON the prompt requires."""


def _load_prompts() -> list[str]:
    blocks = re.findall(r"```text\n(.*?)\n```", PROMPT_PATH.read_text(encoding="utf-8"), re.S)
    if len(blocks) != 4:
        raise RuntimeError(f"{PROMPT_PATH} must hold system and user text blocks for websites and emails")
    return blocks


SYSTEM_PROMPT, USER_TEMPLATE, EMAIL_SYSTEM_PROMPT, EMAIL_USER_TEMPLATE = _load_prompts()

# What a failed scoring attempt can raise: provider errors, and replies that aren't usable.
SCORING_ERRORS = (httpx.HTTPError, KeyError, IndexError, TypeError, AttributeError, ValueError)


def escape(value: str) -> str:
    """Stop scraped text from closing a block early and posing as trusted text."""
    return value.replace("<", "&lt;")


def _absolute(page_url: str, ref: str) -> str:
    try:
        return urljoin(page_url, ref.strip())
    except ValueError:
        return ref.strip()


def strip_query(url: str) -> str:
    """Query strings and fragments can hold session tokens, so they aren't sent."""
    try:
        parts = urlsplit(url if "://" in url else f"https://{url}")
    except ValueError:
        return ""
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def extract_site_data(html: str, page_url: str) -> dict[str, str]:
    """Reduce page HTML to the fields the prompt asks for. Input values are never read."""
    soup = BeautifulSoup(html or "", "lxml")

    scripts = soup.find_all("script")
    script_sources = [strip_query(_absolute(page_url, s["src"])) for s in scripts if s.get("src")]
    inline_parts: list[str] = []
    remaining = MAX_INLINE_SCRIPTS
    for script in scripts:
        body = (script.string or "").strip()
        if script.get("src") or not body or remaining <= 0:
            continue
        inline_parts.append(body[: min(1_000, remaining)])
        remaining -= len(inline_parts[-1])

    iframes = [
        " ".join(
            f"{attr}={frame.get(attr)}"
            for attr in ("src", "width", "height", "style", "hidden")
            if frame.get(attr) is not None
        )
        for frame in soup.find_all("iframe")
    ]

    forms = []
    for form in soup.find_all("form"):
        action = strip_query(_absolute(page_url, form.get("action") or page_url))
        types = sorted({(i.get("type") or "text").lower() for i in form.find_all("input")})
        forms.append(f"action={action} inputs={','.join(types) or 'none'}")

    link_hosts: list[str] = []
    for anchor in soup.find_all("a", href=True):
        host = extract_hostname(_absolute(page_url, anchor["href"]))
        if host and host not in link_hosts:
            link_hosts.append(host)

    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()
    visible_text = soup.get_text(" ", strip=True)

    def joined(items: list[str]) -> str:
        return "\n".join(items[:MAX_LIST_ITEMS])

    return {
        "title": title[:300],
        "visible_text_truncated": visible_text[:MAX_VISIBLE_TEXT],
        "list_of_script_src_urls": joined(script_sources),
        "first_N_chars_of_inline_scripts": "\n---\n".join(inline_parts),
        "iframe_src_and_size_list": joined(iframes),
        "form_action_urls_and_input_types": joined(forms),
        "sample_of_link_hosts": joined(link_hosts),
    }


def registered_parts(hostname: str) -> tuple[str, str]:
    """Return (registered_domain, tld) for a hostname."""
    registered = blacklist_store.registered_domain(hostname)
    if re.fullmatch(r"[\d.]+", hostname) or ":" in hostname:
        return registered, ""
    return registered, hostname.rsplit(".", 1)[-1]


def build_user_message(url: str, html: str, on_blacklist: bool) -> str:
    hostname = extract_hostname(url)
    registered, tld = registered_parts(hostname)
    trusted_url = escape(strip_query(url)).replace("\n", "").replace("\r", "")
    values = {
        "url": trusted_url,
        "registered_domain": registered,
        "tld": tld,
        "hostname": hostname,
        "true|false": "true" if on_blacklist else "false",
    }
    values.update({k: escape(v) for k, v in extract_site_data(html, url).items()})
    return fill_template(USER_TEMPLATE, values)


def fill_template(template: str, values: dict[str, str]) -> str:
    # One pass, so a page title containing "{url}" isn't expanded by a later field.
    return re.sub(r"\{([\w|]+)\}", lambda m: values.get(m.group(1), m.group(0)), template)


def severity_from_model(raw: str) -> dict[str, Any]:
    """Validate the model's JSON and compute the final severity percentage."""
    try:
        data = json.loads(raw)
        crit = data["criteria"]
        scores = {key: max(0, min(100, int(crit[key]["score"]))) for key in WEIGHTS}
    except (TypeError, ValueError, KeyError, OverflowError) as exc:
        raise ModelOutputError(f"Model output failed validation: {exc!r}") from exc

    weighted = round(sum(scores[k] * w for k, w in WEIGHTS.items()))
    severity = weighted
    adjustments: list[str] = []
    if max(scores.values()) >= 90 and severity < 70:
        severity = 70
        adjustments.append(
            "One criterion scored 90 or more, so the score was raised to 70 "
            "to stop a strong signal being averaged away."
        )
    injected = bool(data.get("prompt_injection_detected"))
    if injected and severity < 60:
        severity = 60
        adjustments.append("The page tried to instruct the AI, so the score was raised to 60.")

    criteria = criterion_rows(crit, scores, WEIGHTS, CRITERION_LABELS)

    brand = crit["lookalike_domain"].get("impersonated_brand")
    excerpt = data.get("injection_excerpt")
    return {
        "severity": severity,
        "level": severity_level(severity),
        "scores": scores,
        "criteria": criteria,
        "summary": str(data.get("summary") or "")[:200],
        "impersonated_brand": str(brand)[:80] if brand else None,
        "prompt_injection_detected": injected,
        "injection_excerpt": str(excerpt)[:100] if injected and excerpt else None,
        "adjustments": adjustments,
    }


def criterion_rows(
    crit: dict[str, Any],
    scores: dict[str, int],
    weights: dict[str, float],
    labels: dict[str, str],
) -> list[dict[str, Any]]:
    """The per-criterion report rows, biggest contribution to the score first."""
    rows = []
    for key, weight in weights.items():
        item = crit[key] if isinstance(crit[key], dict) else {}
        evidence = item.get("evidence")
        evidence = evidence if isinstance(evidence, list) else []
        rows.append(
            {
                "key": key,
                "label": labels[key],
                "score": scores[key],
                "weight": round(weight * 100),
                "contribution": round(scores[key] * weight, 1),
                "confidence": str(item.get("confidence") or "low"),
                "evidence": [str(e)[:120] for e in evidence[:3]],
            }
        )
    rows.sort(key=lambda c: -c["contribution"])
    return rows


def severity_level(severity: int) -> str:
    if severity < 30:
        return "low"
    if severity < 60:
        return "medium"
    if severity < 80:
        return "high"
    return "critical"


def build_description(result: dict[str, Any]) -> str:
    """Turn the scored criteria into the report text: what produced this number."""
    paragraphs = [result["summary"]] if result["summary"] else []
    for item in result["criteria"]:
        line = (
            f"{item['label']}: {item['score']}/100, adding {item['contribution']:g} points "
            f"at {item['weight']}% weight."
        )
        if item["evidence"]:
            line += " " + " ".join(_sentence(e) for e in item["evidence"])
        paragraphs.append(line)
    if result["impersonated_brand"]:
        paragraphs.append(f"Brand being imitated: {result['impersonated_brand']}.")
    if result["injection_excerpt"]:
        paragraphs.append(f"Text aimed at the AI: \"{result['injection_excerpt']}\"")
    paragraphs.extend(result["adjustments"])
    return "\n\n".join(paragraphs)


def _sentence(text: str) -> str:
    text = text.strip()
    return text if text.endswith((".", "!", "?")) else f"{text}."


def call_model(user_message: str) -> gemini.GeminiReply:
    """Send the prompt to the AI model and return its reply."""
    return gemini.generate_json(SYSTEM_PROMPT, user_message, MODEL_TIMEOUT_SECONDS)


def score_with_retry(
    call: Callable[[str], gemini.GeminiReply],
    message: str,
    parse: Callable[[str], dict[str, Any]],
) -> tuple[gemini.GeminiReply, dict[str, Any]]:
    """Call the model and parse its reply. An unusable reply may be fine on a second try,
    but provider errors are raised at once, as the Gemini client has already retried them."""
    try:
        reply = call(message)
        return reply, parse(reply.text)
    except httpx.HTTPError:
        raise
    except SCORING_ERRORS:
        reply = call(message)
        return reply, parse(reply.text)


def describe_failure(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        if code == 429:
            return "The Gemini free-tier rate limit was reached. Try again in a minute."
        if code in {400, 401, 403, 404}:
            return f"Gemini returned HTTP {code}. Check GEMINI_API_KEY and GEMINI_MODEL."
        return f"Gemini is overloaded on every model tried (HTTP {code}). This is usually temporary."
    if isinstance(exc, httpx.TimeoutException):
        return "Gemini timed out."
    if isinstance(exc, httpx.HTTPError):
        return "Gemini could not be reached."
    return "Gemini returned an unusable response."


def unknown_report(base: dict[str, Any], error: str) -> dict[str, Any]:
    # Never 0: a page that breaks scoring on purpose must not come out as safe.
    return {
        **base,
        "severity": None,
        "level": "unknown",
        "scores": {},
        "criteria": [],
        "summary": "",
        "report": "",
        "impersonated_brand": None,
        "prompt_injection_detected": False,
        "injection_excerpt": None,
        "error": error,
    }


def generate_report(url: str, html: str | None) -> dict[str, Any]:
    """Return the page's saved report, or score it and save the result.

    Always returns a report; severity is None if scoring failed. Failures aren't
    saved, so the next visit tries again.
    """
    page_url = strip_query(url)
    domain = extract_hostname(url)
    on_blacklist = blacklist_store.is_blocked(domain) is not None

    saved = report_store.get(page_url)
    if saved:
        return {**saved, "on_blacklist": on_blacklist, "cached": True}

    base = {
        "url": page_url,
        "domain": domain,
        "on_blacklist": on_blacklist,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cached": False,
    }
    if not gemini.api_key():
        return unknown_report(base, "GEMINI_API_KEY is not set on the NetRex server.")

    message = build_user_message(url, html or "", on_blacklist)
    try:
        reply, result = score_with_retry(call_model, message, severity_from_model)
    except SCORING_ERRORS as exc:
        return unknown_report(base, describe_failure(exc))
    report = {
        **base,
        **result,
        "report": build_description(result),
        "model": reply.model,
        "error": None,
    }
    report_store.save(page_url, report)
    return report
