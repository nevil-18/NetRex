"""AI risk report for one pasted email. Parses the message itself, so authentication
results, link destinations and attachment types come from the server, not the email's
claims. The email's body is sent to the model but never saved."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from email import message_from_string, policy
from email.message import Message
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from . import ai_report, blacklist_store, gemini, report_store
from .ai_report import ModelOutputError, escape, strip_query
from .scanner import extract_hostname

WEIGHTS = {
    "sender_authenticity": 0.25,
    "link_risk": 0.25,
    "social_engineering": 0.20,
    "attachment_risk": 0.15,
    "ai_judgement": 0.15,
}
CRITERION_LABELS = {
    "sender_authenticity": "Sender authenticity",
    "link_risk": "Links",
    "social_engineering": "Manipulation",
    "attachment_risk": "Attachments",
    "ai_judgement": "Analyst judgement",
}
ATTACK_TYPE_LABELS = {
    "none": "No attack detected",
    "credential_phishing": "Credential phishing",
    "malware_delivery": "Malware delivery",
    "payment_fraud": "Payment fraud",
    "advance_fee_or_prize": "Prize or advance-fee scam",
    "callback_scam": "Callback scam",
    "extortion": "Extortion",
    "spam": "Spam",
    "other": "Other suspicious email",
}
SEVERITY_MEANINGS = {
    "low": "No meaningful sign of an attack.",
    "medium": "Suspicious. Confirm with the sender another way before acting.",
    "high": "Likely malicious. Do not click, open, reply or pay.",
    "critical": "A clear attack. Report it and delete it.",
    "unknown": "This email could not be scored. An unknown result is not a safe result.",
}
# Written here, not by the model, so an email can't talk the report into unsafe advice.
RECOMMENDED_ACTIONS = {
    "low": [
        "No action needed.",
        "Still check the address bar before entering a password or card number.",
    ],
    "medium": [
        "Don't use its links, attachments or phone numbers until you have checked it.",
        "Confirm with the sender using contact details you already trust.",
        "Reach any account by typing the site's address yourself.",
    ],
    "high": [
        "Don't click links, open attachments, reply or make a payment.",
        "Report it as phishing in your email app, or to your IT team at work.",
        "If it claims to be someone you know, warn them another way. Their account may be compromised.",
    ],
    "critical": [
        "Don't click links, open attachments, reply or make a payment.",
        "Report it as phishing in your email app, or to your IT team at work, then delete it.",
        "If you already entered a password, change it from the official site and turn on two-factor authentication.",
        "If you already paid or shared card details, contact your bank now.",
        "If you already opened an attachment, disconnect from the network and run a security scan.",
    ],
    "unknown": [
        "Treat this email with care until it has been scored.",
        "Don't use its links, attachments or phone numbers until you have checked it.",
    ],
}
DANGEROUS_EXTENSIONS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "msi", "dll", "cpl", "hta", "jar", "apk",
    "js", "jse", "vbs", "vbe", "wsf", "ps1", "lnk", "iso", "img", "vhd", "one",
    "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "html", "htm", "svg",
}
BLACKLIST_FLOORS = {"critical": 80, "high": 60, "medium": 30}
STRONG_SIGNAL_SCORE = 90
STRONG_SIGNAL_FLOOR = 70
INJECTION_FLOOR = 60
DANGEROUS_ATTACHMENT_FLOOR = 60

MAX_RAW_CHARS = 10_000_000
MAX_BODY_TEXT = 20_000
MAX_LINKS = 40
MAX_ATTACHMENTS = 20
MODEL_TIMEOUT_SECONDS = 45.0

_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.I)
_SHOWN_HOST_RE = re.compile(r"(?:https?://)?((?:[\w-]+\.)+[^\W\d_]{2,})(?:[/:?#]\S*)?", re.I)
_DOMAIN_RE = re.compile(r"[^\W_][\w-]*(?:\.[\w-]+)+")
_BIDI_CONTROLS_RE = re.compile("[‎‏‪-‮⁦-⁩]")
_AUTH_COMMENT_RE = re.compile(r"\([^()]*\)")


def _header(message: Message, name: str) -> str:
    try:
        value = message[name]
    except Exception:  # the stdlib's header parser can crash on hostile input
        return ""
    return " ".join(str(value or "").split())


def _address_domain(header: str) -> str:
    """The domain of a header's address, or "" unless it looks like a domain. Non-ASCII
    letters are kept so homoglyph domains stay visible to the model."""
    domain = parseaddr(header)[1].rpartition("@")[2].strip().lower()
    return domain if _DOMAIN_RE.fullmatch(domain) else ""


def _auth_results(message: Message) -> dict[str, str]:
    """Read SPF, DKIM and DMARC from the topmost Authentication-Results header. Receiving
    servers add theirs above existing headers, so a sender's forged copy sits lower down."""
    results = dict.fromkeys(("spf", "dkim", "dmarc"), "not_available")
    try:
        values = message.get_all("Authentication-Results") or []
    except Exception:
        values = []
    if not values:
        return results
    # Comments are removed because a sender can write "dkim=pass" inside one.
    text = _AUTH_COMMENT_RE.sub(" ", str(values[0]))
    for method in results:
        found = re.search(rf"\b{method}=([a-z]+)", text, re.I)
        if found:
            results[method] = found.group(1).lower()
    return results


def _part_text(part: Message) -> str:
    try:
        return str(part.get_content())
    except Exception:  # unknown charsets and broken encodings are common in spam
        payload = part.get_payload(decode=True)
        return payload.decode("utf-8", "replace") if isinstance(payload, bytes) else ""


def _link(href: str, text: str) -> dict[str, Any] | None:
    """Describe a link's real destination, or None for mailto, tel and in-page links."""
    href = href.strip()
    try:
        scheme = urlsplit(href).scheme.lower()
    except ValueError:
        scheme = ""
    if href.lower().startswith("www."):
        href, scheme = f"https://{href}", "https"
    if scheme not in {"http", "https"}:
        # javascript: and data: links are unusual enough for the model to see.
        if scheme in {"javascript", "data", "file", "vbscript"}:
            return {"href": f"{scheme}:", "host": "", "text": text[:120], "mismatched": False}
        return None
    host = extract_hostname(href)
    if not host:
        return None
    shown = _SHOWN_HOST_RE.fullmatch(text.strip())
    mismatched = bool(shown) and (
        blacklist_store.registered_domain(extract_hostname(shown.group(1)))
        != blacklist_store.registered_domain(host)
    )
    return {"href": strip_query(href), "host": host, "text": text[:120], "mismatched": mismatched}


def _is_dangerous(filename: str) -> bool:
    name = _BIDI_CONTROLS_RE.sub("", filename).strip(" .").lower()
    return "." in name and name.rsplit(".", 1)[1] in DANGEROUS_EXTENSIONS


def _html_parts(html: str) -> tuple[str, list[dict[str, Any] | None]]:
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()
    links = [_link(a["href"], a.get_text(" ", strip=True)) for a in soup.find_all("a", href=True)]
    return soup.get_text(" ", strip=True), links


def parse_email(raw: str) -> dict[str, Any]:
    """Reduce a pasted email, either full source or just the text, to what the report needs."""
    raw = raw.strip()
    message = message_from_string(raw, policy=policy.default)
    from_header = _header(message, "From")
    subject = _header(message, "Subject")
    headers_available = bool(from_header or subject)
    if not headers_available:
        message = message_from_string(f"\n{raw}", policy=policy.default)

    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict[str, Any]] = []
    links: list[dict[str, Any] | None] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        try:
            filename = part.get_filename()
        except Exception:
            filename = "unnamed"
        if filename or part.get_content_disposition() == "attachment":
            name = " ".join(str(filename or "unnamed").split())[:200]
            attachments.append(
                {"name": name, "content_type": content_type, "dangerous": _is_dangerous(name)}
            )
        elif content_type == "text/html":
            html_parts.append(_part_text(part))
        elif content_type == "text/plain":
            plain_parts.append(_part_text(part))

    for html in html_parts:
        text, html_links = _html_parts(html)
        links.extend(html_links)
        if not plain_parts:
            plain_parts.append(text)
    body_text = "\n".join(plain_parts)
    if not html_parts:
        links.extend(_link(url.rstrip(".,;:!?"), url) for url in _URL_RE.findall(body_text))

    unique_links: dict[tuple[str, str], dict[str, Any]] = {}
    for link in links:
        if link:
            unique_links.setdefault((link["href"], link["text"]), link)

    sender_domain = _address_domain(from_header)
    return {
        "headers_available": headers_available,
        "from_header": from_header,
        "reply_to_header": _header(message, "Reply-To"),
        "subject": subject,
        "sender_domain": sender_domain,
        "reply_to_domain": _address_domain(_header(message, "Reply-To")),
        "return_path_domain": _address_domain(_header(message, "Return-Path")),
        **_auth_results(message),
        "body_text": body_text,
        "links": list(unique_links.values()),
        "attachments": attachments,
    }


def _blacklist_hits(email: dict[str, Any]) -> list[dict[str, str]]:
    hosts = [email["sender_domain"], *(link["host"] for link in email["links"])]
    hits: dict[str, dict[str, str]] = {}
    for host in filter(None, hosts):
        entry = blacklist_store.is_blocked(host)
        if entry:
            hits[entry["domain"]] = {"domain": entry["domain"], "severity": entry.get("severity", "high")}
    return sorted(hits.values(), key=lambda hit: hit["domain"])


def build_user_message(email: dict[str, Any], hits: list[dict[str, str]]) -> str:
    links = email["links"]
    attachments = email["attachments"]
    values = {
        "headers_available": "true" if email["headers_available"] else "false",
        "sender_domain": email["sender_domain"] or "unknown",
        "reply_to_domain": email["reply_to_domain"] or "none",
        "return_path_domain": email["return_path_domain"] or "none",
        "spf": email["spf"],
        "dkim": email["dkim"],
        "dmarc": email["dmarc"],
        "link_count": str(len(links)),
        "mismatched_link_count": str(sum(link["mismatched"] for link in links)),
        "attachment_count": str(len(attachments)),
        "dangerous_attachment_count": str(sum(a["dangerous"] for a in attachments)),
        "blacklisted_domains": ", ".join(hit["domain"] for hit in hits) or "none",
        "from_header": escape(email["from_header"]),
        "reply_to_header": escape(email["reply_to_header"]),
        "subject": escape(email["subject"]),
        "body_text": escape(email["body_text"][:MAX_BODY_TEXT]),
        "links": escape(
            "\n".join(
                f"shown_text={link['text']!r} goes_to={link['href']}"
                f"{' MISMATCH' if link['mismatched'] else ''}"
                for link in links[:MAX_LINKS]
            )
        ),
        "attachments": escape(
            "\n".join(f"{a['name']} ({a['content_type']})" for a in attachments[:MAX_ATTACHMENTS])
        ),
    }
    return ai_report.fill_template(ai_report.EMAIL_USER_TEMPLATE, values)


def severity_from_model(raw: str, email: dict[str, Any], hits: list[dict[str, str]]) -> dict[str, Any]:
    """Validate the model's JSON, then compute the score and apply the server's floors."""
    active = dict(WEIGHTS)
    not_assessed = []
    if not email["links"]:
        del active["link_risk"]
        not_assessed.append("Links: this email has none.")
    if not email["attachments"]:
        del active["attachment_risk"]
        not_assessed.append("Attachments: this email has none.")
    # Without this, an attack with no links or files can't score above 60% of the scale.
    total = sum(active.values())
    weights = {key: weight / total for key, weight in active.items()}

    try:
        data = json.loads(raw)
        crit = data["criteria"]
        scores = {key: max(0, min(100, int(crit[key]["score"]))) for key in weights}
        brand = crit["sender_authenticity"].get("impersonated_brand")
    except (TypeError, ValueError, KeyError, OverflowError, AttributeError) as exc:
        raise ModelOutputError(f"Model output failed validation: {exc!r}") from exc

    severity = round(sum(scores[key] * weight for key, weight in weights.items()))
    adjustments: list[str] = []

    def raise_to(floor: int, reason: str) -> None:
        nonlocal severity
        if severity < floor:
            severity = floor
            adjustments.append(f"{reason} The score was raised to {floor}.")

    if max(scores.values()) >= STRONG_SIGNAL_SCORE:
        raise_to(STRONG_SIGNAL_FLOOR, f"One criterion scored {STRONG_SIGNAL_SCORE} or more.")
    injected = data.get("prompt_injection_detected") is True
    if injected:
        raise_to(INJECTION_FLOOR, "The email tried to instruct the AI.")
    if any(attachment["dangerous"] for attachment in email["attachments"]):
        raise_to(DANGEROUS_ATTACHMENT_FLOOR, "An attachment has a dangerous file type.")
    for hit in hits:
        floor = BLACKLIST_FLOORS.get(hit["severity"])
        if floor:
            raise_to(floor, f"{hit['domain']} is on the NetRex blacklist as {hit['severity']}.")

    level = ai_report.severity_level(severity)
    attack_type = data.get("attack_type")
    attack_type = attack_type if attack_type in ATTACK_TYPE_LABELS else "other"
    excerpt = data.get("injection_excerpt")
    return {
        "severity": severity,
        "level": level,
        "scores": scores,
        "criteria": ai_report.criterion_rows(crit, scores, weights, CRITERION_LABELS),
        "not_assessed": not_assessed,
        "summary": str(data.get("summary") or "")[:200],
        "attack_type": attack_type,
        "attack_type_label": ATTACK_TYPE_LABELS[attack_type],
        "severity_meaning": SEVERITY_MEANINGS[level],
        "recommended_actions": RECOMMENDED_ACTIONS[level],
        "impersonated_brand": str(brand)[:80] if brand else None,
        "prompt_injection_detected": injected,
        "injection_excerpt": str(excerpt)[:100] if injected and excerpt else None,
        "adjustments": adjustments,
    }


def call_model(user_message: str) -> gemini.GeminiReply:
    return gemini.generate_json(ai_report.EMAIL_SYSTEM_PROMPT, user_message, MODEL_TIMEOUT_SECONDS)


def generate_report(raw: str) -> dict[str, Any]:
    """Return the email's saved report, or score it and save the result.

    Always returns a report; severity is None if scoring failed. Failures aren't saved.
    """
    email = parse_email(raw)
    hits = _blacklist_hits(email)
    # The blacklist hits are part of the key, so a blacklist change means a fresh score
    # rather than a saved report that misses the new floor.
    fingerprint = "\0".join([raw.strip(), *(f"{h['domain']}={h['severity']}" for h in hits)])
    key = f"email:{hashlib.sha256(fingerprint.encode('utf-8', 'replace')).hexdigest()[:32]}"

    saved = report_store.get(key)
    if saved:
        return {**saved, "cached": True}

    attachments = email["attachments"][:MAX_ATTACHMENTS]
    base = {
        "kind": "email",
        "url": key,
        "domain": email["sender_domain"],
        "sender": email["from_header"][:200],
        "subject": email["subject"][:200],
        "headers_available": email["headers_available"],
        "authentication": {method: email[method] for method in ("spf", "dkim", "dmarc")},
        "reply_to_domain": email["reply_to_domain"],
        "link_count": len(email["links"]),
        "mismatched_links": [
            {"text": link["text"], "host": link["host"]}
            for link in email["links"]
            if link["mismatched"]
        ][:MAX_LINKS],
        "attachments": attachments,
        "blacklisted_domains": hits,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cached": False,
    }
    unknown_extras = {
        "not_assessed": [],
        "adjustments": [],
        "attack_type": None,
        "attack_type_label": None,
        "severity_meaning": SEVERITY_MEANINGS["unknown"],
        "recommended_actions": RECOMMENDED_ACTIONS["unknown"],
    }
    if not gemini.api_key():
        return ai_report.unknown_report(
            {**base, **unknown_extras}, "GEMINI_API_KEY is not set on the NetRex server."
        )

    message = build_user_message(email, hits)
    try:
        reply, result = ai_report.score_with_retry(
            call_model, message, lambda text: severity_from_model(text, email, hits)
        )
    except ai_report.SCORING_ERRORS as exc:
        return ai_report.unknown_report({**base, **unknown_extras}, ai_report.describe_failure(exc))
    report = {
        **base,
        **result,
        "report": ai_report.build_description(result),
        "model": reply.model,
        "error": None,
    }
    report_store.save(key, report)
    return report
