"""Google Gemini client. The only module that talks to the AI provider."""
from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass

import httpx

API_ROOT = "https://generativelanguage.googleapis.com/v1beta/models"
DEFAULT_MODEL = "gemini-3.8-flash"
# Other free-tier models to try when the main one is overloaded or out of quota.
DEFAULT_FALLBACK_MODELS = "gemini-3.6-flash,gemini-3.5-flash-lite"
ATTEMPTS_PER_MODEL = 2
MOVE_ON_STATUSES = {404, 429}


@dataclass(frozen=True)
class GeminiReply:
    text: str
    model: str


class GeminiReplyError(ValueError):
    """Gemini answered without usable text, for example because it blocked the prompt."""


def api_key() -> str:
    return os.getenv("GEMINI_API_KEY", "").strip()


def model_name() -> str:
    return os.getenv("GEMINI_MODEL", "").strip() or DEFAULT_MODEL


def models() -> list[str]:
    """The main model, then the fallbacks, without duplicates."""
    fallbacks = os.getenv("GEMINI_FALLBACK_MODELS", DEFAULT_FALLBACK_MODELS).split(",")
    return list(dict.fromkeys([model_name(), *(m.strip() for m in fallbacks if m.strip())]))


def _reply_text(payload: dict) -> str:
    candidates = payload.get("candidates") or []
    if not candidates:
        reason = (payload.get("promptFeedback") or {}).get("blockReason", "no candidates")
        raise GeminiReplyError(f"Gemini returned no reply: {reason}")
    parts = (candidates[0].get("content") or {}).get("parts") or []
    text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
    if not text.strip():
        raise GeminiReplyError(f"Gemini reply was empty: {candidates[0].get('finishReason')}")
    return text


def _post(model: str, system_prompt: str, user_message: str, timeout: float) -> str:
    response = httpx.post(
        f"{API_ROOT}/{model}:generateContent",
        # A header, not ?key=, so the key can't end up in logs or error messages.
        headers={"x-goog-api-key": api_key()},
        json={
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_message}]}],
            "generationConfig": {"responseMimeType": "application/json"},
        },
        timeout=timeout,
    )
    response.raise_for_status()
    return _reply_text(response.json())


def _backoff() -> None:
    # Jitter stops many clients retrying an overloaded model at the same moment.
    time.sleep(random.uniform(0.5, 1.5))


def generate_json(system_prompt: str, user_message: str, timeout: float) -> GeminiReply:
    """Ask Gemini for a JSON reply, moving to the next model if one is unavailable.

    Raises the first failure if every model fails. A bad key or request is raised
    straight away, because no other model would accept it either.
    """
    deadline = time.monotonic() + timeout * 2
    first_failure: httpx.HTTPError | None = None
    for model in models():
        for attempt in range(ATTEMPTS_PER_MODEL):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                text = _post(model, system_prompt, user_message, min(timeout, remaining))
                return GeminiReply(text, model)
            except httpx.HTTPStatusError as exc:
                code = exc.response.status_code
                if code not in MOVE_ON_STATUSES and code < 500:
                    raise
                first_failure = first_failure or exc
                # A short wait won't fix a used-up quota or a missing model.
                if code in MOVE_ON_STATUSES:
                    break
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                first_failure = first_failure or exc
            if attempt + 1 < ATTEMPTS_PER_MODEL:
                _backoff()
    if first_failure is None:
        raise httpx.TimeoutException("Gemini deadline passed before a request was sent")
    raise first_failure
