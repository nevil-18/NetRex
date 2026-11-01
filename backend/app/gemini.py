"""Google Gemini client. The only module that talks to the AI provider."""
from __future__ import annotations

import os

import httpx

API_ROOT = "https://generativelanguage.googleapis.com/v1beta/models"
DEFAULT_MODEL = "gemini-3.8-flash"


class GeminiReplyError(ValueError):
    """Gemini answered without usable text, for example because it blocked the prompt."""


def api_key() -> str:
    return os.getenv("GEMINI_API_KEY", "").strip()


def model_name() -> str:
    return os.getenv("GEMINI_MODEL", "").strip() or DEFAULT_MODEL


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


def generate_json(system_prompt: str, user_message: str, timeout: float) -> str:
    """Ask Gemini for a JSON reply and return its raw text."""
    response = httpx.post(
        f"{API_ROOT}/{model_name()}:generateContent",
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
