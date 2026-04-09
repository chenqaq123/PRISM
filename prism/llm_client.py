"""
LLM client wrapper — loads credentials from .env, handles retries.

Two independent client roles:
  cloud  — Phase 1 HASG construction. Cost-sensitive; configured via PRISM_CLOUD_MODEL.
  judge  — Phase 2 LLM judges.  Quality-sensitive; configured via PRISM_JUDGE_MODEL.

Priority for each role:
  CLI --model flag  >  role-specific env var  >  PRISM_MODEL fallback  >  "gpt-4o-mini"
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Type, TypeVar

import openai
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)

_DOTENV_LOADED = False
_MODEL_OVERRIDE: str | None = None   # set by CLI --model flag (overrides both roles)


def _load_dotenv(path: str = ".env") -> None:
    global _DOTENV_LOADED
    if _DOTENV_LOADED:
        return
    candidates = [Path(path)]
    for parent in Path(path).resolve().parents[:3]:
        candidates.append(parent / ".env")
    for p in candidates:
        if p.exists():
            with open(p) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip())
            break
    _DOTENV_LOADED = True


_load_dotenv()

# ── Model resolution ──────────────────────────────────────────────────────────
# Fallback chain: role-specific var → PRISM_MODEL → "gpt-4o-mini"
_FALLBACK_MODEL:  str = os.environ.get("PRISM_MODEL", "gpt-4o-mini")
_CLOUD_MODEL:     str = os.environ.get("PRISM_CLOUD_MODEL", _FALLBACK_MODEL)
_JUDGE_MODEL:     str = os.environ.get("PRISM_JUDGE_MODEL", _FALLBACK_MODEL)


# ── OpenAI client factory ─────────────────────────────────────────────────────

def get_client() -> openai.OpenAI:
    """Default client (uses OPENAI_* env vars)."""
    return openai.OpenAI(
        api_key=os.environ.get("OPENAI_API_KEY", ""),
        base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
    )


def _get_cloud_client() -> openai.OpenAI:
    return openai.OpenAI(
        api_key=os.environ.get("PRISM_CLOUD_API_KEY",
                 os.environ.get("OPENAI_API_KEY", "")),
        base_url=os.environ.get("PRISM_CLOUD_BASE_URL",
                  os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")),
    )


def _get_judge_client() -> openai.OpenAI:
    return openai.OpenAI(
        api_key=os.environ.get("PRISM_JUDGE_API_KEY",
                 os.environ.get("OPENAI_API_KEY", "")),
        base_url=os.environ.get("PRISM_JUDGE_BASE_URL",
                  os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")),
    )


# ── JSON compat helper ────────────────────────────────────────────────────────

def _ensure_json_word(messages: list[dict]) -> list[dict]:
    """
    Qwen API requires the word "json" to appear somewhere in messages when
    response_format is used. Inject a harmless hint if absent.
    """
    all_content = " ".join(str(m.get("content", "")) for m in messages).lower()
    if "json" not in all_content:
        messages = list(messages)
        messages[-1] = {
            **messages[-1],
            "content": messages[-1]["content"] + "\n\nRespond in JSON format.",
        }
    return messages


# ── Core call helpers ─────────────────────────────────────────────────────────

def _do_structured(
    client: openai.OpenAI,
    model: str,
    messages: list[dict],
    response_model: Type[T],
    max_retries: int,
    temperature: float,
) -> T:
    messages = _ensure_json_word(messages)
    last_exc: Exception | None = None
    for attempt in range(max_retries):
        try:
            resp = client.beta.chat.completions.parse(
                model=model,
                messages=messages,
                response_format=response_model,
                temperature=temperature,
            )
            return resp.choices[0].message.parsed
        except openai.RateLimitError as e:
            time.sleep(2 ** (attempt + 1))
            last_exc = e
        except openai.APIError as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(1)
            last_exc = e
    raise last_exc or RuntimeError("LLM call failed after retries")


def _do_text(
    client: openai.OpenAI,
    model: str,
    messages: list[dict],
    max_retries: int,
    temperature: float,
) -> str:
    last_exc: Exception | None = None
    for attempt in range(max_retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
            )
            return resp.choices[0].message.content or ""
        except openai.RateLimitError as e:
            time.sleep(2 ** (attempt + 1))
            last_exc = e
        except openai.APIError as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(1)
            last_exc = e
    raise last_exc or RuntimeError("LLM call failed after retries")


# ── Public API ────────────────────────────────────────────────────────────────

def chat_structured_cloud(
    messages: list[dict],
    response_model: Type[T],
    max_retries: int = 3,
    temperature: float = 0.0,
) -> T:
    """Phase 1 structured call — uses PRISM_CLOUD_MODEL (cost-optimised)."""
    model = _MODEL_OVERRIDE or _CLOUD_MODEL
    return _do_structured(_get_cloud_client(), model, messages, response_model,
                          max_retries, temperature)


def chat_structured_judge(
    messages: list[dict],
    response_model: Type[T],
    max_retries: int = 3,
    temperature: float = 0.0,
) -> T:
    """Phase 2 structured call — uses PRISM_JUDGE_MODEL (quality-optimised)."""
    model = _MODEL_OVERRIDE or _JUDGE_MODEL
    return _do_structured(_get_judge_client(), model, messages, response_model,
                          max_retries, temperature)


def chat_structured(
    messages: list[dict],
    response_model: Type[T],
    model: str | None = None,
    max_retries: int = 3,
    temperature: float = 0.0,
) -> T:
    """Generic structured call — uses PRISM_JUDGE_MODEL unless model is explicit."""
    resolved = _MODEL_OVERRIDE or model or _JUDGE_MODEL
    return _do_structured(_get_judge_client(), resolved, messages, response_model,
                          max_retries, temperature)


def chat_text(
    messages: list[dict],
    model: str | None = None,
    max_retries: int = 3,
    temperature: float = 0.0,
) -> str:
    """Generic text call — uses PRISM_JUDGE_MODEL unless model is explicit."""
    resolved = _MODEL_OVERRIDE or model or _JUDGE_MODEL
    return _do_text(_get_judge_client(), resolved, messages, max_retries, temperature)
