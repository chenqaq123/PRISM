"""
NEXUS LLM Client

Thin wrapper over OpenAI-compatible API with structured output support.
Loads config from .env, handles retries and model resolution.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Type, TypeVar

import openai
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)

_DOTENV_LOADED = False
_MODEL_OVERRIDE: str | None = None


def _load_dotenv() -> None:
    global _DOTENV_LOADED
    if _DOTENV_LOADED:
        return
    for candidate in [Path(".env"), Path(__file__).resolve().parent.parent / ".env"]:
        if candidate.exists():
            with open(candidate) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        os.environ.setdefault(k.strip(), v.strip())
            break
    _DOTENV_LOADED = True


_load_dotenv()

_DEFAULT_MODEL = os.environ.get("NEXUS_MODEL",
                 os.environ.get("PRISM_MODEL",
                 os.environ.get("PRISM_JUDGE_MODEL", "gpt-4o-mini")))


def set_model_override(model: str | None) -> None:
    global _MODEL_OVERRIDE
    _MODEL_OVERRIDE = model


def _get_client() -> openai.OpenAI:
    return openai.OpenAI(
        api_key=os.environ.get("OPENAI_API_KEY", ""),
        base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
    )


def _ensure_json_hint(messages: list[dict]) -> list[dict]:
    """Ensure 'json' appears in messages for Qwen compatibility."""
    all_content = " ".join(str(m.get("content", "")) for m in messages).lower()
    if "json" not in all_content:
        messages = list(messages)
        messages[-1] = {
            **messages[-1],
            "content": messages[-1]["content"] + "\n\nRespond in JSON format.",
        }
    return messages


def chat_structured(
    messages: list[dict],
    response_model: Type[T],
    max_retries: int = 3,
    temperature: float = 0.0,
) -> T:
    """
    Call LLM with structured output (Pydantic schema).
    Uses OpenAI beta.chat.completions.parse for guaranteed schema compliance.
    """
    model = _MODEL_OVERRIDE or _DEFAULT_MODEL
    client = _get_client()
    messages = _ensure_json_hint(messages)

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
        except openai.RateLimitError:
            time.sleep(2 ** (attempt + 1))
        except openai.APIError as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(1)
            last_exc = e
    raise last_exc or RuntimeError("LLM call failed after retries")


def chat_text(
    messages: list[dict],
    max_retries: int = 3,
    temperature: float = 0.0,
) -> str:
    """Plain text LLM call."""
    model = _MODEL_OVERRIDE or _DEFAULT_MODEL
    client = _get_client()

    last_exc: Exception | None = None
    for attempt in range(max_retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
            )
            return resp.choices[0].message.content or ""
        except openai.RateLimitError:
            time.sleep(2 ** (attempt + 1))
        except openai.APIError as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(1)
            last_exc = e
    raise last_exc or RuntimeError("LLM call failed after retries")
