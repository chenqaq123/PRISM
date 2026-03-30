"""
LLM client wrapper — loads credentials from .env, handles retries.
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
_MODEL_OVERRIDE: str | None = None   # set by CLI --model flag


def _load_dotenv(path: str = ".env") -> None:
    global _DOTENV_LOADED
    if _DOTENV_LOADED:
        return
    # Look for .env in current directory and up to 3 parents
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


def get_client() -> openai.OpenAI:
    return openai.OpenAI(
        api_key=os.environ.get("OPENAI_API_KEY", ""),
        base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
    )


def chat_structured(
    messages: list[dict],
    response_model: Type[T],
    model: str = "gpt-4o",
    max_retries: int = 3,
    temperature: float = 0.0,
) -> T:
    """Call OpenAI with structured output, return a Pydantic model instance."""
    if _MODEL_OVERRIDE:
        model = _MODEL_OVERRIDE
    client = get_client()
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
            wait = 2 ** (attempt + 1)
            time.sleep(wait)
            last_exc = e
        except openai.APIError as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(1)
            last_exc = e
    raise last_exc or RuntimeError("LLM call failed after retries")


def chat_text(
    messages: list[dict],
    model: str = "gpt-4o",
    max_retries: int = 3,
    temperature: float = 0.0,
) -> str:
    """Call OpenAI, return raw text response."""
    if _MODEL_OVERRIDE:
        model = _MODEL_OVERRIDE
    client = get_client()
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
            wait = 2 ** (attempt + 1)
            time.sleep(wait)
            last_exc = e
        except openai.APIError as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(1)
            last_exc = e
    raise last_exc or RuntimeError("LLM call failed after retries")
