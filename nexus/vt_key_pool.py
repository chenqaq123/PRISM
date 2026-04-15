"""
VTKeyPool — Multi-key, rate-limit-aware VirusTotal API key manager.

Reads keys from .env / environment variables:
  VT_API_KEYS=key1,key2,key3    # preferred — comma-separated list
  VT_API_KEY=key1               # single key, backward-compatible

Both variables are merged (deduped, order preserved).

Rate-limit handling:
  - HTTP 429 per-minute  → cool key down for ~65 s, try next key immediately
  - HTTP 429 per-day     → park key for 24 h, try next key immediately
  - All keys blocked     → caller receives None from get_key()

Free-tier limits tracked per key:
  - 4 requests / minute
  - 500 requests / day
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path

# VirusTotal free-tier limits (used for proactive capacity estimation)
_MINUTE_LIMIT = 4
_DAY_LIMIT = 500

# Backoff durations after a 429 response
_MINUTE_BACKOFF_S = 65      # slightly longer than 60 s to clear the window
_DAY_BACKOFF_S = 86_400     # 24 h


# =============================================================================
# Per-key state
# =============================================================================

@dataclass
class _KeyState:
    key: str
    minute_requests: int = 0
    minute_window_start: float = field(default_factory=time.monotonic)
    day_requests: int = 0
    day_window_start: float = field(default_factory=time.monotonic)
    blocked_until: float = 0.0           # per-minute cooldown
    daily_exhausted_until: float = 0.0   # per-day park

    # ------------------------------------------------------------------
    # Internal window management
    # ------------------------------------------------------------------

    def _tick_minute(self) -> None:
        if time.monotonic() - self.minute_window_start >= 60.0:
            self.minute_requests = 0
            self.minute_window_start = time.monotonic()

    def _tick_day(self) -> None:
        if time.monotonic() - self.day_window_start >= _DAY_BACKOFF_S:
            self.day_requests = 0
            self.day_window_start = time.monotonic()
            self.daily_exhausted_until = 0.0

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @property
    def is_blocked(self) -> bool:
        now = time.monotonic()
        return self.daily_exhausted_until > now or self.blocked_until > now

    @property
    def minute_remaining(self) -> int:
        self._tick_minute()
        return max(0, _MINUTE_LIMIT - self.minute_requests)

    @property
    def day_remaining(self) -> int:
        self._tick_day()
        return max(0, _DAY_LIMIT - self.day_requests)

    def record_request(self) -> None:
        self._tick_minute()
        self._tick_day()
        self.minute_requests += 1
        self.day_requests += 1

    def apply_minute_backoff(self) -> None:
        self.blocked_until = time.monotonic() + _MINUTE_BACKOFF_S
        self.minute_requests = _MINUTE_LIMIT  # saturate so capacity sorts low

    def apply_day_backoff(self) -> None:
        self.daily_exhausted_until = time.monotonic() + _DAY_BACKOFF_S

    def seconds_until_available(self) -> float:
        now = time.monotonic()
        return max(0.0, max(self.blocked_until, self.daily_exhausted_until) - now)


# =============================================================================
# Key pool
# =============================================================================

class VTKeyPool:
    """
    Pool of VirusTotal API keys with automatic rate-limit rotation.

    Usage::

        pool = VTKeyPool.load()           # reads from .env / env vars
        key = pool.get_key()
        if key is None:
            raise RuntimeError("All VT keys exhausted")
        try:
            result = scanner_using(key)
            pool.on_success(key)
        except RateLimitError:
            pool.on_rate_limited(key, is_daily=False)
    """

    def __init__(self, keys: list[str]) -> None:
        seen: set[str] = set()
        self._states: list[_KeyState] = []
        for k in keys:
            k = k.strip()
            if k and k not in seen:
                seen.add(k)
                self._states.append(_KeyState(key=k))

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def load(
        cls,
        extra_keys: list[str] | None = None,
        env_file: str | Path | None = None,
    ) -> VTKeyPool:
        """
        Build pool from (merged in this priority order):
          1. *extra_keys* passed directly to this call
          2. ``VT_API_KEYS`` environment variable  (comma-separated)
          3. ``VT_API_KEY`` environment variable   (single)
          4. Same variables from the .env file

        Environment variables always override the .env file.
        All sources are merged; duplicates are removed (first occurrence wins).
        """
        import os
        env_vars = _read_env_file(env_file)

        keys: list[str] = list(extra_keys or [])

        for var in ("VT_API_KEYS", "VT_API_KEY"):
            value = os.environ.get(var, "").strip() or env_vars.get(var, "").strip()
            if value:
                keys.extend(k.strip() for k in value.split(",") if k.strip())

        # Deduplicate while preserving insertion order
        seen: set[str] = set()
        unique = [k for k in keys if k and not (k in seen or seen.add(k))]  # type: ignore[func-returns-value]

        return cls(unique)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def size(self) -> int:
        return len(self._states)

    @property
    def is_empty(self) -> bool:
        return not self._states

    def all_exhausted(self) -> bool:
        """True when every key is currently in a cooldown/daily-park state."""
        return bool(self._states) and all(s.is_blocked for s in self._states)

    # ------------------------------------------------------------------
    # Key selection
    # ------------------------------------------------------------------

    def get_key(self) -> str | None:
        """
        Return the best available key, or ``None`` if every key is blocked.

        Selection criterion: most remaining per-minute capacity.
        """
        available = [s for s in self._states if not s.is_blocked]
        if not available:
            return None
        return max(available, key=lambda s: (s.minute_remaining, s.day_remaining)).key

    def soonest_available_in(self) -> float:
        """Seconds until the first blocked key becomes available again."""
        if not self._states:
            return 0.0
        return min(s.seconds_until_available() for s in self._states)

    # ------------------------------------------------------------------
    # Feedback
    # ------------------------------------------------------------------

    def on_success(self, key: str) -> None:
        """Record a successful (non-429) VT request for *key*."""
        state = self._find(key)
        if state:
            state.record_request()

    def on_rate_limited(self, key: str, *, is_daily: bool = False) -> None:
        """
        React to a 429 response for *key*.

        *is_daily=True*  → park key for 24 h.
        *is_daily=False* → cool key down for ~65 s (per-minute window).
        """
        state = self._find(key)
        if not state:
            return
        if is_daily:
            state.apply_day_backoff()
        else:
            state.apply_minute_backoff()

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def status(self) -> list[dict]:
        """
        Return a human-readable status list (API keys are masked).

        Example entry::

            {"key": "abcd12...ef56", "status": "ok (min_rem=3, day_rem=498)"}
        """
        rows = []
        for s in self._states:
            masked = s.key[:6] + "..." + s.key[-4:] if len(s.key) > 10 else "***"
            now = time.monotonic()
            if s.daily_exhausted_until > now:
                wait = int(s.daily_exhausted_until - now)
                status = f"daily_parked ({wait}s remaining)"
            elif s.blocked_until > now:
                wait = int(s.blocked_until - now)
                status = f"minute_cooldown ({wait}s remaining)"
            else:
                status = f"ok (min_rem={s.minute_remaining}, day_rem={s.day_remaining})"
            rows.append({"key": masked, "status": status})
        return rows

    def _find(self, key: str) -> _KeyState | None:
        for s in self._states:
            if s.key == key:
                return s
        return None


# =============================================================================
# .env parser  (no third-party dependency)
# =============================================================================

# Matches:  KEY=value  KEY='value'  KEY="value"  (optional inline comment)
_ENV_LINE_RE = re.compile(
    r"""^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['"]?)(.*?)\2\s*(?:#.*)?$"""
)


def _read_env_file(env_file: str | Path | None = None) -> dict[str, str]:
    """
    Parse a .env file and return ``{KEY: value}`` pairs.

    When *env_file* is ``None``, tries (in order):
      1. ``{cwd}/.env``
      2. ``{project_root}/.env``  — parent directory of the ``nexus/`` package
    """
    candidates: list[Path] = []
    if env_file is not None:
        candidates.append(Path(env_file))
    else:
        candidates.append(Path.cwd() / ".env")
        project_root = Path(__file__).parent.parent  # nexus/ → project root
        root_env = project_root / ".env"
        if root_env not in candidates:
            candidates.append(root_env)

    for path in candidates:
        if path.is_file():
            return _parse_dotenv(path)
    return {}


def _parse_dotenv(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return result
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _ENV_LINE_RE.match(line)
        if m:
            result[m.group(1)] = m.group(3)
    return result
