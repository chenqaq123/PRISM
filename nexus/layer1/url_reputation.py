"""
Layer 1E: URL Reputation Check (VirusTotal)

Checks all external URLs discovered during Layer 0 code scanning against
the VirusTotal v3 API.  Injects CodeFinding objects for MALICIOUS and
SUSPICIOUS URLs so they flow naturally into the Layer 2 scoring pipeline.

Key design decisions:
  - Optional: silently skipped when no VT key is configured
  - Multi-key: uses VTKeyPool — rotates to the next key on HTTP 429
  - Rate-limit-aware: distinguishes per-minute vs per-day quota exhaustion
  - Trusted-domain bypass: well-known CDN / registry URLs are skipped
  - Error-resilient: a single failing URL does not abort the whole check
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from nexus.models import CodeFinding, CodeSignals, Severity, ThreatCategory
from nexus.url_detector_vt import VTError, VirusTotalURLScanner, VTURLScanResult
from nexus.vt_key_pool import VTKeyPool

# Maximum URLs to check per scan (prevents excessive API usage)
_MAX_URLS = 10

# Maximum attempts per URL (one per key in the pool, capped here)
_MAX_ATTEMPTS_PER_URL = 8

# Well-known infrastructure domains — low threat, skip to save quota
_TRUSTED_DOMAIN_FRAGMENTS = {
    "api.github.com",
    "github.com",
    "raw.githubusercontent.com",
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "cdn.jsdelivr.net",
    "storage.googleapis.com",
    "s3.amazonaws.com",
    "anthropic.com",
    "openai.com",
    "huggingface.co",
}


def _is_trusted(url: str) -> bool:
    url_lower = url.lower()
    return any(frag in url_lower for frag in _TRUSTED_DOMAIN_FRAGMENTS)


def _is_rate_limited_error(exc: VTError) -> bool:
    return "429" in str(exc)


def _is_daily_quota_error(exc: VTError) -> bool:
    msg = str(exc).lower()
    return "day" in msg or "daily" in msg or ("quota" in msg and "minute" not in msg)


# =============================================================================
# Result type
# =============================================================================

@dataclass
class URLReputationResult:
    """Aggregated result of the VT URL reputation check."""
    findings: list[CodeFinding] = field(default_factory=list)
    checked_urls: list[str] = field(default_factory=list)
    skipped_urls: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    pool_status: list[dict] = field(default_factory=list)  # key pool diagnostics

    @property
    def has_malicious(self) -> bool:
        return any(
            f.severity == Severity.CRITICAL and f.category == ThreatCategory.MALICIOUS_URL
            for f in self.findings
        )


# =============================================================================
# Main check function
# =============================================================================

def check_url_reputation(
    code_signals: CodeSignals,
    api_key: str | None = None,
    api_keys: list[str] | None = None,
    env_file: str | Path | None = None,
    wait_seconds: int = 60,
    poll_interval: float = 3.0,
    max_urls: int = _MAX_URLS,
) -> URLReputationResult:
    """
    Check external URLs in *code_signals* against VirusTotal.

    API key resolution (merged, deduplicated):
      1. *api_keys* list passed to this call
      2. *api_key* single key passed to this call
      3. ``VT_API_KEYS`` / ``VT_API_KEY`` environment variables
      4. ``VT_API_KEYS`` / ``VT_API_KEY`` from .env file

    Args:
        code_signals:   Layer 0 output; uses ``code_signals.external_urls``.
        api_key:        Single VT API key (optional, backward-compatible).
        api_keys:       List of VT API keys (optional).
        env_file:       Path to .env file (default: auto-detect).
        wait_seconds:   Max seconds to poll per-URL VT analysis.
        poll_interval:  Polling interval in seconds.
        max_urls:       Max number of URLs to submit per scan run.

    Returns:
        URLReputationResult whose ``.findings`` can be injected straight
        into ``code_signals.findings`` for downstream scoring.
    """
    result = URLReputationResult()

    # Build key pool
    extra: list[str] = list(api_keys or [])
    if api_key:
        extra.insert(0, api_key)
    pool = VTKeyPool.load(extra_keys=extra or None, env_file=env_file)

    if pool.is_empty:
        # No keys at all — silently skip (caller decides whether to log)
        return result

    # De-duplicate and filter URL candidates
    candidates: list[str] = []
    seen: set[str] = set()
    for url in code_signals.external_urls:
        if not url or url == "<dynamic>" or url in seen:
            continue
        seen.add(url)
        if _is_trusted(url):
            result.skipped_urls.append(url)
        else:
            candidates.append(url)
        if len(candidates) >= max_urls:
            break

    if not candidates:
        result.pool_status = pool.status()
        return result

    # Scan each URL, rotating keys on 429
    for url in candidates:
        _scan_url_with_pool(
            url=url,
            pool=pool,
            result=result,
            wait_seconds=wait_seconds,
            poll_interval=poll_interval,
        )
        # Stop early if all keys are exhausted
        if pool.all_exhausted():
            result.errors.append(
                "All VT API keys exhausted (rate-limited); "
                f"{len(candidates) - len(result.checked_urls) - len([u for u in candidates if u in result.errors])} URLs not checked."
            )
            break

    result.pool_status = pool.status()
    return result


def _scan_url_with_pool(
    url: str,
    pool: VTKeyPool,
    result: URLReputationResult,
    wait_seconds: int,
    poll_interval: float,
) -> None:
    """
    Try scanning *url* with the pool, rotating to the next key on 429.
    Updates *result* in-place.
    """
    max_attempts = min(_MAX_ATTEMPTS_PER_URL, pool.size)

    for attempt in range(max_attempts):
        key = pool.get_key()
        if key is None:
            result.errors.append(
                f"All VT keys rate-limited while checking {url}; skipped."
            )
            return

        try:
            scanner = VirusTotalURLScanner(api_key=key)
            vt: VTURLScanResult = scanner.scan_url(
                url=url,
                wait_seconds=wait_seconds,
                poll_interval=poll_interval,
            )
        except VTError as exc:
            if _is_rate_limited_error(exc):
                is_daily = _is_daily_quota_error(exc)
                pool.on_rate_limited(key, is_daily=is_daily)
                # Retry immediately with next key
                continue
            # Non-429 VT error (e.g. bad URL format, network issue)
            result.errors.append(f"VT error for {url}: {exc}")
            return
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"Unexpected error scanning {url}: {exc}")
            return

        # Success
        pool.on_success(key)
        result.checked_urls.append(url)
        finding = _vt_result_to_finding(url, vt)
        if finding is not None:
            result.findings.append(finding)
        return

    # Exhausted all attempts for this URL
    result.errors.append(
        f"Could not scan {url}: all {max_attempts} key attempt(s) hit rate limits."
    )


# =============================================================================
# VTURLScanResult → CodeFinding
# =============================================================================

def _vt_result_to_finding(url: str, vt: VTURLScanResult) -> CodeFinding | None:
    """Convert a VTURLScanResult into a CodeFinding, or None if clean/unknown."""
    if vt.risk_level == "MALICIOUS":
        total = max(vt.malicious + vt.harmless + vt.undetected, 5)
        confidence = round(min(1.0, vt.malicious / total), 3)
        return CodeFinding(
            severity=Severity.CRITICAL,
            category=ThreatCategory.MALICIOUS_URL,
            description=(
                f"VirusTotal: MALICIOUS URL — {url} "
                f"({vt.malicious} engines flagged malicious, "
                f"{vt.suspicious} suspicious)"
            ),
            evidence=vt.permalink,
            confidence=confidence,
        )

    if vt.risk_level == "SUSPICIOUS":
        total = max(vt.suspicious + vt.harmless + vt.undetected, 3)
        confidence = round(min(1.0, vt.suspicious / total), 3)
        return CodeFinding(
            severity=Severity.HIGH,
            category=ThreatCategory.MALICIOUS_URL,
            description=(
                f"VirusTotal: SUSPICIOUS URL — {url} "
                f"({vt.suspicious} engines flagged suspicious)"
            ),
            evidence=vt.permalink,
            confidence=confidence,
        )

    return None  # CLEAN or UNKNOWN — no finding
