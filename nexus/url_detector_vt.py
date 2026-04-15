"""
Standalone VirusTotal URL detector (API v3).

This module is intentionally independent from the NEXUS pipeline and can be
used directly for quick URL reputation checks.

Usage examples:
  python -m nexus.url_detector_vt https://example.com
  python -m nexus.url_detector_vt https://example.com --json
  VT_API_KEY=xxx python -m nexus.url_detector_vt https://example.com --wait-seconds 90
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib import error, parse, request


DEFAULT_VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VTError(RuntimeError):
    """VirusTotal request/response error."""


@dataclass
class VTURLScanResult:
    """Normalized scan result from VirusTotal URL APIs."""

    url: str
    vt_url_id: str
    analysis_id: str
    analysis_status: str
    risk_level: str

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    timeout: int = 0

    reputation: int | None = None
    last_analysis_date: str = ""
    categories: dict[str, str] = field(default_factory=dict)
    permalink: str = ""

    raw_stats: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class VirusTotalURLScanner:
    """Small client for VT URL scan endpoints."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = DEFAULT_VT_BASE_URL,
        timeout_s: int = 20,
    ) -> None:
        self.api_key = api_key or os.environ.get("VT_API_KEY", "").strip()
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        if not self.api_key:
            raise VTError("Missing VT API key. Set VT_API_KEY or pass --api-key.")

    @staticmethod
    def url_to_vt_id(url: str) -> str:
        """VT URL IDs are URL-safe base64 without '=' padding."""
        raw = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
        return raw.rstrip("=")

    def _headers(self) -> dict[str, str]:
        return {
            "x-apikey": self.api_key,
            "accept": "application/json",
        }

    def _request_json(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        content_type: str | None = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        headers = self._headers()
        if content_type:
            headers["content-type"] = content_type
        req = request.Request(url=url, method=method.upper(), data=body, headers=headers)
        try:
            with request.urlopen(req, timeout=self.timeout_s) as resp:
                payload = resp.read()
        except error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            raise VTError(f"HTTP {e.code} from VirusTotal: {raw[:300]}") from e
        except error.URLError as e:
            raise VTError(f"Network error calling VirusTotal: {e}") from e

        try:
            parsed = json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError as e:
            raise VTError("VirusTotal returned non-JSON response.") from e
        if not isinstance(parsed, dict):
            raise VTError("Unexpected VirusTotal response format.")
        return parsed

    def submit_url(self, url: str) -> str:
        """
        Submit URL for scanning.
        Returns analysis_id (used for /analyses/{id} polling).
        """
        form = parse.urlencode({"url": url}).encode("utf-8")
        data = self._request_json(
            method="POST",
            path="/urls",
            body=form,
            content_type="application/x-www-form-urlencoded",
        )
        analysis_id = ((data.get("data") or {}).get("id") or "").strip()
        if not analysis_id:
            raise VTError("submit_url succeeded but analysis id is missing.")
        return analysis_id

    def get_analysis(self, analysis_id: str) -> dict[str, Any]:
        """Get analysis status/details."""
        return self._request_json("GET", f"/analyses/{parse.quote(analysis_id, safe='')}")

    def wait_for_analysis(
        self,
        analysis_id: str,
        wait_seconds: int = 60,
        poll_interval: float = 3.0,
    ) -> str:
        """
        Poll analysis status until completed or timeout.
        Returns final status (e.g., 'completed', 'queued').
        """
        deadline = time.time() + max(wait_seconds, 1)
        status = "unknown"
        while time.time() < deadline:
            data = self.get_analysis(analysis_id)
            attrs = (data.get("data") or {}).get("attributes") or {}
            status = str(attrs.get("status", "unknown")).lower()
            if status == "completed":
                return status
            time.sleep(max(poll_interval, 0.3))
        return status

    def get_url_report(self, url: str) -> dict[str, Any]:
        """Fetch URL report by URL identifier."""
        vt_id = self.url_to_vt_id(url)
        return self._request_json("GET", f"/urls/{parse.quote(vt_id, safe='')}")

    def scan_url(
        self,
        url: str,
        wait_seconds: int = 60,
        poll_interval: float = 3.0,
    ) -> VTURLScanResult:
        """
        End-to-end scan:
          1) submit URL
          2) poll analysis until completed/timeout
          3) fetch URL report
        """
        analysis_id = self.submit_url(url)
        analysis_status = self.wait_for_analysis(
            analysis_id=analysis_id,
            wait_seconds=wait_seconds,
            poll_interval=poll_interval,
        )
        report = self.get_url_report(url)
        return self._normalize_result(url, analysis_id, analysis_status, report)

    def _normalize_result(
        self,
        url: str,
        analysis_id: str,
        analysis_status: str,
        report: dict[str, Any],
    ) -> VTURLScanResult:
        data = report.get("data") or {}
        vt_url_id = str(data.get("id", "")) or self.url_to_vt_id(url)
        attrs = data.get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}

        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        timeout = int(stats.get("timeout", 0) or 0)

        if malicious > 0:
            risk = "MALICIOUS"
        elif suspicious > 0:
            risk = "SUSPICIOUS"
        elif harmless > 0:
            risk = "CLEAN"
        else:
            risk = "UNKNOWN"

        last_ts = attrs.get("last_analysis_date")
        last_iso = ""
        if isinstance(last_ts, int):
            last_iso = datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat()

        permalink = f"https://www.virustotal.com/gui/url/{vt_url_id}"
        categories = attrs.get("categories")
        if not isinstance(categories, dict):
            categories = {}

        reputation = attrs.get("reputation")
        if not isinstance(reputation, int):
            reputation = None

        return VTURLScanResult(
            url=url,
            vt_url_id=vt_url_id,
            analysis_id=analysis_id,
            analysis_status=analysis_status,
            risk_level=risk,
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            undetected=undetected,
            timeout=timeout,
            reputation=reputation,
            last_analysis_date=last_iso,
            categories={str(k): str(v) for k, v in categories.items()},
            permalink=permalink,
            raw_stats={str(k): int(v) for k, v in stats.items() if isinstance(v, int)},
        )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m nexus.url_detector_vt",
        description="Standalone VirusTotal URL detector (API v3).",
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument(
        "--api-key",
        default=None,
        help="VirusTotal API key (fallback: VT_API_KEY env var)",
    )
    parser.add_argument(
        "--wait-seconds",
        type=int,
        default=60,
        help="Maximum seconds to wait for analysis completion",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=3.0,
        help="Polling interval in seconds",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print full JSON result",
    )
    return parser.parse_args(argv)


def _print_human(result: VTURLScanResult) -> None:
    print("=" * 70)
    print("VirusTotal URL Scan Result")
    print("=" * 70)
    print(f"URL:              {result.url}")
    print(f"Risk Level:       {result.risk_level}")
    print(f"Analysis Status:  {result.analysis_status}")
    print(
        "Detections:       "
        f"malicious={result.malicious}, suspicious={result.suspicious}, "
        f"harmless={result.harmless}, undetected={result.undetected}, timeout={result.timeout}"
    )
    if result.reputation is not None:
        print(f"Reputation:       {result.reputation}")
    if result.categories:
        print(f"Categories:       {result.categories}")
    if result.last_analysis_date:
        print(f"Last Analysis:    {result.last_analysis_date}")
    print(f"VT URL ID:        {result.vt_url_id}")
    print(f"Analysis ID:      {result.analysis_id}")
    print(f"Permalink:        {result.permalink}")
    print("=" * 70)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        scanner = VirusTotalURLScanner(api_key=args.api_key)
        result = scanner.scan_url(
            url=args.url,
            wait_seconds=args.wait_seconds,
            poll_interval=args.poll_interval,
        )
    except VTError as e:
        print(f"[VT-ERROR] {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[ERROR] Unexpected failure: {e}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        _print_human(result)

    if result.risk_level == "MALICIOUS":
        return 2
    if result.risk_level == "SUSPICIOUS":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
