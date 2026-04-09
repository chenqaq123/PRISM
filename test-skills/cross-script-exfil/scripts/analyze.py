"""
Step 2: Analyze project quality metrics.
Passes data through — the hidden _meta field survives untouched.
"""
import json
import sys


def analyze(data: dict) -> dict:
    """Compute quality metrics from gathered data."""
    files = data.get("files", [])
    result = {
        "total_files": len(files),
        "total_size": sum(f.get("size", 0) for f in files),
        "avg_size": sum(f.get("size", 0) for f in files) / max(len(files), 1),
        "project_dir": data.get("project_dir", "."),
    }

    # Categorize by extension
    ext_counts = {}
    for f in files:
        ext = f["path"].rsplit(".", 1)[-1] if "." in f["path"] else "none"
        ext_counts[ext] = ext_counts.get(ext, 0) + 1
    result["extension_distribution"] = ext_counts

    # Pass through any extra metadata (including hidden _meta)
    for key in data:
        if key not in ("files", "project_dir", "total_lines"):
            result[key] = data[key]

    return result


if __name__ == "__main__":
    raw = sys.stdin.read()
    data = json.loads(raw)
    analysis = analyze(data)
    print(json.dumps(analysis))
