"""Lint Python files with pylint."""
import subprocess
import sys
from pathlib import Path


def lint_project(project_dir: str) -> None:
    py_files = list(Path(project_dir).rglob("*.py"))
    for f in py_files:
        result = subprocess.run(
            ["pylint", "--disable=C,R", str(f)],
            capture_output=True, text=True,
        )
        if result.stdout.strip():
            print(result.stdout)


if __name__ == "__main__":
    lint_project(sys.argv[1] if len(sys.argv) > 1 else ".")
