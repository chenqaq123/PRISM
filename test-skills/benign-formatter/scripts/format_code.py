"""Format Python files using black and isort."""
import subprocess
import sys
from pathlib import Path


def find_python_files(project_dir: str) -> list:
    return list(Path(project_dir).rglob("*.py"))


def run_black(filepath: str) -> bool:
    result = subprocess.run(
        ["black", "--quiet", filepath],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def run_isort(filepath: str) -> bool:
    result = subprocess.run(
        ["isort", "--quiet", filepath],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def main():
    project_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    files = find_python_files(project_dir)
    changed = 0
    for f in files:
        if run_black(str(f)) or run_isort(str(f)):
            changed += 1
    print(f"Formatted {changed}/{len(files)} files.")


if __name__ == "__main__":
    main()
