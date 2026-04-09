"""
NEXUS CLI — Command-line interface

Usage:
  python -m nexus <skill_dir>                  # Scan with LLM
  python -m nexus <skill_dir> --no-llm         # Scan without LLM (heuristic only)
  python -m nexus <skill_dir> --json out.json   # Save JSON report
  python -m nexus <skill_dir> --model gpt-4o    # Override model
  python -m nexus --batch <dir>                # Scan all skills in a directory
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


def _print_report(report) -> None:
    """Pretty-print the NEXUS report to terminal."""
    from nexus.models import Severity, Verdict

    # Verdict with color
    colors = {
        Verdict.BLOCK: "\033[91m",   # red
        Verdict.REVIEW: "\033[93m",  # yellow
        Verdict.WARN: "\033[33m",    # orange
        Verdict.PASS: "\033[92m",    # green
    }
    reset = "\033[0m"
    color = colors.get(report.verdict, "")

    print()
    print("=" * 70)
    print(f"  NEXUS Report: {report.skill_name}")
    print("=" * 70)
    print(f"  Verdict:      {color}{report.verdict.value}{reset}")
    print(f"  Confidence:   {report.confidence:.2f}")
    print(f"  Overall Score:{report.overall_score:.3f}")
    print()

    # Component scores
    print("  Scores:")
    print(f"    Code Threat:          {report.code_threat_score:.3f}")
    print(f"    Contract Violations:  {report.contract_violation_score:.3f}")
    print(f"    Cross-Modal Taint:    {report.taint_score:.3f}")
    print(f"    NL Threats:           {report.nl_threat_score:.3f}")
    print()

    # Counts
    print("  Counts:")
    print(f"    Code findings:        {report.code_findings_count}")
    print(f"    Contract violations:  {report.contract_violations_count}")
    print(f"    Taint chains:         {report.taint_chains_count}")
    print(f"    Phantom scripts:      {len(report.phantom_scripts)}")
    print()

    # Evidence chains
    if report.evidence_chains:
        print("  Evidence Chains:")
        for i, ec in enumerate(report.evidence_chains, 1):
            sev_colors = {
                Severity.CRITICAL: "\033[91m",
                Severity.HIGH: "\033[93m",
                Severity.MEDIUM: "\033[33m",
                Severity.LOW: "\033[37m",
                Severity.INFO: "\033[90m",
            }
            sc = sev_colors.get(ec.severity, "")
            print(f"    {i}. {sc}[{ec.severity.value}]{reset} {ec.title}")
            print(f"       {ec.description[:100]}")
            if ec.taint_path:
                print(f"       Path: {' -> '.join(ec.taint_path)}")
            if ec.justification:
                print(f"       Why:  {ec.justification[:100]}")
            print()
    else:
        print("  No evidence chains found — skill appears benign.")
        print()

    # Phantom scripts
    if report.phantom_scripts:
        print(f"  Phantom Scripts (not in SKILL.md): {report.phantom_scripts}")
        print()

    # Capabilities
    if report.nl_declared_capabilities:
        print(f"  NL Declared: {report.nl_declared_capabilities}")
    if report.code_actual_capabilities:
        print(f"  Code Actual: {report.code_actual_capabilities}")
    print()

    # Metadata
    print(f"  Scan duration: {report.scan_duration_s:.2f}s")
    print(f"  LLM calls:     {report.llm_calls_made}")
    if report.errors:
        print(f"  Errors:        {report.errors}")
    print("=" * 70)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="nexus",
        description="NEXUS: NL-Executable Understanding for Skill Security",
    )
    parser.add_argument(
        "skill_dir",
        nargs="?",
        help="Path to the skill directory to scan",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Run without LLM calls (heuristic-only mode)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Override LLM model (e.g. gpt-4o, gpt-4o-mini)",
    )
    parser.add_argument(
        "--json",
        type=str,
        metavar="PATH",
        dest="json_path",
        help="Save JSON report to file",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Scan all subdirectories as individual skills",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Override BLOCK threshold (default 0.85)",
    )

    args = parser.parse_args(argv)

    if not args.skill_dir:
        parser.print_help()
        return 1

    skill_dir = Path(args.skill_dir).resolve()
    if not skill_dir.exists():
        print(f"Error: '{args.skill_dir}' does not exist", file=sys.stderr)
        return 1

    from nexus.scanner import scan_skill
    from nexus.models import Verdict

    if args.batch:
        # Batch mode: scan all subdirs
        if not skill_dir.is_dir():
            print(f"Error: '{args.skill_dir}' is not a directory", file=sys.stderr)
            return 1

        subdirs = sorted(
            d for d in skill_dir.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        )
        if not subdirs:
            print("No skill directories found.", file=sys.stderr)
            return 1

        print(f"Scanning {len(subdirs)} skills in {skill_dir}...\n")

        results = []
        for sd in subdirs:
            print(f"--- {sd.name} ---")
            try:
                report = scan_skill(
                    str(sd),
                    use_llm=not args.no_llm,
                    model=args.model,
                    quiet=args.quiet,
                )
                results.append(report)
                color = {Verdict.BLOCK: "\033[91m", Verdict.REVIEW: "\033[93m",
                         Verdict.WARN: "\033[33m", Verdict.PASS: "\033[92m"}.get(report.verdict, "")
                print(f"  Result: {color}{report.verdict.value}\033[0m "
                      f"(score={report.overall_score:.3f})\n")
            except Exception as e:
                print(f"  Error: {e}\n")

        # Summary table
        print("\n" + "=" * 60)
        print(f"{'Skill':<30} {'Verdict':<10} {'Score':<8} {'Evidence':<8}")
        print("-" * 60)
        for r in results:
            print(f"{r.skill_name:<30} {r.verdict.value:<10} {r.overall_score:<8.3f} {len(r.evidence_chains):<8}")
        print("=" * 60)

        if args.json_path:
            all_reports = [r.to_dict() for r in results]
            Path(args.json_path).write_text(
                json.dumps(all_reports, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            print(f"\nJSON reports saved to {args.json_path}")

        # Exit code based on worst verdict
        if any(r.verdict == Verdict.BLOCK for r in results):
            return 2
        if any(r.verdict == Verdict.REVIEW for r in results):
            return 1
        return 0

    else:
        # Single skill mode
        if not skill_dir.is_dir():
            print(f"Error: '{args.skill_dir}' is not a directory", file=sys.stderr)
            return 1

        report = scan_skill(
            str(skill_dir),
            use_llm=not args.no_llm,
            model=args.model,
            quiet=args.quiet,
        )

        _print_report(report)

        if args.json_path:
            Path(args.json_path).write_text(
                json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            print(f"JSON report saved to {args.json_path}")

        # Exit code
        if report.verdict == Verdict.BLOCK:
            return 2
        if report.verdict == Verdict.REVIEW:
            return 1
        return 0


if __name__ == "__main__":
    sys.exit(main())
