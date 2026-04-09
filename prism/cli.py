"""
PRISM Command-Line Interface
Usage:
    python -m prism.cli <skill_path> [options]
    python -m prism      <skill_path> [options]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="prism",
        description="PRISM — Pre-installation Risk Identification via Semantic-Structural Multimodal analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m prism.cli ./my_skill
  python -m prism.cli ./my_skill --json report.json
  python -m prism.cli ./my_skill --graph --quiet
  python -m prism.cli ./skills/ --batch --json results/
        """,
    )

    p.add_argument(
        "skill_path",
        type=str,
        help="Path to skill directory (must contain SKILL.md) or parent dir for --batch mode",
    )

    p.add_argument(
        "--json", "-j",
        metavar="OUTPUT",
        default=None,
        help="Save JSON report to OUTPUT path (or directory if --batch)",
    )

    p.add_argument(
        "--graph", "-g",
        action="store_true",
        default=False,
        help="Print HASG node/edge summary after scan",
    )

    p.add_argument(
        "--quiet", "-q",
        action="store_true",
        default=False,
        help="Suppress verbose pipeline logs (still prints final report)",
    )

    p.add_argument(
        "--no-report",
        action="store_true",
        default=False,
        help="Skip printing the detailed report (useful in batch mode)",
    )

    p.add_argument(
        "--batch", "-b",
        action="store_true",
        default=False,
        help="Scan all skill subdirectories under skill_path",
    )

    p.add_argument(
        "--threshold",
        type=float,
        default=None,
        metavar="P",
        help="Override BLOCK threshold (default: 0.90). Exit code 2 if any skill exceeds threshold.",
    )

    p.add_argument(
        "--model",
        type=str,
        default=None,
        metavar="MODEL_ID",
        help="Override LLM model for both phases (e.g. gpt-4o-mini)",
    )

    p.add_argument(
        "--viz", "-v",
        metavar="OUTPUT_HTML",
        nargs="?",
        const="hasg.html",
        default=None,
        help=(
            "Generate interactive HASG HTML visualization. "
            "Optionally specify output path (default: hasg.html). "
            "Opens in browser automatically."
        ),
    )

    p.add_argument(
        "--no-browser",
        action="store_true",
        default=False,
        help="With --viz: write HTML but do not open browser.",
    )

    p.add_argument(
        "--nl-only",
        action="store_true",
        default=False,
        help=(
            "Build and visualize only the NL graph from SKILL.md. "
            "Skips all code analysis and LLM judges. "
            "Prints instruction_units detail table for review."
        ),
    )

    # ── Two-phase deployment flags ────────────────────────────────────────────
    phase_group = p.add_mutually_exclusive_group()
    phase_group.add_argument(
        "--phase1-only",
        action="store_true",
        default=False,
        help=(
            "Cloud mode: run Phase 1 only (HASG + static analysis). "
            "Saves Phase1Result JSON to --json path. "
            "Uses PRISM_CLOUD_MODEL."
        ),
    )
    phase_group.add_argument(
        "--phase2",
        metavar="PHASE1_JSON",
        default=None,
        help=(
            "User mode: run Phase 2 judges on a saved Phase1Result JSON. "
            "skill_path must point to the locally downloaded skill directory. "
            "Uses PRISM_JUDGE_MODEL."
        ),
    )

    return p


def _set_model_override(model_override: str | None) -> None:
    if model_override:
        import prism.llm_client as _lc
        _lc._MODEL_OVERRIDE = model_override


def _scan_single(
    skill_path: Path,
    verbose: bool,
    print_report: bool,
    save_json_path: Path | None,
    print_graph: bool,
    model_override: str | None,
) -> "PRISMReport":  # type: ignore[name-defined]
    from .scanner import PRISMScanner
    from .report import print_report as _print_report, save_json

    _set_model_override(model_override)
    scanner = PRISMScanner(verbose=verbose)
    report = scanner.scan(skill_path)

    if print_report:
        _print_report(report)
    if print_graph:
        _print_graph_summary(skill_path)
    if save_json_path:
        save_json(report, save_json_path)

    return report


def _scan_phase1_only(
    skill_path: Path,
    verbose: bool,
    save_json_path: Path | None,
    print_graph: bool,
    model_override: str | None,
) -> None:
    """Cloud mode: Phase 1 only — save Phase1Result JSON."""
    from .scanner import PRISMScanner
    from .models import Phase1Result

    _set_model_override(model_override)
    scanner = PRISMScanner(verbose=verbose)
    p1 = scanner.scan_phase1(skill_path)

    if print_graph:
        _print_graph_summary(skill_path)

    if save_json_path:
        save_json_path.parent.mkdir(parents=True, exist_ok=True)
        save_json_path.write_text(p1.model_dump_json(indent=2), encoding="utf-8")
        print(f"\n  Phase1Result saved → {save_json_path}")
    else:
        # Print compact summary
        print(f"\n  fast_p={p1.fast_p:.3f}  "
              f"findings={len(p1.static_findings)}  "
              f"llm_calls={p1.llm_calls_phase1}")
        if p1.errors:
            for e in p1.errors:
                print(f"  ! {e}")


def _scan_phase2_from_json(
    phase1_json: Path,
    skill_path: Path,
    verbose: bool,
    print_rep: bool,
    save_json_path: Path | None,
    model_override: str | None,
) -> "PRISMReport":  # type: ignore[name-defined]
    """User mode: Phase 2 judges from saved Phase1Result JSON."""
    from .scanner import PRISMScanner
    from .models import Phase1Result
    from .report import print_report as _print_report, save_json

    if not phase1_json.exists():
        print(f"[PRISM] Phase1Result JSON not found: {phase1_json}", file=sys.stderr)
        sys.exit(1)

    _set_model_override(model_override)
    p1 = Phase1Result.model_validate_json(phase1_json.read_text(encoding="utf-8"))

    scanner = PRISMScanner(verbose=verbose)
    report  = scanner.scan_phase2(p1, skill_path)

    if print_rep:
        _print_report(report)
    if save_json_path:
        save_json(report, save_json_path)

    return report


def _print_graph_summary(skill_path: Path) -> None:
    """Print a detailed HASG summary using Rich (falls back to plain text)."""
    try:
        from .visualize import visualize
        visualize(skill_path, output_html=None, open_browser=False, terminal=True)
    except Exception as ex:
        print(f"  [graph] Could not build HASG for display: {ex}")


def _run_viz(skill_path: Path, viz_path: str, open_browser: bool) -> None:
    """Generate interactive HTML visualization of the HASG."""
    try:
        from .visualize import visualize
        out = Path(viz_path)
        visualize(skill_path, output_html=out, open_browser=open_browser, terminal=False)
    except Exception as ex:
        print(f"  [viz] Failed to generate HTML: {ex}")


def _batch_scan(
    root: Path,
    verbose: bool,
    print_report: bool,
    json_dir: Path | None,
    print_graph: bool,
    model_override: str | None,
    threshold: float | None,
) -> int:
    """Scan all skill subdirectories. Returns exit code."""
    from .report import save_json

    skill_dirs = sorted(
        d for d in root.iterdir()
        if d.is_dir() and (d / "SKILL.md").exists()
    )

    if not skill_dirs:
        print(f"[PRISM] No skill directories found under {root}", file=sys.stderr)
        return 1

    print(f"[PRISM] Batch scan: {len(skill_dirs)} skills under {root}\n")

    results = []
    for skill_dir in skill_dirs:
        print(f"{'─'*60}")
        print(f"  Scanning: {skill_dir.name}")
        print(f"{'─'*60}")

        json_path = None
        if json_dir:
            json_path = json_dir / f"{skill_dir.name}.json"

        try:
            report = _scan_single(
                skill_dir, verbose=verbose, print_report=print_report,
                save_json_path=json_path, print_graph=print_graph,
                model_override=model_override,
            )
            results.append((skill_dir.name, report))
        except Exception as e:
            print(f"  ERROR scanning {skill_dir.name}: {e}", file=sys.stderr)
            results.append((skill_dir.name, None))

    # Batch summary table
    print(f"\n{'═'*68}")
    print("  BATCH SCAN SUMMARY")
    print(f"{'═'*68}")
    _VERDICT_COLORS = {"BLOCK": "🔴", "REVIEW": "🟠", "WARN": "🟡", "PASS": "🟢"}
    block_count = 0
    for name, report in results:
        if report is None:
            print(f"  ⚪  ERROR   {name}")
            continue
        icon = _VERDICT_COLORS.get(report.verdict.value, "⚪")
        print(f"  {icon}  {report.verdict.value:<6}  p={report.p_malicious:.3f}  {name}")
        if report.verdict.value == "BLOCK":
            block_count += 1
        if threshold and report.p_malicious >= threshold:
            block_count += 1
    print(f"{'═'*68}")
    print(f"  Total: {len(results)}  |  BLOCK: {block_count}")
    print(f"{'═'*68}\n")

    return 2 if block_count > 0 else 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    skill_path = Path(args.skill_path).resolve()
    verbose = not args.quiet
    print_rep = not args.no_report

    # Model override: patch llm_client before any imports
    if args.model:
        try:
            import prism.llm_client as _lc
            _lc._MODEL_OVERRIDE = args.model
        except ImportError:
            pass

    # ── NL-only graph (debug / inspection mode) ───────────────────────────────
    if args.nl_only:
        if not skill_path.is_dir():
            print(f"[PRISM] skill_path must be a directory: {skill_path}", file=sys.stderr)
            return 1
        if not (skill_path / "SKILL.md").exists():
            print(f"[PRISM] SKILL.md not found in {skill_path}", file=sys.stderr)
            return 1
        from .visualize import visualize_nl
        html_path = Path(args.viz) if args.viz else None
        visualize_nl(
            skill_path=skill_path,
            output_html=html_path,
            open_browser=not args.no_browser,
            terminal=True,
        )
        return 0

    # ── Phase 1 only (cloud mode) ─────────────────────────────────────────────
    if args.phase1_only:
        if not skill_path.is_dir():
            print(f"[PRISM] skill_path must be a directory: {skill_path}", file=sys.stderr)
            return 1
        json_path = Path(args.json) if args.json else None
        _scan_phase1_only(
            skill_path=skill_path,
            verbose=verbose,
            save_json_path=json_path,
            print_graph=args.graph,
            model_override=args.model,
        )
        if args.viz:
            _run_viz(skill_path, args.viz, open_browser=not args.no_browser)
        return 0

    # ── Phase 2 only (user mode) ──────────────────────────────────────────────
    if args.phase2:
        phase1_json = Path(args.phase2)
        if not skill_path.is_dir():
            print(f"[PRISM] skill_path must point to the downloaded skill directory: {skill_path}",
                  file=sys.stderr)
            return 1
        json_path = Path(args.json) if args.json else None
        report = _scan_phase2_from_json(
            phase1_json=phase1_json,
            skill_path=skill_path,
            verbose=verbose,
            print_rep=print_rep,
            save_json_path=json_path,
            model_override=args.model,
        )
        verdict = report.verdict.value
        if verdict == "BLOCK":  return 2
        if verdict == "REVIEW": return 1
        return 0

    # ── Batch mode ────────────────────────────────────────────────────────────
    if args.batch:
        if not skill_path.is_dir():
            print(f"[PRISM] --batch requires a directory: {skill_path}", file=sys.stderr)
            return 1

        json_dir = None
        if args.json:
            json_dir = Path(args.json)
            json_dir.mkdir(parents=True, exist_ok=True)

        return _batch_scan(
            root=skill_path,
            verbose=verbose,
            print_report=print_rep,
            json_dir=json_dir,
            print_graph=args.graph,
            model_override=args.model,
            threshold=args.threshold,
        )

    # Single skill scan
    if not skill_path.is_dir():
        print(f"[PRISM] Not a directory: {skill_path}", file=sys.stderr)
        return 1

    if not (skill_path / "SKILL.md").exists():
        print(f"[PRISM] SKILL.md not found in {skill_path}", file=sys.stderr)
        return 1

    json_path = None
    if args.json:
        json_path = Path(args.json)

    try:
        report = _scan_single(
            skill_path=skill_path,
            verbose=verbose,
            print_report=print_rep,
            save_json_path=json_path,
            print_graph=args.graph,
            model_override=args.model,
        )
        if args.viz:
            _run_viz(skill_path, args.viz, open_browser=not args.no_browser)
    except FileNotFoundError as e:
        print(f"[PRISM] {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[PRISM] Scan failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

    # Exit code: 2 = BLOCK, 1 = REVIEW, 0 = WARN/PASS
    verdict = report.verdict.value
    if verdict == "BLOCK":
        return 2
    if verdict == "REVIEW":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
