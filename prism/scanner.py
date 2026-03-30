"""
PRISM Scanner — main orchestrator.
Runs the full two-phase four-module pipeline.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from .hasg_builder import build_hasg
from .m1_nl_threat import analyze_nl_threats
from .m2_code_threat import analyze_code_threats
from .m3_cmia import compute_cmia
from .m4_llm_panel import run_llm_panel
from .aggregation import assemble_report
from .models import PRISMReport


class PRISMScanner:
    """
    Main entry point for PRISM skill security analysis.

    Usage:
        scanner = PRISMScanner()
        report  = scanner.scan("/path/to/skill")
        scanner.print_report(report)
    """

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self._llm_calls = 0

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def scan(self, skill_path: str | Path) -> PRISMReport:
        """
        Full PRISM scan of a skill directory.
        Returns a PRISMReport with verdict, scores, and kill chains.
        """
        skill_dir  = Path(skill_path).resolve()
        start_time = time.time()
        errors: list[str] = []
        self._llm_calls = 0

        if not skill_dir.is_dir():
            raise NotADirectoryError(f"Not a directory: {skill_dir}")
        if not (skill_dir / "SKILL.md").exists():
            raise FileNotFoundError(f"SKILL.md not found in {skill_dir}")

        self._log(f"\n{'━'*60}")
        self._log(f"  PRISM  ·  Scanning: {skill_dir.name}")
        self._log(f"{'━'*60}")

        # ── HASG Construction ──────────────────────────────────────────────
        self._log("\n[0/4] Building HASG (NL parse + AST analysis)…")
        try:
            graph, wf_extract, nl_caps, code_caps = build_hasg(skill_dir)
            self._llm_calls += 1   # NL parsing uses 1 LLM call
        except Exception as e:
            errors.append(f"HASG build failed: {e}")
            # Return a minimal error report
            from .models import NLThreatScore, CodeThreatScore, CMIAScore
            return assemble_report(
                skill_name=skill_dir.name, skill_dir=str(skill_dir),
                nl_score=NLThreatScore(), code_score=CodeThreatScore(),
                cmia_score=CMIAScore(), verdicts=[], nl_caps=None, code_caps=None,
                scan_duration=time.time() - start_time,
                llm_calls=self._llm_calls, errors=errors, injection_detected=False,
            )

        frontmatter = {}
        import re, yaml
        skill_md = skill_dir / "SKILL.md"
        if skill_md.exists():
            content = skill_md.read_text(encoding="utf-8", errors="replace")
            fm_match = re.match(r"^---\n(.*?)\n---", content, re.DOTALL)
            if fm_match:
                frontmatter = yaml.safe_load(fm_match.group(1)) or {}

        misalign_count = len(graph.misalign_edges())
        code_node_count = sum(
            1 for n in graph.nodes.values()
            if n.node_type.value in ("sys_op", "net_op", "io_op", "env_op")
        )
        self._log(
            f"  → {len(graph.nodes)} nodes  |  {len(graph.edges)} edges  |  "
            f"{misalign_count} misalign edges  |  "
            f"analyzability={code_caps.analyzability:.0%}"
        )

        # ── PHASE 1: Parallel deterministic analysis ───────────────────────
        self._log("\n[PHASE 1] Deterministic analysis (3 modules in parallel)…")

        # Module 1: NL Threat
        self._log("  [1/4] Module 1 — NL Instruction Threat Analyzer…")
        try:
            nl_score = analyze_nl_threats(wf_extract, frontmatter)
            self._llm_calls += 1
        except Exception as e:
            errors.append(f"Module 1 failed: {e}")
            from .models import NLThreatScore
            nl_score = NLThreatScore()

        if nl_score.flagged_units:
            self._log(f"       → {len(nl_score.flagged_units)} NL threat signals  |  "
                      f"max_score={nl_score.overall:.2f}")
        else:
            self._log(f"       → No NL threats detected  |  score={nl_score.overall:.2f}")

        # Module 2: Code Threat
        self._log("  [2/4] Module 2 — Code Threat Analyzer…")
        # Gather raw ops from hasg_builder internals
        from .hasg_builder import analyze_python_file, _RawCodeOp
        all_ops: list[_RawCodeOp] = []
        scripts_dir = skill_dir / "scripts"
        if scripts_dir.exists():
            for py_file in sorted(scripts_dir.glob("*.py")):
                ops, _ = analyze_python_file(py_file)
                all_ops.extend(ops)
        for py_file in sorted(skill_dir.glob("*.py")):
            ops, _ = analyze_python_file(py_file)
            all_ops.extend(ops)

        try:
            code_score = analyze_code_threats(graph, all_ops, code_caps)
        except Exception as e:
            errors.append(f"Module 2 failed: {e}")
            from .models import CodeThreatScore
            code_score = CodeThreatScore()

        self._log(f"       → pattern={code_score.pattern_score:.2f}  "
                  f"taint={code_score.taint_risk:.2f}  "
                  f"obfusc={code_score.obfusc_score:.2f}  "
                  f"overall={code_score.overall:.2f}")

        # Module 3: CMIA
        self._log("  [3/4] Module 3 — Cross-Modal Intent Alignment…")
        try:
            cmia_score = compute_cmia(graph, nl_caps, code_caps)
        except Exception as e:
            errors.append(f"Module 3 failed: {e}")
            from .models import CMIAScore
            cmia_score = CMIAScore()

        self._log(f"       → overall={cmia_score.overall:.2f}  "
                  f"over_reach={cmia_score.over_reach_score:.2f}  "
                  f"align={cmia_score.align_score:.2f}  "
                  f"gaps={len(cmia_score.capability_gaps)}")

        # Early exit check: if Phase 1 is very clear, skip LLM panel
        s1, s2, s3 = nl_score.overall, code_score.overall, cmia_score.overall
        fast_p = _fast_p_estimate(s1, s2, s3)

        if fast_p < 0.15:
            self._log("\n[PHASE 2] Skipped (Phase 1 strongly BENIGN — saving LLM cost)")
            verdicts = []
            injection_detected = False
        elif fast_p > 0.92:
            self._log("\n[PHASE 2] Skipped (Phase 1 strongly MALICIOUS — early BLOCK)")
            verdicts = []
            injection_detected = False
        else:
            # ── PHASE 2: LLM Panel ─────────────────────────────────────────
            self._log("\n[PHASE 2] Graph-Enhanced LLM Panel (3 judges)…")
            try:
                verdicts, injection_detected = run_llm_panel(
                    skill_dir, graph, nl_caps, code_caps,
                    nl_score, code_score, cmia_score,
                )
                self._llm_calls += 3  # one call per judge
            except Exception as e:
                errors.append(f"Module 4 (LLM panel) failed: {e}")
                verdicts = []
                injection_detected = False

            for v in verdicts:
                self._log(f"       [{v.judge_role:15s}] risk={v.risk_score:.2f}  "
                          f"conf={v.confidence:.2f}  malicious={v.is_malicious}")

        # ── Bayesian aggregation + kill chains ─────────────────────────────
        self._log("\n[4/4] Bayesian aggregation + kill chain extraction…")
        report = assemble_report(
            skill_name=graph.skill_name,
            skill_dir=str(skill_dir),
            nl_score=nl_score,
            code_score=code_score,
            cmia_score=cmia_score,
            verdicts=verdicts,
            nl_caps=nl_caps,
            code_caps=code_caps,
            scan_duration=time.time() - start_time,
            llm_calls=self._llm_calls,
            errors=errors,
            injection_detected=injection_detected if 'injection_detected' in dir() else False,
        )

        self._log(f"\n{'━'*60}")
        _VERDICT_COLORS = {
            "BLOCK":  "🔴",
            "REVIEW": "🟠",
            "WARN":   "🟡",
            "PASS":   "🟢",
        }
        icon = _VERDICT_COLORS.get(report.verdict.value, "⚪")
        self._log(
            f"  {icon}  VERDICT: {report.verdict.value:6s}  "
            f"P(malicious)={report.p_malicious:.3f}  "
            f"({report.scan_duration_s:.1f}s  /  {report.llm_calls_made} LLM calls)"
        )
        self._log(f"{'━'*60}\n")

        return report

    def print_report(self, report: PRISMReport) -> None:
        """Print a detailed human-readable report to stdout."""
        from .report import print_report
        print_report(report)


def scan_skill(skill_path: str | Path, verbose: bool = True) -> PRISMReport:
    """Convenience function for one-off scans."""
    return PRISMScanner(verbose=verbose).scan(skill_path)


# ─────────────────────────────────────────────────────────────────────────────
# Fast Phase 1 estimate (for early-exit logic)
# ─────────────────────────────────────────────────────────────────────────────

def _fast_p_estimate(s1: float, s2: float, s3: float) -> float:
    """Quick heuristic P(malicious) from Phase 1 scores only."""
    # Simple weighted average used only for early-exit decision
    w = [0.35, 0.30, 0.35]
    raw = w[0] * s1 + w[1] * s2 + w[2] * s3
    # Transform with sigmoid to get proper probability range
    import math
    # Rescale: raw=0.5 → p=0.5; raw=0.8 → p≈0.88; raw=0.2 → p≈0.12
    logit = 8 * (raw - 0.45)
    return 1.0 / (1.0 + math.exp(-logit))
