"""
PRISM Scanner — main orchestrator.

Three-phase pipeline:
  Phase 0  Preprocessing   — HASG construction + static injection detection
  Phase 1  Static Analysis — 1a pattern matching, 1b behavioral analysis,
                             1c pipeline analysis, 1d NL-code alignment (CMIA),
                             1e plugin checks
  Phase 2  LLM Judges      — 2a per-finding filter, 2b NL consistency analysis,
                             2c adversarial role-play judges
  Output   Bayesian aggregation + verdict + user-friendly report
"""
from __future__ import annotations

import math
import re
import time
import yaml
from pathlib import Path
from typing import Optional

from .hasg_builder import build_hasg, analyze_python_file, _RawCodeOp
from .m2_code_threat import analyze_code_threats
from .m3_cmia import compute_cmia
from .m4_llm_panel import run_llm_panel, run_nl_consistency
from .phase0_injection import detect_injection
from .phase1_pipeline import analyze_pipeline
from .phase1_plugins import run_plugins
from .phase2_finding_filter import filter_findings, compute_filtered_score
from .aggregation import assemble_report
from .models import (
    Finding, InjectionResult, NLThreatScore, CodeThreatScore,
    CMIAScore, PRISMReport, Verdict, Severity, ThreatCategory,
)


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

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

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

        self._log(f"\n{'━'*64}")
        self._log(f"  PRISM  ·  Scanning: {skill_dir.name}")
        self._log(f"{'━'*64}")

        # ══════════════════════════════════════════════════════════════════════
        # PHASE 0 — PREPROCESSING
        # ══════════════════════════════════════════════════════════════════════
        self._log("\n[PHASE 0] Preprocessing — HASG construction + injection detection")

        # 0-A: HASG Construction (NL parse + AST analysis)
        self._log("  [0a] Building HASG (NL parse + AST analysis)…")
        try:
            graph, wf_extract, nl_caps, code_caps = build_hasg(skill_dir)
            self._llm_calls += 1   # NL parsing uses 1 LLM call
        except Exception as e:
            errors.append(f"HASG build failed: {e}")
            return assemble_report(
                skill_name=skill_dir.name, skill_dir=str(skill_dir),
                nl_score=NLThreatScore(), code_score=CodeThreatScore(),
                cmia_score=CMIAScore(), verdicts=[], nl_caps=None, code_caps=None,
                scan_duration=time.time() - start_time,
                llm_calls=self._llm_calls, errors=errors,
                injection_detected=False, static_findings=[],
                pipeline_score=0.0, plugin_score=0.0,
            )

        # Parse frontmatter for context used throughout
        frontmatter = _parse_frontmatter(skill_dir)
        misalign_count = len(graph.misalign_edges())
        self._log(
            f"       → {len(graph.nodes)} nodes  |  {len(graph.edges)} edges  |  "
            f"{misalign_count} misalign edges  |  "
            f"analyzability={code_caps.analyzability:.0%}"
        )

        # 0-B: Static injection detection (no LLM needed)
        self._log("  [0b] Static injection detection…")
        injection_result: InjectionResult = detect_injection(skill_dir)
        if injection_result.detected:
            self._log(
                f"       ⚠ INJECTION DETECTED (conf={injection_result.confidence:.2f})  "
                f"patterns={injection_result.patterns_found}"
            )
            # Early exit: obvious injection → immediate BLOCK without further analysis
            errors.append(
                f"PHASE 0 EARLY EXIT: Static injection detected "
                f"(confidence={injection_result.confidence:.2f}, "
                f"patterns={injection_result.patterns_found})"
            )
            for txt in injection_result.matched_texts:
                errors.append(f"  Matched: {txt}")
            return assemble_report(
                skill_name=graph.skill_name, skill_dir=str(skill_dir),
                nl_score=NLThreatScore(), code_score=CodeThreatScore(),
                cmia_score=CMIAScore(), verdicts=[], nl_caps=nl_caps, code_caps=code_caps,
                scan_duration=time.time() - start_time,
                llm_calls=self._llm_calls, errors=errors,
                injection_detected=True, static_findings=[],
                pipeline_score=0.0, plugin_score=0.0,
            )
        else:
            self._log(f"       → No injection patterns detected (conf={injection_result.confidence:.2f})")

        # Collect raw code ops for Phase 1 analyzers
        all_ops: list[_RawCodeOp] = _collect_ops(skill_dir)

        # ══════════════════════════════════════════════════════════════════════
        # PHASE 1 — STATIC ANALYSIS (all sub-analyzers, no LLM)
        # ══════════════════════════════════════════════════════════════════════
        self._log("\n[PHASE 1] Static Analysis (5 sub-analyzers, no LLM)…")
        all_static_findings: list[Finding] = []

        # 1a + 1b: Pattern matching + Behavioral analysis (taint propagation)
        self._log("  [1a/1b] Pattern matching + Behavioral analysis (taint propagation)…")
        try:
            code_score = analyze_code_threats(graph, all_ops, code_caps)
        except Exception as e:
            errors.append(f"Phase 1a/1b failed: {e}")
            code_score = CodeThreatScore()
        self._log(
            f"         → pattern={code_score.pattern_score:.2f}  "
            f"taint={code_score.taint_risk:.2f}  "
            f"obfusc={code_score.obfusc_score:.2f}  "
            f"overall={code_score.overall:.2f}"
        )
        # Promote top code findings to Finding objects
        for f in code_score.top_findings[:5]:
            sev = Severity.CRITICAL if f["score"] > 0.85 else (
                Severity.HIGH if f["score"] > 0.60 else Severity.MEDIUM
            )
            all_static_findings.append(Finding(
                severity=sev,
                category=ThreatCategory.UNKNOWN,
                description=f["description"],
                analyzer="pattern/behavioral",
            ))

        # 1c: Pipeline analysis (graph-based multi-step chain detection)
        self._log("  [1c]   Pipeline analysis (workflow graph chain detection)…")
        try:
            pipeline_score, pipeline_findings = analyze_pipeline(graph)
        except Exception as e:
            errors.append(f"Phase 1c (pipeline) failed: {e}")
            pipeline_score, pipeline_findings = 0.0, []
        all_static_findings.extend(pipeline_findings)
        if pipeline_findings:
            self._log(f"         → {len(pipeline_findings)} pipeline chain(s) detected  "
                      f"score={pipeline_score:.2f}")
        else:
            self._log(f"         → No dangerous chains detected  score={pipeline_score:.2f}")

        # 1d: Cross-Modal Intent Alignment (CMIA)
        self._log("  [1d]   NL–code alignment (CMIA)…")
        try:
            cmia_score = compute_cmia(graph, nl_caps, code_caps)
        except Exception as e:
            errors.append(f"Phase 1d (CMIA) failed: {e}")
            cmia_score = CMIAScore()
        self._log(
            f"         → overall={cmia_score.overall:.2f}  "
            f"over_reach={cmia_score.over_reach_score:.2f}  "
            f"align={cmia_score.align_score:.2f}  "
            f"gaps={len(cmia_score.capability_gaps)}"
        )
        # CMIA gaps as findings
        for gap in cmia_score.capability_gaps[:3]:
            all_static_findings.append(Finding(
                severity=Severity.MEDIUM,
                category=ThreatCategory.T11_NL_EXPANSION,
                description=f"Code capability not declared in SKILL.md: {gap}",
                analyzer="cmia",
            ))

        # 1e: Plugin checks (embedded resources, manifest audit, comment injection)
        self._log("  [1e]   Plugin checks (resource scan, manifest audit, comment injection)…")
        try:
            plugin_score, plugin_findings = run_plugins(skill_dir, graph)
        except Exception as e:
            errors.append(f"Phase 1e (plugins) failed: {e}")
            plugin_score, plugin_findings = 0.0, []
        all_static_findings.extend(plugin_findings)
        if plugin_findings:
            self._log(f"         → {len(plugin_findings)} plugin finding(s)  score={plugin_score:.2f}")
        else:
            self._log(f"         → No plugin findings  score={plugin_score:.2f}")

        self._log(
            f"\n  Phase 1 summary: {len(all_static_findings)} total findings  "
            f"(pattern={code_score.overall:.2f}  pipeline={pipeline_score:.2f}  "
            f"cmia={cmia_score.overall:.2f}  plugins={plugin_score:.2f})"
        )

        # Fast P(malicious) estimate from Phase 1 only (for early-exit / Phase 2 gate)
        fast_p = _fast_p_estimate(
            code_score.overall, cmia_score.overall, pipeline_score, plugin_score
        )

        # ══════════════════════════════════════════════════════════════════════
        # PHASE 2 — LLM JUDGES
        # ══════════════════════════════════════════════════════════════════════

        # Early-exit conditions (skip Phase 2 to save LLM cost)
        if fast_p < 0.12:
            self._log("\n[PHASE 2] Skipped (Phase 1 strongly BENIGN — saving LLM cost)")
            nl_score = NLThreatScore()   # neutral
            verdicts = []
            llm_injection_detected = False
        elif fast_p > 0.93:
            self._log("\n[PHASE 2] Skipped (Phase 1 strongly MALICIOUS — early BLOCK)")
            nl_score = NLThreatScore()
            verdicts = []
            llm_injection_detected = False
        else:
            self._log("\n[PHASE 2] LLM Analysis…")

            # 2a: Per-finding LLM filter (false-positive triage)
            self._log("  [2a]   Per-finding LLM filter…")
            declared_purpose = wf_extract.declared_purpose if wf_extract else ""
            manifest_perms   = str(frontmatter.get("permissions", ""))
            try:
                all_static_findings = filter_findings(
                    all_static_findings, declared_purpose, manifest_perms
                )
                self._llm_calls += 1
            except Exception as e:
                errors.append(f"Phase 2a (finding filter) failed: {e}")
            filtered_score = compute_filtered_score(all_static_findings)
            confirmed_count = sum(
                1 for f in all_static_findings if f.llm_verified is True
            )
            self._log(f"         → filtered_score={filtered_score:.2f}  "
                      f"confirmed={confirmed_count}/{len(all_static_findings)} findings")

            # 2b: LLM NL / script consistency analysis (context-aware NL threat scoring)
            self._log("  [2b]   LLM NL–script consistency analysis…")
            pipeline_descs = [f.description[:80] for f in pipeline_findings[:3]]
            try:
                nl_score = run_nl_consistency(
                    wf_extract, frontmatter,
                    code_score, cmia_score, pipeline_descs,
                )
                self._llm_calls += 1
            except Exception as e:
                errors.append(f"Phase 2b (NL consistency) failed: {e}")
                nl_score = NLThreatScore()
            if nl_score.flagged_units:
                self._log(
                    f"         → {len(nl_score.flagged_units)} NL threat signals  "
                    f"max_score={nl_score.overall:.2f}"
                )
                if nl_score.kill_chain_detected:
                    self._log(f"         ⛓ Kill chain: {nl_score.kill_chain_description[:60]}")
            else:
                self._log(f"         → No NL threats detected  score={nl_score.overall:.2f}")

            # 2c: Adversarial role-play judges (Defender / Red Team / Intent Auditor)
            self._log("  [2c]   Adversarial role-play judges (Defender / Red Team / Auditor)…")
            try:
                verdicts, llm_injection_detected = run_llm_panel(
                    skill_dir, graph, nl_caps, code_caps,
                    nl_score, code_score, cmia_score,
                )
                self._llm_calls += 3   # one call per judge
            except Exception as e:
                errors.append(f"Phase 2c (role judges) failed: {e}")
                verdicts = []
                llm_injection_detected = False
            for v in verdicts:
                self._log(
                    f"         [{v.judge_role:15s}] risk={v.risk_score:.2f}  "
                    f"conf={v.confidence:.2f}  malicious={v.is_malicious}"
                )

        # ══════════════════════════════════════════════════════════════════════
        # OUTPUT — Bayesian aggregation + verdict
        # ══════════════════════════════════════════════════════════════════════
        self._log("\n[OUTPUT] Bayesian aggregation + verdict…")
        combined_injection = injection_result.detected or (
            'llm_injection_detected' in dir() and llm_injection_detected
        )
        report = assemble_report(
            skill_name=graph.skill_name,
            skill_dir=str(skill_dir),
            nl_score=nl_score if 'nl_score' in dir() else NLThreatScore(),
            code_score=code_score,
            cmia_score=cmia_score,
            verdicts=verdicts if 'verdicts' in dir() else [],
            nl_caps=nl_caps,
            code_caps=code_caps,
            scan_duration=time.time() - start_time,
            llm_calls=self._llm_calls,
            errors=errors,
            injection_detected=combined_injection,
            static_findings=all_static_findings,
            pipeline_score=pipeline_score,
            plugin_score=plugin_score,
        )

        self._log(f"\n{'━'*64}")
        _VERDICT_ICONS = {"BLOCK": "🔴", "REVIEW": "🟠", "WARN": "🟡", "PASS": "🟢"}
        icon = _VERDICT_ICONS.get(report.verdict.value, "⚪")
        self._log(
            f"  {icon}  VERDICT: {report.verdict.value:6s}  "
            f"P(malicious)={report.p_malicious:.3f}  "
            f"({report.scan_duration_s:.1f}s  /  {report.llm_calls_made} LLM calls)"
        )
        self._log(f"{'━'*64}\n")

        return report

    def print_report(self, report: PRISMReport) -> None:
        """Print a detailed human-readable report to stdout."""
        from .report import print_report
        print_report(report)


# ─────────────────────────────────────────────────────────────────────────────
# Convenience function
# ─────────────────────────────────────────────────────────────────────────────

def scan_skill(skill_path: str | Path, verbose: bool = True) -> PRISMReport:
    """Convenience function for one-off scans."""
    return PRISMScanner(verbose=verbose).scan(skill_path)


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_frontmatter(skill_dir: Path) -> dict:
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        return {}
    content = skill_md.read_text(encoding="utf-8", errors="replace")
    fm_match = re.match(r"^---\n(.*?)\n---", content, re.DOTALL)
    if fm_match:
        try:
            return yaml.safe_load(fm_match.group(1)) or {}
        except Exception:
            pass
    return {}


def _collect_ops(skill_dir: Path) -> list[_RawCodeOp]:
    """Gather raw code operations from all Python files in the skill."""
    all_ops: list[_RawCodeOp] = []
    for subdir in ("scripts", "."):
        target = skill_dir / subdir if subdir != "." else skill_dir
        for py_file in sorted(target.glob("*.py")):
            try:
                ops, _ = analyze_python_file(py_file)
                all_ops.extend(ops)
            except Exception:
                pass
        if subdir == ".":
            break
    return all_ops


def _fast_p_estimate(
    code_score: float,
    cmia_score: float,
    pipeline_score: float,
    plugin_score: float,
) -> float:
    """
    Quick heuristic P(malicious) from Phase 1 scores only.
    Used for Phase 2 early-exit gate — not the final posterior.
    """
    # Weighted combination of Phase 1 signals
    w = [0.35, 0.35, 0.20, 0.10]
    raw = (
        w[0] * code_score +
        w[1] * cmia_score +
        w[2] * pipeline_score +
        w[3] * plugin_score
    )
    # Sigmoid rescaling: raw=0.45 → p≈0.5; raw=0.8 → p≈0.88; raw=0.15 → p≈0.10
    logit = 8.0 * (raw - 0.45)
    return 1.0 / (1.0 + math.exp(-logit))
