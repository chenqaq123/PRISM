"""
PRISM Scanner — main orchestrator.

Deployment model
────────────────
  scan_phase1()  Cloud-side scan: HASG construction (1 LLM call, PRISM_CLOUD_MODEL)
                 + full deterministic static analysis.
                 Returns Phase1Result (JSON-serialisable). No sensitive data leaves
                 the cloud; the skill directory is read remotely.

  scan_phase2()  User-side scan: LLM-judge panel (PRISM_JUDGE_MODEL).
                 Accepts a Phase1Result (loaded from JSON) + the local skill
                 directory (already downloaded). Never re-reads the cloud.

  scan()         Convenience wrapper: runs both phases in sequence (dev / CI use).

Attack-surface rationale
────────────────────────
  Phase 1 threat model — adversarial skill content at scale
    • SKILL.md may contain prompt-injection payloads targeting the cloud LLM
      used for HASG construction. Mitigation: random delimiter wrapping + Phase 0
      static injection detector (fires before any LLM call).
    • Cloud sees ALL skills; cheap model + strict schema keeps cost tractable.

  Phase 2 threat model — targeted manipulation of user-side judge
    • Only skills the user actually downloaded reach Phase 2.
    • Adversary has stronger incentive to craft judge-manipulation payloads
      (single target vs. millions). Quality model + adversarial judge trio
      increases manipulation cost.
    • User machine: no bulk API exposure, but higher per-call quality budget.
"""
from __future__ import annotations

import json
import math
import re
import time
import yaml
from pathlib import Path
from typing import Optional

from .hasg_builder import build_hasg, analyze_python_file, serialize_hasg, _RawCodeOp
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
    Phase1Result, WorkflowExtract,
)


class PRISMScanner:
    """
    Main entry point for PRISM skill security analysis.

    Typical usage (combined):
        scanner = PRISMScanner()
        report  = scanner.scan("/path/to/skill")

    Two-phase usage (cloud + user):
        # Cloud:
        p1 = scanner.scan_phase1("/path/to/skill")
        p1_json = p1.model_dump_json()          # save / ship to user

        # User:
        p1 = Phase1Result.model_validate_json(p1_json)
        report = scanner.scan_phase2(p1)        # skill_dir read from p1.skill_dir
    """

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self._llm_calls = 0

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 1 — Cloud-side
    # ─────────────────────────────────────────────────────────────────────────

    def scan_phase1(self, skill_path: str | Path) -> Phase1Result:
        """
        Cloud-side scan: HASG construction + full static analysis.
        Uses PRISM_CLOUD_MODEL for the single LLM call (HASG NL parsing).
        Returns a JSON-serialisable Phase1Result.
        """
        skill_dir  = Path(skill_path).resolve()
        start_time = time.time()
        errors: list[str] = []
        llm_calls = 0

        if not skill_dir.is_dir():
            raise NotADirectoryError(f"Not a directory: {skill_dir}")
        if not (skill_dir / "SKILL.md").exists():
            raise FileNotFoundError(f"SKILL.md not found in {skill_dir}")

        self._log(f"\n{'━'*64}")
        self._log(f"  PRISM Phase 1  ·  {skill_dir.name}")
        self._log(f"{'━'*64}")

        # ── Phase 0-A: HASG Construction ──────────────────────────────────────
        self._log("\n[PHASE 0] Preprocessing — HASG construction + injection detection")
        self._log("  [0a] Building HASG (PRISM_CLOUD_MODEL)…")
        try:
            graph, wf_extract, nl_caps, code_caps = build_hasg(skill_dir)
            llm_calls += 1
        except Exception as e:
            errors.append(f"HASG build failed: {e}")
            return Phase1Result(
                skill_name=skill_dir.name, skill_dir=str(skill_dir),
                injection_detected=False,
                code_score=CodeThreatScore(), cmia_score=CMIAScore(),
                nl_caps=None, code_caps=None,
                scan_duration_phase1=time.time() - start_time,
                llm_calls_phase1=llm_calls, errors=errors,
            )

        # ── Debug: print LLM-extracted instruction units ──────────────────
        if self.verbose:
            from .visualize import print_instruction_units
            print_instruction_units(wf_extract)

        frontmatter = _parse_frontmatter(skill_dir)
        misalign_count = len(graph.misalign_edges())
        self._log(
            f"       → {len(graph.nodes)} nodes  |  {len(graph.edges)} edges  |  "
            f"{misalign_count} misalign edges  |  "
            f"analyzability={code_caps.analyzability:.0%}"
        )

        # ── Phase 0-B: Static injection detection ────────────────────────────
        self._log("  [0b] Static injection detection…")
        injection_result: InjectionResult = detect_injection(skill_dir)
        if injection_result.detected:
            self._log(
                f"       ⚠ INJECTION DETECTED (conf={injection_result.confidence:.2f})  "
                f"patterns={injection_result.patterns_found}"
            )
            errors.append(
                f"PHASE 0 EARLY EXIT: injection detected "
                f"(confidence={injection_result.confidence:.2f})"
            )
            return Phase1Result(
                skill_name=graph.skill_name, skill_dir=str(skill_dir),
                injection_detected=True,
                code_score=CodeThreatScore(), cmia_score=CMIAScore(),
                nl_caps=nl_caps, code_caps=code_caps,
                wf_extract=wf_extract, frontmatter=frontmatter,
                fast_p=1.0,
                scan_duration_phase1=time.time() - start_time,
                llm_calls_phase1=llm_calls, errors=errors,
            )
        else:
            self._log(f"       → No injection patterns (conf={injection_result.confidence:.2f})")

        # ── Phase 1: Static analysis (all sub-analyzers, no LLM) ─────────────
        self._log("\n[PHASE 1] Static Analysis (deterministic, no LLM)…")
        all_static_findings: list[Finding] = []
        all_ops: list[_RawCodeOp] = _collect_ops(skill_dir)

        # 1a+1b: Pattern + behavioral
        self._log("  [1a/1b] Pattern matching + Behavioral analysis…")
        try:
            code_score = analyze_code_threats(graph, all_ops, code_caps)
        except Exception as e:
            errors.append(f"Phase 1a/1b failed: {e}")
            code_score = CodeThreatScore()
        self._log(
            f"         → pattern={code_score.pattern_score:.2f}  "
            f"taint={code_score.taint_risk:.2f}  "
            f"obfusc={code_score.obfusc_score:.2f}  overall={code_score.overall:.2f}"
        )
        for f in code_score.top_findings[:5]:
            sev = Severity.CRITICAL if f["score"] > 0.85 else (
                Severity.HIGH if f["score"] > 0.60 else Severity.MEDIUM)
            all_static_findings.append(Finding(
                severity=sev, category=ThreatCategory.UNKNOWN,
                description=f["description"], analyzer="pattern/behavioral",
            ))

        # 1c: Pipeline
        self._log("  [1c]   Pipeline analysis…")
        try:
            pipeline_score, pipeline_findings = analyze_pipeline(graph)
        except Exception as e:
            errors.append(f"Phase 1c failed: {e}")
            pipeline_score, pipeline_findings = 0.0, []
        all_static_findings.extend(pipeline_findings)
        if pipeline_findings:
            self._log(f"         → {len(pipeline_findings)} chain(s)  score={pipeline_score:.2f}")
        else:
            self._log(f"         → No dangerous chains  score={pipeline_score:.2f}")

        # 1d: CMIA
        self._log("  [1d]   NL–code alignment (CMIA)…")
        try:
            cmia_score = compute_cmia(graph, nl_caps, code_caps)
        except Exception as e:
            errors.append(f"Phase 1d failed: {e}")
            cmia_score = CMIAScore()
        self._log(
            f"         → overall={cmia_score.overall:.2f}  "
            f"over_reach={cmia_score.over_reach_score:.2f}  "
            f"gaps={len(cmia_score.capability_gaps)}"
        )
        for gap in cmia_score.capability_gaps[:3]:
            all_static_findings.append(Finding(
                severity=Severity.MEDIUM, category=ThreatCategory.T11_NL_EXPANSION,
                description=f"Code capability not declared in SKILL.md: {gap}",
                analyzer="cmia",
            ))

        # 1e: Plugins
        self._log("  [1e]   Plugin checks…")
        try:
            plugin_score, plugin_findings = run_plugins(skill_dir, graph)
        except Exception as e:
            errors.append(f"Phase 1e failed: {e}")
            plugin_score, plugin_findings = 0.0, []
        all_static_findings.extend(plugin_findings)
        if plugin_findings:
            self._log(f"         → {len(plugin_findings)} finding(s)  score={plugin_score:.2f}")
        else:
            self._log(f"         → No plugin findings  score={plugin_score:.2f}")

        self._log(
            f"\n  Phase 1 summary: {len(all_static_findings)} findings  "
            f"(pattern={code_score.overall:.2f}  pipeline={pipeline_score:.2f}  "
            f"cmia={cmia_score.overall:.2f}  plugins={plugin_score:.2f})"
        )

        fast_p = _fast_p_estimate(
            code_score.overall, cmia_score.overall, pipeline_score, plugin_score
        )

        # Pre-serialise HASG context (Phase 2 appends nl_score supplement later)
        hasg_context_base = serialize_hasg(
            graph, nl_caps, code_caps,
            {"s1": 0.0, "s2": code_score.overall, "s3": cmia_score.overall,
             "flagged_nl_patterns": [], "capability_gaps": cmia_score.capability_gaps[:3]},
        )

        self._log(f"\n  Phase 1 complete — fast_p={fast_p:.3f}  "
                  f"({time.time() - start_time:.1f}s  /  {llm_calls} LLM call)")

        return Phase1Result(
            skill_name=graph.skill_name,
            skill_dir=str(skill_dir),
            injection_detected=False,
            code_score=code_score,
            cmia_score=cmia_score,
            pipeline_score=pipeline_score,
            plugin_score=plugin_score,
            fast_p=fast_p,
            static_findings=all_static_findings,
            pipeline_findings_desc=[f.description[:80] for f in pipeline_findings[:3]],
            nl_caps=nl_caps,
            code_caps=code_caps,
            wf_extract=wf_extract,
            frontmatter=frontmatter,
            hasg_context_base=hasg_context_base,
            scan_duration_phase1=round(time.time() - start_time, 1),
            llm_calls_phase1=llm_calls,
            errors=errors,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 2 — User-side
    # ─────────────────────────────────────────────────────────────────────────

    def scan_phase2(
        self,
        p1: Phase1Result,
        skill_path: str | Path | None = None,
    ) -> PRISMReport:
        """
        User-side scan: LLM judge panel using PRISM_JUDGE_MODEL.
        Accepts a Phase1Result (loaded from JSON) + optional skill_path override
        (defaults to p1.skill_dir — must be accessible on the user's machine).
        """
        skill_dir  = Path(skill_path).resolve() if skill_path else Path(p1.skill_dir)
        start_time = time.time()
        llm_calls  = 0
        errors     = list(p1.errors)

        self._log(f"\n{'━'*64}")
        self._log(f"  PRISM Phase 2  ·  {p1.skill_name}")
        self._log(f"{'━'*64}")

        # Early-exit: injection already detected in Phase 1
        if p1.injection_detected:
            self._log("\n[PHASE 2] Skipped (injection detected in Phase 1 — BLOCK)")
            return assemble_report(
                skill_name=p1.skill_name, skill_dir=str(skill_dir),
                nl_score=NLThreatScore(), code_score=p1.code_score,
                cmia_score=p1.cmia_score, verdicts=[], nl_caps=p1.nl_caps,
                code_caps=p1.code_caps,
                scan_duration=p1.scan_duration_phase1 + (time.time() - start_time),
                llm_calls=p1.llm_calls_phase1, errors=errors,
                injection_detected=True,
                static_findings=p1.static_findings,
                pipeline_score=p1.pipeline_score, plugin_score=p1.plugin_score,
            )

        # Phase 2 gate
        if p1.fast_p < 0.12:
            self._log("\n[PHASE 2] Skipped (Phase 1 strongly BENIGN — saving LLM cost)")
            return self._assemble(p1, NLThreatScore(), [], False,
                                  start_time, skill_dir, llm_calls, errors)
        elif p1.fast_p > 0.93:
            self._log("\n[PHASE 2] Skipped (Phase 1 strongly MALICIOUS — early BLOCK)")
            return self._assemble(p1, NLThreatScore(), [], False,
                                  start_time, skill_dir, llm_calls, errors)

        self._log("\n[PHASE 2] LLM Analysis (PRISM_JUDGE_MODEL)…")
        all_findings = list(p1.static_findings)

        # 2a: Per-finding LLM filter
        self._log("  [2a]   Per-finding LLM filter…")
        declared_purpose = p1.wf_extract.declared_purpose if p1.wf_extract else ""
        manifest_perms   = str(p1.frontmatter.get("permissions", ""))
        try:
            all_findings = filter_findings(all_findings, declared_purpose, manifest_perms)
            llm_calls += 1
        except Exception as e:
            errors.append(f"Phase 2a failed: {e}")
        filtered_score  = compute_filtered_score(all_findings)
        confirmed_count = sum(1 for f in all_findings if f.llm_verified is True)
        self._log(f"         → filtered_score={filtered_score:.2f}  "
                  f"confirmed={confirmed_count}/{len(all_findings)}")

        # 2b: NL consistency
        self._log("  [2b]   LLM NL–script consistency analysis…")
        try:
            nl_score = run_nl_consistency(
                p1.wf_extract, p1.frontmatter,
                p1.code_score, p1.cmia_score, p1.pipeline_findings_desc,
            )
            llm_calls += 1
        except Exception as e:
            errors.append(f"Phase 2b failed: {e}")
            nl_score = NLThreatScore()
        if nl_score.flagged_units:
            self._log(f"         → {len(nl_score.flagged_units)} NL threat signals  "
                      f"max={nl_score.overall:.2f}")
            if nl_score.kill_chain_detected:
                self._log(f"         ⛓ Kill chain: {nl_score.kill_chain_description[:60]}")
        else:
            self._log(f"         → No NL threats  score={nl_score.overall:.2f}")

        # 2c: Adversarial role-play judges
        self._log("  [2c]   Adversarial role-play judges…")
        try:
            verdicts, llm_injection_detected = run_llm_panel(
                skill_dir=skill_dir,
                graph=None,
                nl_caps=p1.nl_caps,
                code_caps=p1.code_caps,
                nl_score=nl_score,
                code_score=p1.code_score,
                cmia_score=p1.cmia_score,
                hasg_context_base=p1.hasg_context_base,
            )
            llm_calls += 3
        except Exception as e:
            errors.append(f"Phase 2c failed: {e}")
            verdicts, llm_injection_detected = [], False
        for v in verdicts:
            self._log(
                f"         [{v.judge_role:15s}] risk={v.risk_score:.2f}  "
                f"conf={v.confidence:.2f}  malicious={v.is_malicious}"
            )

        return self._assemble(
            p1, nl_score, verdicts,
            llm_injection_detected, start_time, skill_dir, llm_calls, errors,
            static_findings=all_findings,
        )

    def _assemble(
        self, p1: Phase1Result,
        nl_score: NLThreatScore,
        verdicts: list,
        llm_injection: bool,
        start_time: float,
        skill_dir: Path,
        llm_calls_p2: int,
        errors: list[str],
        static_findings: list | None = None,
    ) -> PRISMReport:
        combined_injection = p1.injection_detected or llm_injection
        report = assemble_report(
            skill_name=p1.skill_name,
            skill_dir=str(skill_dir),
            nl_score=nl_score,
            code_score=p1.code_score,
            cmia_score=p1.cmia_score,
            verdicts=verdicts,
            nl_caps=p1.nl_caps,
            code_caps=p1.code_caps,
            scan_duration=p1.scan_duration_phase1 + (time.time() - start_time),
            llm_calls=p1.llm_calls_phase1 + llm_calls_p2,
            errors=errors,
            injection_detected=combined_injection,
            static_findings=static_findings if static_findings is not None
                            else p1.static_findings,
            pipeline_score=p1.pipeline_score,
            plugin_score=p1.plugin_score,
        )
        self._log(f"\n{'━'*64}")
        _ICONS = {"BLOCK": "🔴", "REVIEW": "🟠", "WARN": "🟡", "PASS": "🟢"}
        icon = _ICONS.get(report.verdict.value, "⚪")
        self._log(
            f"  {icon}  VERDICT: {report.verdict.value:6s}  "
            f"P(malicious)={report.p_malicious:.3f}  "
            f"({report.scan_duration_s:.1f}s  /  {report.llm_calls_made} LLM calls)"
        )
        self._log(f"{'━'*64}\n")
        return report

    # ─────────────────────────────────────────────────────────────────────────
    # Combined convenience API (dev / CI)
    # ─────────────────────────────────────────────────────────────────────────

    def scan(self, skill_path: str | Path) -> PRISMReport:
        """Run both phases in sequence. Equivalent to cloud + user scan."""
        p1 = self.scan_phase1(skill_path)
        return self.scan_phase2(p1, skill_path)

    def print_report(self, report: PRISMReport) -> None:
        from .report import print_report
        print_report(report)


# ─────────────────────────────────────────────────────────────────────────────
# Convenience functions
# ─────────────────────────────────────────────────────────────────────────────

def scan_skill(skill_path: str | Path, verbose: bool = True) -> PRISMReport:
    return PRISMScanner(verbose=verbose).scan(skill_path)


def scan_phase1(skill_path: str | Path, verbose: bool = True) -> Phase1Result:
    return PRISMScanner(verbose=verbose).scan_phase1(skill_path)


def scan_phase2(
    p1: Phase1Result,
    skill_path: str | Path | None = None,
    verbose: bool = True,
) -> PRISMReport:
    return PRISMScanner(verbose=verbose).scan_phase2(p1, skill_path)


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
    w   = [0.35, 0.35, 0.20, 0.10]
    raw = (w[0]*code_score + w[1]*cmia_score +
           w[2]*pipeline_score + w[3]*plugin_score)
    logit = 8.0 * (raw - 0.45)
    return 1.0 / (1.0 + math.exp(-logit))
