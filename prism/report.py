"""
PRISM Report Renderer
Generates rich human-readable reports and JSON exports.
"""
from __future__ import annotations

import json
from pathlib import Path

from .models import PRISMReport, Verdict, Severity, KillChain, JudgeVerdict


# ─────────────────────────────────────────────────────────────────────────────
# Console report
# ─────────────────────────────────────────────────────────────────────────────

_VERDICT_STYLE = {
    Verdict.BLOCK:  ("🔴", "BLOCK   — Automatic rejection recommended"),
    Verdict.REVIEW: ("🟠", "REVIEW  — Manual security review required"),
    Verdict.WARN:   ("🟡", "WARN    — Install with caution, user notified"),
    Verdict.PASS:   ("🟢", "PASS    — No significant threats detected"),
}

_SEV_STYLE = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH:     "🟠 HIGH    ",
    Severity.MEDIUM:   "🟡 MEDIUM  ",
    Severity.LOW:      "🔵 LOW     ",
}

_BAR_WIDTH = 20


def _score_bar(score: float) -> str:
    filled = int(score * _BAR_WIDTH)
    bar    = "█" * filled + "░" * (_BAR_WIDTH - filled)
    return f"[{bar}] {score:.2f}"


def print_report(report: PRISMReport) -> None:
    SEP  = "─" * 68
    SEP2 = "═" * 68

    print(f"\n{SEP2}")
    print(f"  PRISM SCAN REPORT  ·  {report.skill_name}")
    print(SEP2)

    # ── Verdict ──────────────────────────────────────────────────────────────
    icon, desc = _VERDICT_STYLE.get(report.verdict, ("⚪", report.verdict.value))
    sev_str    = _SEV_STYLE.get(report.severity(), report.severity().value)
    print(f"\n  {icon}  {desc}")
    print(f"  {sev_str}    P(malicious) = {report.p_malicious:.3f}    "
          f"Confidence = {report.confidence:.2f}")

    # ── Module scores ─────────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("  MODULE SCORES")
    print(SEP)
    print(f"  s1  NL Threat  (Module 1)  {_score_bar(report.s1_nl_threat)}")
    print(f"  s2  Code Threat (Module 2)  {_score_bar(report.s2_code_threat)}")
    print(f"  s3  CMIA       (Module 3)  {_score_bar(report.s3_cmia)}")
    print(f"  s4  LLM Panel  (Module 4)  {_score_bar(report.s4_llm_panel)}")

    # ── NL Threat Detail ─────────────────────────────────────────────────────
    if report.nl_threat_detail and report.nl_threat_detail.flagged_units:
        print(f"\n{SEP}")
        print("  NL INSTRUCTION THREATS (Module 1)")
        print(SEP)
        nl = report.nl_threat_detail
        cats = [
            ("I-MIS  Misdirection",    nl.i_mis_score),
            ("I-EXP  Expansion",       nl.i_exp_score),
            ("I-EXF  Exfiltration",    nl.i_exf_score),
            ("I-CAM  Camouflage",      nl.i_cam_score),
            ("I-PRIV Privilege",       nl.i_priv_score),
        ]
        for name, score in cats:
            if score > 0.1:
                flag = " ⚠" if score > 0.5 else ""
                print(f"  {name:<26}  {_score_bar(score)}{flag}")
        if nl.kill_chain_detected:
            print(f"\n  ⛓  KILL CHAIN DETECTED: {nl.kill_chain_description[:80]}")
        for u in nl.flagged_units[:4]:
            print(f"\n  Step {u['step_index']:2d} [{u['category']:6s}] score={u['score']:.2f}")
            print(f"    └─ {u['text'][:80]}")

    # ── Code Threat Detail ────────────────────────────────────────────────────
    if report.code_threat_detail and report.code_threat_detail.top_findings:
        print(f"\n{SEP}")
        print("  CODE THREATS (Module 2)")
        print(SEP)
        ct = report.code_threat_detail
        print(f"  Pattern Score:  {_score_bar(ct.pattern_score)}")
        print(f"  Taint Risk:     {_score_bar(ct.taint_risk)}")
        print(f"  Obfuscation:    {_score_bar(ct.obfusc_score)}")
        print(f"  Analyzability:  {_score_bar(ct.analyzability)}")
        print()
        for f in ct.top_findings[:5]:
            flag = "⚠ " if f["score"] > 0.70 else "△ "
            print(f"  {flag}[{f['score']:.2f}] {f['description'][:72]}")

    # ── CMIA Detail ───────────────────────────────────────────────────────────
    if report.cmia_detail and (report.cmia_detail.overall > 0.1 or report.cmia_detail.capability_gaps):
        print(f"\n{SEP}")
        print("  CROSS-MODAL ALIGNMENT (Module 3)")
        print(SEP)
        cm = report.cmia_detail
        print(f"  CMIA Overall:   {_score_bar(cm.overall)}")
        print(f"  Over-Reach:     {_score_bar(cm.over_reach_score)}")
        print(f"  Alignment:      {_score_bar(cm.align_score)}")
        print(f"  Misalign edges: {cm.misalign_count}")
        if cm.capability_gaps:
            print("\n  Undeclared capabilities (code exceeds NL declarations):")
            for gap in cm.capability_gaps[:5]:
                print(f"    ⚠ {gap}")

    # ── LLM Panel Detail ──────────────────────────────────────────────────────
    if report.judge_verdicts:
        print(f"\n{SEP}")
        print("  LLM PANEL VERDICTS (Module 4)")
        print(SEP)
        for v in report.judge_verdicts:
            mal_icon = "⚠" if v.is_malicious else "✓"
            print(f"\n  {mal_icon} [{v.judge_role:15s}] "
                  f"risk={v.risk_score:.2f}  conf={v.confidence:.2f}")
            if v.threat_categories:
                print(f"    Categories: {', '.join(v.threat_categories[:3])}")
            if v.reasoning:
                print(f"    Reasoning: {v.reasoning[:120]}")
            for ev in v.evidence[:2]:
                print(f"    Evidence: {ev[:80]}")

    # ── Kill Chains ───────────────────────────────────────────────────────────
    if report.kill_chains:
        print(f"\n{SEP}")
        print("  KILL CHAINS")
        print(SEP)
        for i, chain in enumerate(report.kill_chains, 1):
            sev = _SEV_STYLE.get(chain.severity, chain.severity.value)
            print(f"\n  [{i}] {sev}  {chain.name}")
            print(f"       Strategy: {chain.attack_strategy}")
            for ev in chain.nl_evidence[:2]:
                print(f"       NL:   {ev[:72]}")
            for ev in chain.code_evidence[:2]:
                print(f"       Code: {ev[:72]}")
            if chain.misalign_count:
                print(f"       Misalign edges: {chain.misalign_count}  "
                      f"CMIA contribution: {chain.cmia_contribution:.2f}")

    # ── Errors ────────────────────────────────────────────────────────────────
    if report.error_messages:
        print(f"\n{SEP}")
        print("  WARNINGS / ERRORS")
        print(SEP)
        for err in report.error_messages:
            print(f"  ! {err}")

    # ── Footer ────────────────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"  Scan time: {report.scan_duration_s:.1f}s  |  "
          f"LLM calls: {report.llm_calls_made}  |  "
          f"Skill: {report.skill_dir}")
    print(SEP2 + "\n")


def save_json(report: PRISMReport, output_path: str | Path) -> None:
    """Save the full report as JSON."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report.model_dump(), f, indent=2, default=str)
    print(f"  Report saved → {path}")
