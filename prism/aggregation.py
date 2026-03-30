"""
Risk Score Fusion + Kill Chain Group Generation.

Score fusion strategy: weighted sigmoid
─────────────────────────────────────────────────────────────────────────────
The previous naive-Bayes (Beta-likelihood) formulation was replaced because:

  1. Conditional-independence assumption is structurally violated in the v5
     pipeline — Phase 2b (NL consistency, s1) is explicitly conditioned on
     Phase 1 outputs (s2, s3), so ∏ P(si|M) double-counts shared information.

  2. All Beta parameters were hand-tuned without a validation set, giving a
     false sense of calibration.

  3. The AV3 structural failure (s1≈0 from clean NL catastrophically
     suppressing the posterior even when s2, s3 are high) required a separate
     hard override — a symptom that the model was wrong.

Replacement: calibrated weighted sigmoid
─────────────────────────────────────────────────────────────────────────────
  raw = w_s3·s3 + w_s2·s2 + w_pl·s_pipeline + w_pk·s_plugin
      + w_int·(s2·s3)           ← interaction: code+misalign both high
      + w_s1·s1   (if > 0)      ← NL bonus only, never penalises
      + w_s4·(s4 - 0.5)·2  (if judges ran and s4 > 0.5)

  p = sigmoid( k · (raw − bias) )

Design properties:
  • CMIA (s3) is the highest-weight primary signal — theoretically grounded,
    obfuscation-invariant, lowest FP rate.
  • NL score (s1) and judge score (s4) are ADDITIVE BONUSES only.
    They cannot pull p downward — AV3 attacks with clean NL (s1≈0)
    are handled naturally without any override.
  • Interaction term s2·s3 captures "code is suspicious AND it diverges from
    the NL description" as a jointly stronger signal.
  • Weights and bias are transparent constants, clearly labelled as
    PENDING CALIBRATION on SkillScan-1K. Once the dataset exists, replace
    with logistic regression coefficients fitted on the validation split.

Calibration targets (verify once SkillScan-1K is available):
  All signals zero (clean benign)  → p ≈ 0.05
  s3=0.5, s2=0.5 (moderate)       → p ≈ 0.40 (WARN boundary)
  s3=0.7, s2=0.6, pl=0.5          → p ≈ 0.72 (REVIEW)
  s3=0.8, s2=0.7, pl=0.8, s4=0.8  → p ≈ 0.93 (BLOCK)
  AV3: s1=0, s3=0.7, s2=0.5, s4=0.75 → p ≈ 0.67 (REVIEW, no override needed)
"""
from __future__ import annotations

import math

from .models import (
    CMIAScore, CodeThreatScore, JudgeVerdict, KillChain,
    NLThreatScore, PRISMReport, Severity, Verdict,
)

# ─────────────────────────────────────────────────────────────────────────────
# Fusion weights — PENDING calibration on SkillScan-1K validation split.
# Replace with logistic-regression coefficients once labelled data is available.
# ─────────────────────────────────────────────────────────────────────────────

# Phase 1 signals (deterministic, always present)
_W_CMIA      = 0.40   # s3: primary signal, obfusc-invariant
_W_CODE      = 0.25   # s2: code threat (pattern + behavioral)
_W_PIPELINE  = 0.15   # s_pipeline: multi-step graph chains
_W_PLUGIN    = 0.05   # s_plugin: supporting evidence
_W_INTERACT  = 0.10   # s2 × s3: joint code+misalign signal

# Phase 2 signals (additive bonuses — only contribute when positive)
_W_NL        = 0.10   # s1: NL consistency (Phase 2b), bonus only
_W_JUDGES    = 0.15   # s4: judge consensus above neutral (Phase 2c)

# Sigmoid parameters
_K    = 7.0    # steepness
_BIAS = 0.40   # decision-boundary raw score → p = 0.50 at raw = BIAS


def fuse_scores(
    s2:         float,
    s3:         float,
    s_pipeline: float,
    s_plugin:   float,
    s1:         float = 0.0,   # NL threat (Phase 2b); 0 if Phase 2 was skipped
    s4:         float | None = None,  # judge consensus; None if Phase 2 skipped
) -> float:
    """
    Compute P(malicious) via calibrated weighted sigmoid fusion.

    s1 is treated as an additive bonus (never penalises).
    s4 only contributes when judges ran (s4 is not None) and agree malicious.
    """
    # Phase 1 core
    raw = (
        _W_CMIA     * s3
      + _W_CODE     * s2
      + _W_PIPELINE * s_pipeline
      + _W_PLUGIN   * s_plugin
      + _W_INTERACT * s2 * s3
    )

    # Phase 2 additive bonuses
    if s1 > 0.0:
        raw += _W_NL * s1

    if s4 is not None and s4 > 0.5:
        # Normalise to [0, 1] range above neutral: (s4 - 0.5) * 2
        raw += _W_JUDGES * (s4 - 0.5) * 2.0

    return round(1.0 / (1.0 + math.exp(-_K * (raw - _BIAS))), 4)


def score_to_verdict(p_malicious: float) -> Verdict:
    if p_malicious > 0.90: return Verdict.BLOCK
    if p_malicious > 0.70: return Verdict.REVIEW
    if p_malicious > 0.40: return Verdict.WARN
    return Verdict.PASS


# ─────────────────────────────────────────────────────────────────────────────
# Kill chain generation
# ─────────────────────────────────────────────────────────────────────────────

def _judge_consensus_score(verdicts: list[JudgeVerdict]) -> float:
    """Weighted consensus of three judges."""
    if not verdicts:
        return 0.5
    # Weight by confidence: higher-confidence judges get more weight
    total_weight = sum(v.confidence for v in verdicts)
    if total_weight == 0:
        return sum(v.risk_score for v in verdicts) / len(verdicts)
    return sum(v.risk_score * v.confidence for v in verdicts) / total_weight


def extract_kill_chains(
    nl_score:   NLThreatScore,
    code_score: CodeThreatScore,
    cmia_score: CMIAScore,
    verdicts:   list[JudgeVerdict],
    p_malicious: float,
) -> list[KillChain]:
    """Build kill chain descriptions from multi-module evidence."""
    chains: list[KillChain] = []

    # ── Chain 1: NL-directed + code-exfiltration ──────────────────────────────
    nl_exf_evidence = [u for u in nl_score.flagged_units if u["category"] in ("I-EXF", "I-EXP")]
    code_net_evidence = [f for f in code_score.top_findings if "external" in f["description"].lower()
                         or "http" in f["description"].lower()]
    if nl_exf_evidence and code_net_evidence and cmia_score.overall > 0.35:
        sev = Severity.CRITICAL if p_malicious > 0.85 else Severity.HIGH
        chains.append(KillChain(
            name="NL-Directed Data Exfiltration Chain",
            severity=sev,
            nl_evidence=[
                f"Step {u['step_index']} ({u['category']}): {u['text'][:60]}"
                for u in nl_exf_evidence[:3]
            ],
            code_evidence=[f["description"][:80] for f in code_net_evidence[:3]],
            misalign_count=cmia_score.misalign_count,
            cmia_contribution=cmia_score.overall,
            attack_strategy="AV3 (Semantic Camouflage + NL Exfiltration Instruction)",
        ))

    # ── Chain 2: Credential access ────────────────────────────────────────────
    cred_code_evidence = [
        f for f in code_score.top_findings
        if "sensitive" in f["description"].lower() or "ssh" in f["description"].lower()
        or "credential" in f["description"].lower() or "aws" in f["description"].lower()
    ]
    if cred_code_evidence and p_malicious > 0.45:
        sev = Severity.CRITICAL if any(f["score"] > 0.80 for f in cred_code_evidence) else Severity.HIGH
        nl_ev = []
        if nl_score.flagged_units:
            nl_ev = [f"Step {u['step_index']}: {u['text'][:60]}" for u in nl_score.flagged_units[:2]]
        chains.append(KillChain(
            name="Credential Theft",
            severity=sev,
            nl_evidence=nl_ev,
            code_evidence=[f["description"][:80] for f in cred_code_evidence[:3]],
            misalign_count=cmia_score.misalign_count,
            cmia_contribution=cmia_score.over_reach_score,
            attack_strategy="T1-CredentialTheft / AV-Code",
        ))

    # ── Chain 3: Code obfuscation + execution ────────────────────────────────
    obfusc_evidence = [
        f for f in code_score.top_findings
        if any(k in f["description"].lower()
               for k in ("obfuscat", "base64", "eval", "exec", "entropy", "encoded"))
    ]
    if code_score.obfusc_score > 0.40 and obfusc_evidence:
        chains.append(KillChain(
            name="Obfuscated Code Execution",
            severity=Severity.HIGH,
            nl_evidence=[],
            code_evidence=[f["description"][:80] for f in obfusc_evidence[:3]],
            misalign_count=cmia_score.misalign_count,
            cmia_contribution=code_score.obfusc_score,
            attack_strategy="AV1 (Code Obfuscation) / T5-RCE",
        ))

    # ── Chain 4: NL kill chain (sequence of steps) ────────────────────────────
    if nl_score.kill_chain_detected and nl_score.kill_chain_description:
        chains.append(KillChain(
            name="Multi-Step NL Instruction Kill Chain",
            severity=Severity.HIGH,
            nl_evidence=[nl_score.kill_chain_description[:200]],
            code_evidence=[],
            misalign_count=0,
            cmia_contribution=nl_score.overall,
            attack_strategy="AV2 (NL Instruction Injection)",
        ))

    # ── LLM judge evidence ────────────────────────────────────────────────────
    for v in verdicts:
        if v.is_malicious and v.evidence:
            # Check if this evidence overlaps with existing chains
            existing_evidence = {e for c in chains for e in c.code_evidence + c.nl_evidence}
            new_evidence = [e for e in v.evidence if e not in existing_evidence]
            if new_evidence and not any(
                tc in ("T1-CredentialTheft", "T3-DataExfiltration")
                for tc in v.threat_categories
            ):
                chains.append(KillChain(
                    name=f"LLM-Detected: {', '.join(v.threat_categories[:2]) or 'Unknown Threat'}",
                    severity=Severity.HIGH if v.risk_score > 0.75 else Severity.MEDIUM,
                    nl_evidence=[],
                    code_evidence=new_evidence[:3],
                    misalign_count=0,
                    cmia_contribution=v.risk_score,
                    attack_strategy=f"Detected by {v.judge_role} judge",
                ))

    # Deduplicate and sort by severity
    sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    chains.sort(key=lambda c: sev_order.get(c.severity, 9))
    return chains[:6]  # cap at 6 chains


# ─────────────────────────────────────────────────────────────────────────────
# Assemble final report
# ─────────────────────────────────────────────────────────────────────────────

def assemble_report(
    skill_name:    str,
    skill_dir:     str,
    nl_score:      NLThreatScore,
    code_score:    CodeThreatScore,
    cmia_score:    CMIAScore,
    verdicts:      list[JudgeVerdict],
    nl_caps,
    code_caps,
    scan_duration: float,
    llm_calls:     int,
    errors:        list[str],
    injection_detected: bool,
    static_findings: list | None = None,
    pipeline_score: float = 0.0,
    plugin_score: float = 0.0,
) -> PRISMReport:

    s1 = nl_score.overall
    s2 = code_score.overall
    s3 = cmia_score.overall
    # s4: None when Phase 2 was skipped (verdicts=[]) so fusion treats it as absent
    s4 = _judge_consensus_score(verdicts) if verdicts else None

    p_malicious = fuse_scores(
        s2=s2, s3=s3,
        s_pipeline=pipeline_score,
        s_plugin=plugin_score,
        s1=s1,
        s4=s4,
    )
    verdict = score_to_verdict(p_malicious)

    # ── Injection override (phase 0 static detection) ──────────────────────
    # Phase 0 already caused an early-exit BLOCK in scanner.py, but the flag
    # is also stored here for report transparency.  If somehow assemble_report
    # is called with injection_detected=True (e.g. LLM delimiter probe in 2c),
    # we floor p to 0.97.
    if injection_detected:
        p_malicious = max(p_malicious, 0.97)
        verdict     = score_to_verdict(p_malicious)
        errors.append("⚠ INJECTION DETECTED — p_malicious floored to 0.97")

    kill_chains = extract_kill_chains(nl_score, code_score, cmia_score, verdicts, p_malicious)

    return PRISMReport(
        skill_name=skill_name,
        skill_dir=skill_dir,
        verdict=verdict,
        confidence=round(max(abs(p_malicious - 0.5) * 2, 0.1), 2),
        s1_nl_threat=round(s1, 3),
        s2_code_threat=round(s2, 3),
        s3_cmia=round(s3, 3),
        s4_llm_panel=round(s4, 3),
        s_pipeline=round(pipeline_score, 3),
        s_plugins=round(plugin_score, 3),
        p_malicious=p_malicious,
        phase0_injection=injection_detected,
        static_findings=static_findings or [],
        nl_threat_detail=nl_score,
        code_threat_detail=code_score,
        cmia_detail=cmia_score,
        judge_verdicts=verdicts,
        kill_chains=kill_chains,
        nl_capabilities=nl_caps,
        code_capabilities=code_caps,
        scan_duration_s=round(scan_duration, 1),
        llm_calls_made=llm_calls,
        error_messages=errors,
    )
