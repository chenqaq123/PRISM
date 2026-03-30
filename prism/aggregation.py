"""
Bayesian Risk Aggregation + Kill Chain Group Generation.

Bayesian fusion:
  P(M=1 | s1,s2,s3,s4) ∝ P(M=1) * ∏ P(si | M=1)

Each module's likelihood is modeled as a Beta distribution calibrated from
domain knowledge (in lieu of a held-out validation set).
"""
from __future__ import annotations

import math
from typing import Optional

from pydantic import BaseModel

from .models import (
    CMIAScore, CodeThreatScore, JudgeVerdict, KillChain,
    NLThreatScore, PRISMReport, Severity, Verdict,
)

# ─────────────────────────────────────────────────────────────────────────────
# Beta distribution likelihood parameters
# ─────────────────────────────────────────────────────────────────────────────
# For each module i, we have Beta(alpha_pos, beta_pos) for malicious skills
# and Beta(alpha_neg, beta_neg) for benign skills.
# Parameters calibrated from domain knowledge:
#   - malicious skills should have HIGH scores → Beta(8,2) (concentrated near 1)
#   - benign skills should have LOW scores    → Beta(2,8) (concentrated near 0)

_BETA_PARAMS = {
    # module: (alpha_pos, beta_pos, alpha_neg, beta_neg)
    # NOTE: m1 uses softer Beta(4,3) for the malicious class (mean≈0.57).
    # Reason: AV3 (Semantic Camouflage) attacks deliberately keep SKILL.md clean,
    # so malicious skills can have s1≈0. A concentrated Beta(7,2) would make
    # s1=0 catastrophically penalise the malicious hypothesis even when code+CMIA
    # signals are strong. This was validated against the evil-formatter test case.
    "m1": (4.0, 3.0, 1.5, 9.0),   # NL threat — softer malicious prior for AV3 tolerance
    "m2": (6.0, 2.5, 2.0, 8.0),   # Code threat — solid but more FP
    "m3": (8.0, 1.5, 1.5, 9.5),   # CMIA — strongest discriminator (obfusc-invariant)
    "m4": (7.5, 2.0, 2.0, 8.5),   # LLM panel — powerful but depends on LLM quality
}

PRIOR_P_MALICIOUS = 0.08   # ~8% of skills are malicious (from Wild Study)


def _beta_log_pdf(x: float, alpha: float, beta: float) -> float:
    """Log of Beta PDF at x (uses log-gamma for numerical stability)."""
    # B(alpha, beta) = Gamma(alpha)*Gamma(beta)/Gamma(alpha+beta)
    # PDF = x^(alpha-1) * (1-x)^(beta-1) / B(alpha, beta)
    x = max(1e-9, min(1 - 1e-9, x))  # clamp to avoid log(0)
    log_norm = math.lgamma(alpha + beta) - math.lgamma(alpha) - math.lgamma(beta)
    return log_norm + (alpha - 1) * math.log(x) + (beta - 1) * math.log(1 - x)


def bayesian_fuse(
    s1: float,
    s2: float,
    s3: float,
    s4: float,
) -> float:
    """
    Compute P(M=1 | s1, s2, s3, s4) via Bayes' theorem.
    Returns posterior probability of maliciousness.
    """
    log_prior_pos = math.log(PRIOR_P_MALICIOUS)
    log_prior_neg = math.log(1.0 - PRIOR_P_MALICIOUS)

    scores = {"m1": s1, "m2": s2, "m3": s3, "m4": s4}

    log_pos = log_prior_pos
    log_neg = log_prior_neg

    for key, score in scores.items():
        ap, bp, an, bn = _BETA_PARAMS[key]
        log_pos += _beta_log_pdf(score, ap, bp)
        log_neg += _beta_log_pdf(score, an, bn)

    # Numerical stability: subtract max before exponentiation
    log_max = max(log_pos, log_neg)
    p_pos = math.exp(log_pos - log_max)
    p_neg = math.exp(log_neg - log_max)

    return round(p_pos / (p_pos + p_neg), 4)


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
) -> PRISMReport:

    s1 = nl_score.overall
    s2 = code_score.overall
    s3 = cmia_score.overall
    s4 = _judge_consensus_score(verdicts)

    p_malicious = bayesian_fuse(s1, s2, s3, s4)
    verdict     = score_to_verdict(p_malicious)

    # ── Hard override: Semantic Camouflage (AV3) ──────────────────────────────
    # When code+CMIA signals are strong but NL is clean (s1≈0), the Bayesian
    # product can underweight the posterior. Apply a floor when:
    #   - At least one LLM judge flagged is_malicious=True
    #   - AND (s2 > 0.3 OR s3 > 0.4)  [code or alignment anomaly]
    # This floor (0.55) forces at least a WARN verdict for these "clean NL" cases.
    judge_flagged = any(v.is_malicious for v in verdicts)
    code_or_cmia_elevated = (s2 > 0.30 or s3 > 0.40)
    if judge_flagged and code_or_cmia_elevated and p_malicious < 0.55:
        p_malicious = max(p_malicious, 0.55)
        verdict     = score_to_verdict(p_malicious)
        errors.append("⚠ AV3 override applied: clean NL + elevated code/CMIA + judge flag")

    # Boost p_malicious if prompt injection was attempted (strong signal itself)
    if injection_detected:
        p_malicious = min(1.0, p_malicious + 0.25)
        verdict     = score_to_verdict(p_malicious)
        errors.append("⚠ PROMPT INJECTION ATTEMPT DETECTED in skill content")

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
        p_malicious=p_malicious,
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
