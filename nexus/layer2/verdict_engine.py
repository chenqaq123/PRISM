"""
Layer 2: Evidence-Based Verdict Engine

Assembles evidence chains from all three Layer 1 modules and produces
a final verdict with explainable justification.

Unlike black-box score fusion, every verdict is backed by concrete
evidence chains that auditors can inspect.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from nexus.models import (
    CodeFinding,
    CodeSignals,
    ContractResult,
    ContractViolation,
    EnrichmentAction,
    EvidenceChain,
    NEXUSReport,
    NLProgram,
    Severity,
    TaintChain,
    TaintResult,
    ThreatCategory,
    Verdict,
    ViolationType,
)

# =============================================================================
# Score computation
# =============================================================================

def _sigmoid(x: float, k: float = 7.0, bias: float = 0.5) -> float:
    z = k * (x - bias)
    return 1.0 / (1.0 + math.exp(-z))


def _compute_code_threat_score(findings: list[CodeFinding]) -> float:
    """Score code threats from enriched findings."""
    if not findings:
        return 0.0

    severity_weights = {
        Severity.CRITICAL: 1.0,
        Severity.HIGH: 0.7,
        Severity.MEDIUM: 0.4,
        Severity.LOW: 0.15,
        Severity.INFO: 0.0,
    }

    # Take max severity-weighted score, with count bonus
    max_score = 0.0
    total_weight = 0.0
    for f in findings:
        w = severity_weights.get(f.severity, 0.0)
        max_score = max(max_score, w)
        total_weight += w

    # Count bonus: more findings = higher confidence, but diminishing returns
    count_bonus = min(0.15, len(findings) * 0.02)

    return min(1.0, max_score + count_bonus)


def _compute_contract_score(contract_result: ContractResult) -> float:
    """Score contract violations."""
    if not contract_result.violations:
        return 0.0

    severity_weights = {
        Severity.CRITICAL: 1.0,
        Severity.HIGH: 0.7,
        Severity.MEDIUM: 0.4,
        Severity.LOW: 0.15,
        Severity.INFO: 0.0,
    }

    max_score = 0.0
    for v in contract_result.violations:
        w = severity_weights.get(v.severity, 0.0) * v.confidence
        max_score = max(max_score, w)

    count_bonus = min(0.1, len(contract_result.violations) * 0.03)
    return min(1.0, max_score + count_bonus)


def _compute_taint_score(taint_result: TaintResult) -> float:
    """Score cross-modal taint chains."""
    if not taint_result.chains:
        return 0.0

    severity_weights = {
        Severity.CRITICAL: 1.0,
        Severity.HIGH: 0.8,
        Severity.MEDIUM: 0.5,
        Severity.LOW: 0.2,
        Severity.INFO: 0.0,
    }

    max_score = 0.0
    for chain in taint_result.chains:
        w = severity_weights.get(chain.severity, 0.0)
        # Chains crossing multiple scripts are more suspicious
        cross_script_bonus = min(0.15, (len(chain.scripts_involved) - 1) * 0.1)
        # Undeclared chains are more suspicious
        undeclared_bonus = 0.1 if not chain.declared_in_nl else 0.0
        score = w + cross_script_bonus + undeclared_bonus
        max_score = max(max_score, score)

    return min(1.0, max_score)


def _compute_nl_threat_score(
    nl_program: NLProgram,
    phantom_scripts: list[str],
    code_signals: CodeSignals,
) -> float:
    """Score NL-layer threats (phantom scripts, prompt injection in NL)."""
    score = 0.0

    # Phantom scripts
    if phantom_scripts:
        score += min(0.5, len(phantom_scripts) * 0.2)

    # Check if any findings are prompt injection in SKILL.md
    for f in code_signals.findings:
        if f.category == ThreatCategory.PROMPT_INJECTION and "SKILL.md" in f.file:
            score += 0.4

    return min(1.0, score)


# =============================================================================
# Phantom script detection
# =============================================================================

def _detect_phantom_scripts(
    nl_program: NLProgram,
    code_signals: CodeSignals,
) -> list[str]:
    """
    Find scripts in the skill directory that are NOT referenced by any NL step.
    These are suspicious: why include a script if the NL doesn't mention it?
    """
    nl_scripts = nl_program.scripts_referenced()
    phantoms: list[str] = []

    # Files that are commonly non-suspicious
    safe_names = {
        "__init__.py", "setup.py", "conftest.py", "pytest.ini",
        "requirements.txt", "pyproject.toml", "setup.cfg",
    }

    for script_path in code_signals.all_scripts:
        basename = script_path.rsplit("/", 1)[-1] if "/" in script_path else script_path
        if basename in safe_names:
            continue
        if basename in nl_scripts or script_path in nl_scripts:
            continue
        # Check if any NL step description mentions this script
        mentioned = any(
            basename in step.description or script_path in step.description
            for step in nl_program.steps
        )
        if not mentioned:
            phantoms.append(script_path)

    return phantoms


# =============================================================================
# Evidence chain assembly
# =============================================================================

def _build_evidence_chains(
    findings: list[CodeFinding],
    contract_result: ContractResult,
    taint_result: TaintResult,
    phantom_scripts: list[str],
    enrichment_actions: list[EnrichmentAction],
) -> list[EvidenceChain]:
    """Assemble all signals into structured evidence chains."""
    chains: list[EvidenceChain] = []

    # ── 1. Contract violations → evidence ──
    for v in contract_result.violations:
        chains.append(EvidenceChain(
            chain_type="contract_violation",
            severity=v.severity,
            title=f"Contract Violation: {v.violation_type.value}",
            description=v.description,
            nl_step=v.nl_step_id,
            script=v.script,
            justification=f"Expected: {v.expected}. Actual: {v.actual}",
        ))

    # ── 2. Taint chains → evidence ──
    for tc in taint_result.chains:
        chains.append(EvidenceChain(
            chain_type="taint_chain",
            severity=tc.severity,
            title=f"Cross-Script Data Flow: {tc.source.label.value}",
            description=tc.description,
            nl_step=tc.source.origin_step_id,
            script=tc.sink.dest_script,
            taint_path=[tc.source.detail] + tc.scripts_involved + [tc.sink.detail],
            justification=(
                f"Sensitive data ({tc.source.label.value}) flows from "
                f"{tc.source.origin_script} to {tc.sink.dest_script} via NL pipeline. "
                + ("This flow is declared in NL." if tc.declared_in_nl else "This flow is NOT declared in NL.")
            ),
        ))

    # ── 3. High-severity code findings → evidence ──
    for f in findings:
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            chains.append(EvidenceChain(
                chain_type="code_finding",
                severity=f.severity,
                title=f"Code Threat: {f.category.value}",
                description=f.description,
                script=f.file,
                justification=f.enrichment_reason if f.enriched else f"Static analysis detection (confidence={f.confidence})",
            ))

    # ── 4. Phantom scripts → evidence ──
    for ps in phantom_scripts:
        chains.append(EvidenceChain(
            chain_type="phantom_script",
            severity=Severity.MEDIUM,
            title=f"Phantom Script: {ps}",
            description=f"Script '{ps}' exists in skill directory but is not referenced in SKILL.md",
            script=ps,
            justification="Unreferenced scripts may contain hidden functionality not visible to the user via SKILL.md",
        ))

    # Sort by severity
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    chains.sort(key=lambda c: severity_order.get(c.severity, 5))

    return chains


# =============================================================================
# Verdict decision
# =============================================================================

_VERDICT_THRESHOLDS = {
    "block": 0.85,
    "review": 0.65,
    "warn": 0.35,
}


def _decide_verdict(
    overall_score: float,
    evidence_chains: list[EvidenceChain],
    taint_result: TaintResult,
    contract_result: ContractResult,
) -> tuple[Verdict, float]:
    """
    Decide final verdict from overall score and evidence.

    Returns (verdict, confidence).
    """
    # Hard rules: certain evidence patterns force specific verdicts
    has_critical_evidence = any(e.severity == Severity.CRITICAL for e in evidence_chains)
    has_undeclared_exfil = taint_result.has_exfiltration
    has_critical_contract = contract_result.has_critical

    # Rule 1: Any undeclared exfiltration chain → at least REVIEW
    if has_undeclared_exfil:
        overall_score = max(overall_score, _VERDICT_THRESHOLDS["review"] + 0.05)

    # Rule 2: Critical contract violation → at least REVIEW
    if has_critical_contract:
        overall_score = max(overall_score, _VERDICT_THRESHOLDS["review"] + 0.05)

    # Rule 3: Multiple critical evidence → BLOCK
    critical_count = sum(1 for e in evidence_chains if e.severity == Severity.CRITICAL)
    if critical_count >= 2:
        overall_score = max(overall_score, _VERDICT_THRESHOLDS["block"] + 0.05)

    # Score → verdict
    if overall_score >= _VERDICT_THRESHOLDS["block"]:
        verdict = Verdict.BLOCK
    elif overall_score >= _VERDICT_THRESHOLDS["review"]:
        verdict = Verdict.REVIEW
    elif overall_score >= _VERDICT_THRESHOLDS["warn"]:
        verdict = Verdict.WARN
    else:
        verdict = Verdict.PASS

    # Confidence: higher when signals agree, lower when ambiguous
    if has_critical_evidence and overall_score > _VERDICT_THRESHOLDS["review"]:
        confidence = min(0.95, overall_score + 0.1)
    elif overall_score < 0.2 and not evidence_chains:
        confidence = 0.9  # confidently benign
    else:
        confidence = max(0.5, overall_score)

    return verdict, round(confidence, 3)


# =============================================================================
# Main entry point
# =============================================================================

def produce_verdict(
    skill_name: str,
    skill_dir: str,
    code_signals: CodeSignals,
    nl_program: NLProgram,
    contract_result: ContractResult,
    taint_result: TaintResult,
    enrichment_actions: list[EnrichmentAction],
    scan_duration: float = 0.0,
    llm_calls: int = 0,
    errors: list[str] | None = None,
) -> NEXUSReport:
    """
    Produce the final NEXUS verdict by assembling all evidence.

    This is the Layer 2 orchestrator that:
      1. Detects phantom scripts
      2. Computes component scores
      3. Fuses into overall score
      4. Builds evidence chains
      5. Decides verdict
    """
    # Phantom scripts
    phantom_scripts = _detect_phantom_scripts(nl_program, code_signals)

    # Component scores
    code_score = _compute_code_threat_score(code_signals.findings)
    contract_score = _compute_contract_score(contract_result)
    taint_score = _compute_taint_score(taint_result)
    nl_score = _compute_nl_threat_score(nl_program, phantom_scripts, code_signals)

    # Fusion: max-of-pathways (any single strong signal triggers)
    # Plus a combined pathway with interaction term
    combined = (
        0.30 * contract_score
        + 0.25 * code_score
        + 0.25 * taint_score
        + 0.10 * nl_score
        + 0.10 * min(1.0, contract_score * code_score * 3)  # interaction: contract+code together
    )
    overall = max(code_score, contract_score, taint_score, nl_score, combined)
    overall = round(min(1.0, overall), 3)

    # Evidence chains
    evidence_chains = _build_evidence_chains(
        code_signals.findings,
        contract_result,
        taint_result,
        phantom_scripts,
        enrichment_actions,
    )

    # Verdict
    verdict, confidence = _decide_verdict(
        overall, evidence_chains, taint_result, contract_result,
    )

    # Capabilities summary
    nl_caps: dict = {}
    if nl_program.steps:
        nl_caps = {
            "purpose": nl_program.declared_purpose,
            "step_count": len(nl_program.steps),
            "scripts_referenced": list(nl_program.scripts_referenced()),
        }

    code_caps: dict = {}
    if code_signals.script_interfaces:
        all_reads = []
        all_writes = []
        all_network = []
        for iface in code_signals.script_interfaces.values():
            all_reads.extend(iface.sensitive_reads)
            all_network.extend(se.detail for se in iface.side_effects if se.effect_type == "network_request")
        code_caps = {
            "scripts_found": len(code_signals.all_scripts),
            "sensitive_reads": list(set(all_reads)),
            "network_destinations": list(set(all_network)),
            "has_obfuscation": code_signals.has_obfuscation,
            "has_dynamic_execution": code_signals.has_dynamic_execution,
            "overall_analyzability": round(code_signals.overall_analyzability, 2),
        }

    return NEXUSReport(
        skill_name=skill_name,
        skill_dir=skill_dir,
        verdict=verdict,
        confidence=confidence,
        evidence_chains=evidence_chains,
        code_findings_count=len(code_signals.findings),
        contract_violations_count=len(contract_result.violations),
        taint_chains_count=len(taint_result.chains),
        phantom_scripts=phantom_scripts,
        code_threat_score=round(code_score, 3),
        contract_violation_score=round(contract_score, 3),
        taint_score=round(taint_score, 3),
        nl_threat_score=round(nl_score, 3),
        overall_score=overall,
        nl_declared_capabilities=nl_caps,
        code_actual_capabilities=code_caps,
        scan_duration_s=scan_duration,
        llm_calls_made=llm_calls,
        errors=errors or [],
    )
