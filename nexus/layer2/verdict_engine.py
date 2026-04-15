"""
Layer 2: Evidence-Based Verdict Engine

Assembles evidence chains from all Layer 1 modules and produces
a final verdict with explainable justification.

Scoring architecture (PRISM-aligned):
  p_code     - code threat score (T1-T9 static patterns)
  p_align    - NL-code misalignment (CMIA over-reach score)
  p_pipeline - pipeline-level kill chain score (AV6)
  p_nl       - NL-layer threats (phantom scripts, prompt injection)
  p_combined - composite score with interaction term

Final: p = max(p_code, p_align, p_pipeline, p_nl, p_combined)
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING

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

if TYPE_CHECKING:
    from nexus.layer0.injection_detector import InjectionDetectionResult
    from nexus.layer1.pipeline_analyzer import PipelineAnalysisResult


# =============================================================================
# Sigmoid helper
# =============================================================================

def _sigmoid(x: float, k: float = 7.0, bias: float = 0.5) -> float:
    z = k * (x - bias)
    return 1.0 / (1.0 + math.exp(-z))


# =============================================================================
# Component score computation
# =============================================================================

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

    max_score = 0.0
    total_weight = 0.0
    for f in findings:
        w = severity_weights.get(f.severity, 0.0)
        max_score = max(max_score, w)
        total_weight += w

    # Count bonus: more findings = higher confidence, but diminishing returns
    count_bonus = min(0.15, len(findings) * 0.02)

    raw = max_score + count_bonus
    return round(min(1.0, _sigmoid(raw, k=6.0, bias=0.55)), 3)


def _compute_contract_score(contract_result: ContractResult) -> float:
    """Score contract violations (NL-code misalignment / CMIA)."""
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
    raw = max_score + count_bonus
    return round(min(1.0, _sigmoid(raw, k=6.0, bias=0.55)), 3)


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

    return round(min(1.0, max_score), 3)


def _compute_pipeline_score(pipeline_result) -> float:
    """Score pipeline-level kill chain analysis (AV6)."""
    if pipeline_result is None:
        return 0.0
    return round(min(1.0, pipeline_result.pipeline_score), 3)


def _compute_nl_threat_score(
    nl_program: NLProgram,
    phantom_scripts: list[str],
    code_signals: CodeSignals,
    injection_result=None,
) -> float:
    """Score NL-layer threats: phantom scripts, prompt injection."""
    score = 0.0

    # Phantom scripts
    if phantom_scripts:
        score += min(0.5, len(phantom_scripts) * 0.2)

    # Check if any findings are prompt injection in SKILL.md
    for f in code_signals.findings:
        if f.category == ThreatCategory.PROMPT_INJECTION and "SKILL.md" in f.file:
            score += 0.5
            break

    # Injection detector result
    if injection_result is not None and injection_result.is_injection:
        score += min(0.5, injection_result.confidence * 0.8)

    return round(min(1.0, score), 3)


def _compute_cmia_score(
    nl_program: NLProgram,
    code_signals: CodeSignals,
) -> float:
    """
    Cross-Modal Intent Alignment (CMIA) over-reach score.

    Measures how much the code does BEYOND what the NL declares.

    Formula (PRISM §3):
      over_reach = len(C - N) / max(len(C), 1)
      align      = len(C & N) / max(len(C | N), 1)
      CMIA       = 0.6 * over_reach + 0.4 * (1 - align)
    """
    if not code_signals.script_interfaces:
        return 0.0

    # Build NL-declared capability set (N)
    nl_caps: set[str] = set()
    for step in nl_program.steps:
        desc_lower = step.description.lower()
        if any(w in desc_lower for w in ("network", "send", "post", "upload", "fetch", "download", "api", "http")):
            nl_caps.add("network")
        if any(w in desc_lower for w in ("credential", "secret", "ssh", "token", "key", "password", ".env")):
            nl_caps.add("credential")
        if any(w in desc_lower for w in ("subprocess", "execute", "run", "shell", "command", "cmd")):
            nl_caps.add("subprocess")
        if any(w in desc_lower for w in ("write", "save", "create", "modify", "format", "edit")):
            nl_caps.add("file_write")
        if any(w in desc_lower for w in ("read", "scan", "find", "list", "collect")):
            nl_caps.add("file_read")

    # Build code-level capability set (C)
    code_caps: set[str] = set()
    for iface in code_signals.script_interfaces.values():
        for se in iface.side_effects:
            if se.effect_type == "network_request":
                code_caps.add("network")
            elif se.effect_type == "subprocess":
                code_caps.add("subprocess")
            elif se.effect_type in ("file_write",):
                code_caps.add("file_write")
        if iface.sensitive_reads:
            code_caps.add("credential")
        if iface.inputs:
            code_caps.add("file_read")
        if iface.has_dynamic_execution:
            code_caps.add("dynamic_exec")
        if iface.has_obfuscation:
            code_caps.add("obfuscation")

    # Compute CMIA
    if not code_caps:
        return 0.0

    # If NL extraction found no capability keywords at all (heuristic failure),
    # CMIA cannot be reliably computed — every code capability would look like
    # "over-reach".  Return 0.0 to avoid systematic false positives.
    if not nl_caps and not nl_program.steps:
        return 0.0
    if not nl_caps and not any(step.target_script for step in nl_program.steps):
        # NL steps exist but describe no known capability keywords — extraction
        # likely failed or the skill has non-standard structure.
        return 0.0

    n_c = len(code_caps)
    n_diff = len(code_caps - nl_caps)  # code does more than NL declares
    n_intersect = len(code_caps & nl_caps)
    n_union = len(code_caps | nl_caps)

    over_reach = n_diff / max(n_c, 1)
    align = n_intersect / max(n_union, 1)
    cmia = 0.6 * over_reach + 0.4 * (1.0 - align)

    return round(min(1.0, cmia), 3)


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

    # If NL extraction found no script references at all and no step has a
    # target_script set, it means the heuristic extractor couldn't link scripts
    # to steps (typically happens without LLM).  Flagging every script as a
    # phantom in this case would be a systematic false positive.
    if not nl_scripts:
        has_any_target = any(step.target_script for step in nl_program.steps)
        if not has_any_target:
            return []

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
    pipeline_result=None,
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

    # ── 5. Pipeline attack chains → evidence ──
    if pipeline_result is not None:
        for chain in pipeline_result.chains:
            chains.append(EvidenceChain(
                chain_type="pipeline_attack",
                severity=chain.severity,
                title=f"Kill Chain: {chain.chain_type}",
                description=chain.description,
                taint_path=chain.scripts_involved,
                justification=(
                    f"Multi-stage attack chain detected: "
                    + ", ".join(s.value for s in chain.stages_detected)
                ),
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
    pipeline_result=None,
) -> tuple[Verdict, float]:
    """
    Decide final verdict from overall score and evidence.

    Hard rules take precedence over score thresholds.
    Returns (verdict, confidence).
    """
    # Hard rules: certain evidence patterns force specific verdicts
    has_undeclared_exfil = taint_result.has_exfiltration
    has_critical_contract = contract_result.has_critical
    has_complete_kill_chain = (
        pipeline_result is not None and pipeline_result.has_complete_kill_chain
    )

    # Rule 1: Any undeclared exfiltration chain → at least REVIEW
    if has_undeclared_exfil:
        overall_score = max(overall_score, _VERDICT_THRESHOLDS["review"] + 0.05)

    # Rule 2: Critical contract violation → at least REVIEW
    if has_critical_contract:
        overall_score = max(overall_score, _VERDICT_THRESHOLDS["review"] + 0.05)

    # Rule 3: Complete kill chain → at least REVIEW
    if has_complete_kill_chain:
        overall_score = max(overall_score, _VERDICT_THRESHOLDS["review"] + 0.10)

    # Rule 4: Multiple CRITICAL evidence → BLOCK
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

    # Confidence calibration
    has_critical_evidence = any(e.severity == Severity.CRITICAL for e in evidence_chains)
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
    pipeline_result=None,
    injection_result=None,
    scan_duration: float = 0.0,
    llm_calls: int = 0,
    errors: list[str] | None = None,
) -> NEXUSReport:
    """
    Produce the final NEXUS verdict by assembling all evidence.

    Layer 2 orchestrator:
      1. Detect phantom scripts
      2. Compute CMIA over-reach score
      3. Compute all component scores
      4. Fuse into overall score (PRISM multi-pathway max)
      5. Build evidence chains
      6. Decide verdict
    """
    # Phantom scripts
    phantom_scripts = _detect_phantom_scripts(nl_program, code_signals)

    # Component scores
    s_code = _compute_code_threat_score(code_signals.findings)
    s_contract = _compute_contract_score(contract_result)     # CMIA contract violations
    s_taint = _compute_taint_score(taint_result)
    s_pipeline = _compute_pipeline_score(pipeline_result)
    s_nl = _compute_nl_threat_score(nl_program, phantom_scripts, code_signals, injection_result)
    s_cmia = _compute_cmia_score(nl_program, code_signals)    # CMIA over-reach

    # ── PRISM-aligned multi-pathway fusion ──
    # Each pathway can independently trigger: take max of all pathways
    # Plus a combined pathway with interaction terms
    p_code     = _sigmoid(s_code,     k=6.0, bias=0.55)
    p_align    = _sigmoid(max(s_contract, s_cmia), k=6.0, bias=0.55)  # NL-code misalignment
    p_pipeline = _sigmoid(s_pipeline, k=6.0, bias=0.60)
    p_nl       = _sigmoid(s_nl,       k=6.0, bias=0.55)
    p_taint    = _sigmoid(s_taint,    k=6.0, bias=0.50)

    # Combined pathway: weighted sum with interaction term (code × align)
    raw_combined = (
        0.30 * max(s_contract, s_cmia)
        + 0.25 * s_code
        + 0.15 * s_pipeline
        + 0.10 * max(s_contract, s_cmia) * s_code  # interaction
        + 0.08 * s_nl
        + 0.12 * s_taint
    )
    p_combined = _sigmoid(raw_combined, k=6.0, bias=0.35)

    overall = max(p_code, p_align, p_pipeline, p_nl, p_taint, p_combined)
    overall = round(min(1.0, overall), 3)

    # Evidence chains
    evidence_chains = _build_evidence_chains(
        code_signals.findings,
        contract_result,
        taint_result,
        phantom_scripts,
        enrichment_actions,
        pipeline_result,
    )

    # Verdict
    verdict, confidence = _decide_verdict(
        overall, evidence_chains, taint_result, contract_result, pipeline_result,
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
            "cmia_over_reach_score": s_cmia,
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
        code_threat_score=s_code,
        contract_violation_score=s_contract,
        taint_score=s_taint,
        nl_threat_score=s_nl,
        overall_score=overall,
        nl_declared_capabilities=nl_caps,
        code_actual_capabilities=code_caps,
        scan_duration_s=scan_duration,
        llm_calls_made=llm_calls,
        errors=errors or [],
    )
