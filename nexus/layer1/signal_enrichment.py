"""
Layer 1C: Signal Enrichment

Uses NL context to re-evaluate code findings:
  - Upgrade: code finding + contract violation = double evidence → severity UP
  - Downgrade: code finding covered by NL declaration → severity DOWN
  - Phantom flag: script not referenced in NL → severity UP
"""
from __future__ import annotations

from nexus.models import (
    CodeFinding,
    CodeSignals,
    ContractBounds,
    EnrichmentAction,
    NLProgram,
    Severity,
    ThreatCategory,
)

# =============================================================================
# Severity manipulation
# =============================================================================

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _upgrade(severity: Severity) -> Severity:
    idx = _SEVERITY_ORDER.index(severity)
    return _SEVERITY_ORDER[min(idx + 1, len(_SEVERITY_ORDER) - 1)]


def _downgrade(severity: Severity) -> Severity:
    idx = _SEVERITY_ORDER.index(severity)
    return _SEVERITY_ORDER[max(idx - 1, 0)]


# =============================================================================
# Categories that can be legitimised by NL declaration
# =============================================================================

_LEGITIMISABLE_CATEGORIES = {
    ThreatCategory.DATA_EXFILTRATION,
    ThreatCategory.COMMAND_INJECTION,
    ThreatCategory.OBFUSCATION,
    ThreatCategory.ENV_HIJACKING,
}

# These are NEVER legitimised by NL
_NEVER_LEGITIMISE = {
    ThreatCategory.PROMPT_INJECTION,
    ThreatCategory.SUPPLY_CHAIN,
    ThreatCategory.PERSISTENCE,
    ThreatCategory.TIME_BOMB,
    ThreatCategory.MALICIOUS_URL,
}

# Categories whose NL coverage should be checked via contract
_CONTRACT_RELEVANT = {
    ThreatCategory.CREDENTIAL_THEFT: "sensitive_access_allowed",
    ThreatCategory.DATA_EXFILTRATION: "network_allowed",
    ThreatCategory.COMMAND_INJECTION: "allowed_subprocesses",
}


# =============================================================================
# Core enrichment
# =============================================================================

def enrich_signals(
    code_signals: CodeSignals,
    nl_program: NLProgram,
    contracts: dict[str, ContractBounds],
) -> tuple[list[CodeFinding], list[EnrichmentAction]]:
    """
    Re-evaluate code findings using NL context.

    Returns:
        enriched_findings: updated finding list
        actions: log of all enrichment actions taken
    """
    actions: list[EnrichmentAction] = []
    nl_scripts = nl_program.scripts_referenced()

    # If NL extraction produced no script links at all (heuristic mode without
    # LLM), phantom upgrades are unreliable — every script would be "phantom".
    # Disable phantom upgrades in this case.
    _has_any_script_link = bool(nl_scripts) or any(
        step.target_script for step in nl_program.steps
    )

    for i, finding in enumerate(code_signals.findings):
        if not finding.file:
            continue

        # Which script does this finding belong to?
        script_path = finding.file
        script_basename = script_path.rsplit("/", 1)[-1] if "/" in script_path else script_path

        # Find the NL step for this script
        nl_step = nl_program.find_step_for_script(script_path)

        # ── Case 1: Phantom Script ──
        # Script exists in skill dir but is NOT referenced by any NL step.
        # Only apply when the NL extractor actually linked at least one script —
        # otherwise all scripts look like phantoms (extraction failure FP).
        if (
            _has_any_script_link
            and nl_step is None
            and script_basename not in ("__init__.py", "setup.py", "conftest.py")
        ):
            # Check if ANY NL step references this script
            is_phantom = script_basename not in nl_scripts and script_path not in nl_scripts
            if is_phantom and finding.severity.value in ("MEDIUM", "HIGH", "CRITICAL"):
                old_sev = finding.severity
                finding.original_severity = old_sev
                finding.severity = _upgrade(finding.severity)
                finding.enriched = True
                finding.enrichment_reason = (
                    f"PHANTOM_SCRIPT: '{script_path}' is not referenced in SKILL.md. "
                    f"Findings in unreferenced scripts are more suspicious."
                )
                actions.append(EnrichmentAction(
                    finding_index=i,
                    action="upgrade",
                    reason=f"Phantom script: {script_path}",
                    old_severity=old_sev,
                    new_severity=finding.severity,
                ))
                continue

        if nl_step is None:
            continue

        # Get contract for this step
        contract = contracts.get(nl_step.step_id)

        # ── Case 2: NL Legitimisation (downgrade) ──
        if finding.category in _LEGITIMISABLE_CATEGORIES and contract is not None:
            is_covered = _is_finding_covered_by_contract(finding, contract, nl_step)
            if is_covered:
                old_sev = finding.severity
                finding.original_severity = old_sev
                finding.severity = _downgrade(finding.severity)
                finding.enriched = True
                finding.enrichment_reason = (
                    f"NL_COVERED: NL step '{nl_step.step_id}' declares '{nl_step.description[:60]}' "
                    f"which covers this operation."
                )
                actions.append(EnrichmentAction(
                    finding_index=i,
                    action="downgrade",
                    reason=f"Covered by NL step {nl_step.step_id}: {nl_step.description[:40]}",
                    old_severity=old_sev,
                    new_severity=finding.severity,
                ))
                continue

        # ── Case 3: Double Evidence (upgrade) ──
        if finding.category in _CONTRACT_RELEVANT and contract is not None:
            is_covered = _is_finding_covered_by_contract(finding, contract, nl_step)
            if not is_covered and finding.category not in _NEVER_LEGITIMISE:
                old_sev = finding.severity
                finding.original_severity = old_sev
                finding.severity = _upgrade(finding.severity)
                finding.enriched = True
                finding.enrichment_reason = (
                    f"DOUBLE_EVIDENCE: Code does '{finding.description[:50]}' which violates "
                    f"NL contract for step '{nl_step.step_id}' ({nl_step.description[:40]})"
                )
                actions.append(EnrichmentAction(
                    finding_index=i,
                    action="upgrade",
                    reason=f"Contract violation + code finding: {finding.category.value}",
                    old_severity=old_sev,
                    new_severity=finding.severity,
                ))
                continue

        # ── Case 4: Never-legitimise categories stay as-is ──
        # PROMPT_INJECTION, SUPPLY_CHAIN, PERSISTENCE, TIME_BOMB are never downgraded

    return code_signals.findings, actions


def _is_finding_covered_by_contract(
    finding: CodeFinding,
    contract: ContractBounds,
    nl_step: NLStep,
) -> bool:
    """Check if a finding's operation is within the contract bounds."""

    cat = finding.category

    if cat == ThreatCategory.DATA_EXFILTRATION:
        return contract.network_allowed

    if cat == ThreatCategory.CREDENTIAL_THEFT:
        return contract.sensitive_access_allowed

    if cat == ThreatCategory.COMMAND_INJECTION:
        if contract.allowed_subprocesses:
            evidence_lower = (finding.evidence or "").lower()
            return any(cmd.lower() in evidence_lower for cmd in contract.allowed_subprocesses)
        return False

    if cat == ThreatCategory.OBFUSCATION:
        # Obfuscation is covered if NL explicitly mentions encoding
        desc_lower = nl_step.description.lower()
        return any(w in desc_lower for w in ("encode", "encrypt", "compress", "obfusc", "base64"))

    if cat == ThreatCategory.ENV_HIJACKING:
        if contract.allowed_env_vars:
            return True
        return False

    return False
