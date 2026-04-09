"""
NEXUS Scanner — Main orchestrator

Runs the three-layer pipeline:
  Layer 0: Foundation (parallel extraction)
    0A: Code Threat Scanner + Script Interface Extractor
    0B: NL Program Extractor
    0C: Manifest Validator
  Layer 1: Cross-Modal Joint Analysis
    1A: Contract Verification
    1B: Cross-Modal Taint Analysis
    1C: Signal Enrichment
  Layer 2: Verdict Fusion
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Type, TypeVar

from pydantic import BaseModel

from nexus.models import (
    CodeSignals,
    ContractResult,
    EnrichmentAction,
    ManifestInfo,
    NEXUSReport,
    NLProgram,
    TaintResult,
)

T = TypeVar("T", bound=BaseModel)


def scan_skill(
    skill_dir: str,
    use_llm: bool = True,
    model: str | None = None,
    quiet: bool = False,
) -> NEXUSReport:
    """
    Run the full NEXUS scan on a skill directory.

    Args:
        skill_dir: path to the skill package directory
        use_llm: whether to use LLM for NL extraction and contract inference
        model: override LLM model name
        quiet: suppress progress output
    """
    start = time.time()
    llm_calls = 0
    errors: list[str] = []

    # Resolve skill name
    skill_path = Path(skill_dir).resolve()
    skill_name = skill_path.name

    def _log(msg: str) -> None:
        if not quiet:
            print(f"  [NEXUS] {msg}")

    # ── Set up LLM client ──
    llm_call = None
    if use_llm:
        try:
            from nexus.llm_client import chat_structured, set_model_override
            if model:
                set_model_override(model)

            def llm_call(messages, response_model):
                nonlocal llm_calls
                llm_calls += 1
                return chat_structured(messages, response_model)
        except ImportError:
            errors.append("OpenAI package not available; running without LLM")
            use_llm = False

    # =====================================================================
    # Layer 0: Foundation (extraction)
    # =====================================================================
    _log("Layer 0: Extracting foundations...")

    # 0A: Code Scanner
    _log("  0A: Scanning code...")
    from nexus.layer0.code_scanner import scan_code
    code_signals: CodeSignals = scan_code(str(skill_path))
    _log(f"      {len(code_signals.findings)} findings, {len(code_signals.script_interfaces)} scripts analyzed")

    # 0B: NL Program Extractor
    _log("  0B: Extracting NL program...")
    from nexus.layer0.nl_extractor import extract_nl_program
    try:
        nl_program: NLProgram = extract_nl_program(str(skill_path), llm_call=llm_call)
    except Exception as e:
        errors.append(f"NL extraction error: {e}")
        nl_program = NLProgram()
        # Fallback to heuristic
        try:
            from nexus.layer0.nl_extractor import extract_nl_program_heuristic
            skill_md = skill_path / "SKILL.md"
            if skill_md.exists():
                content = skill_md.read_text(encoding="utf-8", errors="replace")
                nl_program = extract_nl_program_heuristic(content)
                nl_program.skill_name = skill_name
        except Exception:
            pass
    _log(f"      Purpose: {nl_program.declared_purpose[:60]}...")
    _log(f"      {len(nl_program.steps)} steps, scripts referenced: {nl_program.scripts_referenced()}")

    # 0C: Manifest Validator
    _log("  0C: Validating manifest...")
    from nexus.layer0.manifest_validator import validate_manifest
    manifest: ManifestInfo = validate_manifest(str(skill_path))
    # Merge manifest findings into code_signals
    code_signals.findings.extend(manifest.findings)
    _log(f"      {len(manifest.findings)} manifest findings")

    # =====================================================================
    # Layer 1: Cross-Modal Joint Analysis
    # =====================================================================
    _log("Layer 1: Cross-modal analysis...")

    # 1A: Contract Verification
    _log("  1A: Verifying contracts...")
    from nexus.layer1.contract_verifier import (
        infer_contracts_llm,
        verify_contracts,
    )
    from nexus.layer1.contract_verifier import _infer_contract_heuristic

    contracts: dict = {}
    if use_llm and llm_call is not None:
        try:
            contracts = infer_contracts_llm(nl_program, manifest, llm_call)
        except Exception as e:
            errors.append(f"Contract inference LLM error: {e}")
    # Fill in missing contracts with heuristics
    for step in nl_program.steps:
        if step.target_script and step.step_id not in contracts:
            contracts[step.step_id] = _infer_contract_heuristic(step, manifest)

    contract_result: ContractResult = verify_contracts(nl_program, code_signals, contracts)
    _log(f"      {len(contract_result.violations)} contract violations")

    # 1B: Cross-Modal Taint Analysis
    _log("  1B: Tracking cross-modal taint...")
    from nexus.layer1.taint_tracker import track_cross_modal_taint
    taint_result: TaintResult = track_cross_modal_taint(nl_program, code_signals)
    _log(f"      {len(taint_result.chains)} taint chains detected")

    # 1C: Signal Enrichment
    _log("  1C: Enriching signals...")
    from nexus.layer1.signal_enrichment import enrich_signals
    enriched_findings, enrichment_actions = enrich_signals(
        code_signals, nl_program, contracts,
    )
    upgrades = sum(1 for a in enrichment_actions if a.action == "upgrade")
    downgrades = sum(1 for a in enrichment_actions if a.action == "downgrade")
    _log(f"      {upgrades} upgrades, {downgrades} downgrades")

    # =====================================================================
    # Layer 2: Verdict
    # =====================================================================
    _log("Layer 2: Producing verdict...")
    from nexus.layer2.verdict_engine import produce_verdict
    report = produce_verdict(
        skill_name=skill_name,
        skill_dir=str(skill_path),
        code_signals=code_signals,
        nl_program=nl_program,
        contract_result=contract_result,
        taint_result=taint_result,
        enrichment_actions=enrichment_actions,
        scan_duration=time.time() - start,
        llm_calls=llm_calls,
        errors=errors,
    )

    _log(f"Verdict: {report.verdict.value} (score={report.overall_score:.3f}, confidence={report.confidence:.3f})")
    return report
