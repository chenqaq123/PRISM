"""
NEXUS Scanner — Main orchestrator

Runs the three-layer pipeline:
  Layer 0: Foundation (parallel extraction)
    0A: Code Threat Scanner + Script Interface Extractor
    0B: NL Program Extractor
    0B2: Static Prompt Injection Pre-filter (AV5)
    0C: Manifest Validator
  Layer 1: Cross-Modal Joint Analysis
    1A: Contract Verification
    1B: Cross-Modal Taint Analysis
    1C: Signal Enrichment
    1D: Pipeline Kill-Chain Analysis (AV6)
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
    vt_api_key: str | None = None,
    vt_api_keys: list[str] | None = None,
    vt_wait_seconds: int = 60,
) -> NEXUSReport:
    """
    Run the full NEXUS scan on a skill directory.

    Args:
        skill_dir: path to the skill package directory
        use_llm: whether to use LLM for NL extraction and contract inference
        model: override LLM model name
        quiet: suppress progress output
        vt_api_key: Single VirusTotal API key (backward-compatible).
        vt_api_keys: List of VT API keys for multi-key rotation.
                     Keys are merged with vt_api_key and VT_API_KEYS env var.
                     If none are configured, the VT check is silently skipped.
        vt_wait_seconds: max seconds to wait for each VT analysis to complete
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

    # 0B2: Static Prompt Injection Pre-filter (AV5)
    _log("  0B2: Checking for prompt injection...")
    from nexus.layer0.injection_detector import scan_skill_for_injection
    from nexus.models import CodeFinding, Severity, ThreatCategory
    injection_result = scan_skill_for_injection(str(skill_path))
    if injection_result.is_injection:
        _log(f"      ⚠ INJECTION DETECTED (confidence={injection_result.confidence:.2f})")
        # Inject as a high-severity code finding
        inj_finding = CodeFinding(
            severity=Severity.CRITICAL if injection_result.confidence > 0.7 else Severity.HIGH,
            category=ThreatCategory.PROMPT_INJECTION,
            description=(
                f"Prompt injection detected in SKILL.md "
                f"(confidence={injection_result.confidence:.2f}): "
                + "; ".join(f"{t}/{n}" for t, n in injection_result.detections[:3])
            ),
            file="SKILL.md",
            line=0,
            evidence="; ".join(injection_result.evidence[:3]),
            confidence=injection_result.confidence,
        )
        code_signals.findings.insert(0, inj_finding)
    else:
        _log(f"      No injection detected")

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

    # 1D: Pipeline Kill-Chain Analysis (AV6)
    _log("  1D: Analyzing pipeline attack chains...")
    from nexus.layer1.pipeline_analyzer import analyze_pipeline
    pipeline_result = analyze_pipeline(nl_program, code_signals)
    _log(f"      {len(pipeline_result.chains)} attack chains, pipeline_score={pipeline_result.pipeline_score:.3f}")
    if pipeline_result.chains:
        for chain in pipeline_result.chains[:2]:
            _log(f"        [{chain.severity.value}] {chain.chain_type}: {chain.description[:80]}")

    # 1E: URL Reputation Check (VirusTotal)
    _log("  1E: Checking URL reputation via VirusTotal...")
    from nexus.layer1.url_reputation import check_url_reputation
    url_rep_result = check_url_reputation(
        code_signals,
        api_key=vt_api_key,
        api_keys=vt_api_keys,
        wait_seconds=vt_wait_seconds,
    )
    if url_rep_result.pool_status == [] and not url_rep_result.checked_urls and not url_rep_result.skipped_urls:
        # Pool was empty (no keys configured) — silent skip
        _log("      Skipped (no VT_API_KEY configured)")
    else:
        _log(
            f"      Checked {len(url_rep_result.checked_urls)} URLs, "
            f"skipped {len(url_rep_result.skipped_urls)} trusted, "
            f"{len(url_rep_result.findings)} reputation findings"
        )
        if url_rep_result.findings:
            for rf in url_rep_result.findings[:3]:
                _log(f"        [{rf.severity.value}] {rf.description[:90]}")
        if url_rep_result.errors:
            for err in url_rep_result.errors[:2]:
                _log(f"        [warn] {err}")
                errors.append(f"VT URL check: {err}")
        if url_rep_result.pool_status:
            _log(f"      Key pool: " + ", ".join(
                f"{s['key']} → {s['status']}" for s in url_rep_result.pool_status
            ))
        # Inject VT findings into code_signals for downstream scoring
        code_signals.findings.extend(url_rep_result.findings)

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
        pipeline_result=pipeline_result,
        injection_result=injection_result,
        scan_duration=time.time() - start,
        llm_calls=llm_calls,
        errors=errors,
    )

    _log(f"Verdict: {report.verdict.value} (score={report.overall_score:.3f}, confidence={report.confidence:.3f})")
    return report
