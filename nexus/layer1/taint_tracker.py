"""
Layer 1B: Cross-Modal Taint Analysis

Tracks sensitive data flow ACROSS scripts through the NL orchestration layer.

Key insight: in Agent Skills, data flows between scripts via the NL program
(stdout→stdin pipes, intermediate files, NL-directed parameter passing).
We don't need full intra-procedural taint analysis — we track at the
pipeline level: what sensitive data ENTERS a script, and what EXITS it.
"""
from __future__ import annotations

import re
from pathlib import Path

from nexus.models import (
    CodeSignals,
    NLProgram,
    NLStep,
    ScriptInterface,
    Severity,
    SinkType,
    TaintChain,
    TaintLabel,
    TaintResult,
    TaintSink,
    TaintSource,
)

# =============================================================================
# Sensitive path → TaintLabel mapping
# =============================================================================

_SENSITIVE_PATH_MAP: list[tuple[re.Pattern, TaintLabel]] = [
    (re.compile(r"\.ssh[/\\](id_rsa|id_ed25519|id_dsa)", re.I), TaintLabel.SSH_KEY),
    (re.compile(r"\.ssh[/\\](authorized_keys|known_hosts|config)", re.I), TaintLabel.SSH_KEY),
    (re.compile(r"\.aws[/\\](credentials|config)", re.I), TaintLabel.AWS_CRED),
    (re.compile(r"\.env\b", re.I), TaintLabel.DOTENV),
    (re.compile(r"\.netrc", re.I), TaintLabel.NETRC),
    (re.compile(r"\.kube[/\\]config", re.I), TaintLabel.GENERIC_CREDENTIAL),
    (re.compile(r"\.docker[/\\]config\.json", re.I), TaintLabel.GENERIC_CREDENTIAL),
    (re.compile(r"\.git-credentials", re.I), TaintLabel.GENERIC_CREDENTIAL),
    (re.compile(r"\.pgpass", re.I), TaintLabel.GENERIC_CREDENTIAL),
    (re.compile(r"(password|secret|token|api.?key|private.?key)", re.I), TaintLabel.GENERIC_CREDENTIAL),
    (re.compile(r"/etc/(passwd|shadow)", re.I), TaintLabel.SENSITIVE_FILE),
]

_ENV_SECRET_RE = re.compile(
    r"(key|token|secret|pass|api|aws|github|openai|anthropic|password|credential)",
    re.IGNORECASE,
)


def _classify_sensitive_path(path: str) -> TaintLabel | None:
    """Map a file path to a taint label, or None if not sensitive."""
    for pattern, label in _SENSITIVE_PATH_MAP:
        if pattern.search(path):
            return label
    return None


def _classify_env_var(var_name: str) -> TaintLabel | None:
    """Map an env var to a taint label if it looks secret-bearing."""
    if var_name.startswith("env:"):
        var_name = var_name[4:]
    if _ENV_SECRET_RE.search(var_name):
        return TaintLabel.ENV_SECRET
    return None


# =============================================================================
# Core taint tracking algorithm
# =============================================================================

def track_cross_modal_taint(
    nl_program: NLProgram,
    code_signals: CodeSignals,
) -> TaintResult:
    """
    Track sensitive data flow across scripts through NL orchestration.

    Algorithm:
      1. For each NL step (in topological/execution order):
         a. Inherit taint from upstream steps (via input_refs or sequential flow)
         b. Seed new taint from the step's script's sensitive_reads
         c. Check if tainted data reaches a network sink
         d. Propagate taint to downstream steps

      2. Conservative approximation:
         - If script analyzability is low (eval/dynamic), assume ALL inputs
           propagate to ALL outputs
         - If script analyzability is high, check if sensitive reads are
           actually connected to outputs (via side-effect type matching)
    """
    result = TaintResult()

    if not nl_program.steps:
        return result

    # Build step map
    step_map = {s.step_id: s for s in nl_program.steps}

    # Taint state per step: step_id -> set of TaintSource objects
    taint_state: dict[str, list[TaintSource]] = {}

    # Process steps in topological order
    for step in nl_program.topological_order():
        current_taints: list[TaintSource] = []

        # ── 1. Inherit taints from upstream ──
        for ref in step.input_refs:
            # ref format: "S1.output.xxx" or "S1.output"
            upstream_id = ref.split(".")[0]
            if upstream_id in taint_state:
                current_taints.extend(taint_state[upstream_id])

        # Also inherit from previous sequential step if no explicit refs
        if not step.input_refs:
            idx = nl_program.steps.index(step) if step in nl_program.steps else -1
            if idx > 0:
                prev_step = nl_program.steps[idx - 1]
                if prev_step.step_id in taint_state:
                    # Only inherit if previous step produces output
                    if prev_step.output_name:
                        current_taints.extend(taint_state[prev_step.step_id])

        # ── 2. Seed new taints from this step's script ──
        iface = _find_interface(step.target_script, code_signals.script_interfaces)
        if iface is not None:
            for sensitive_path in iface.sensitive_reads:
                # Check env vars
                label = _classify_env_var(sensitive_path)
                if label is None:
                    label = _classify_sensitive_path(sensitive_path)
                if label is None:
                    label = TaintLabel.UNKNOWN_SENSITIVE

                source = TaintSource(
                    label=label,
                    origin_script=iface.script_path,
                    origin_step_id=step.step_id,
                    detail=sensitive_path,
                )
                current_taints.append(source)

        # ── 3. Propagate: decide which taints survive through this script ──
        propagated_taints: list[TaintSource] = []

        if iface is not None:
            if iface.analyzability < 0.5:
                # Low analyzability: conservatively assume ALL input taints
                # propagate to ALL outputs
                propagated_taints = list(current_taints)
            else:
                # Higher analyzability: check if script has outputs that could
                # carry the taint forward
                has_output = (
                    any(o.sink_type == SinkType.STDOUT for o in iface.outputs)
                    or any(o.sink_type == SinkType.FILE_WRITE for o in iface.outputs)
                    or step.output_name
                )
                if has_output:
                    propagated_taints = list(current_taints)
                # If script has no outputs, taints die here (data consumed locally)
        else:
            # No interface info — conservative: propagate all
            propagated_taints = list(current_taints)

        # Store propagated state for downstream
        taint_state[step.step_id] = propagated_taints

        # Store in result for inspection
        result.taint_map[step.step_id] = {t.label.value for t in propagated_taints}

        # ── 4. Check for taint reaching dangerous sinks ──
        if iface is not None and current_taints:
            for se in iface.side_effects:
                if se.effect_type == "network_request":
                    for taint in current_taints:
                        # Is this network sink declared in NL?
                        declared = _is_network_declared(step, nl_program)

                        chain = TaintChain(
                            source=taint,
                            sink=TaintSink(
                                sink_type=SinkType.NETWORK_POST if "post" in se.detail.lower() else SinkType.NETWORK_GET,
                                dest_script=iface.script_path,
                                dest_step_id=step.step_id,
                                detail=se.detail,
                            ),
                            path=_reconstruct_path(taint.origin_step_id, step.step_id, nl_program),
                            scripts_involved=_scripts_in_path(
                                taint.origin_step_id, step.step_id, nl_program, code_signals,
                            ),
                            severity=_compute_chain_severity(taint, se),
                            description=(
                                f"Sensitive data ({taint.label.value}: {taint.detail}) "
                                f"originates in {taint.origin_script} (step {taint.origin_step_id}), "
                                f"flows through NL pipeline to {iface.script_path} (step {step.step_id}), "
                                f"then reaches network sink: {se.detail}"
                            ),
                            declared_in_nl=declared,
                        )
                        result.chains.append(chain)

            # Also check file writes to sensitive locations as sinks
            for out in iface.outputs:
                if out.sink_type == SinkType.FILE_WRITE and _is_persistence_target(out.detail):
                    for taint in current_taints:
                        chain = TaintChain(
                            source=taint,
                            sink=TaintSink(
                                sink_type=SinkType.FILE_WRITE,
                                dest_script=iface.script_path,
                                dest_step_id=step.step_id,
                                detail=out.detail,
                            ),
                            path=_reconstruct_path(taint.origin_step_id, step.step_id, nl_program),
                            scripts_involved=_scripts_in_path(
                                taint.origin_step_id, step.step_id, nl_program, code_signals,
                            ),
                            severity=Severity.HIGH,
                            description=(
                                f"Sensitive data ({taint.label.value}: {taint.detail}) "
                                f"flows to persistence target: {out.detail}"
                            ),
                            declared_in_nl=False,
                        )
                        result.chains.append(chain)

    # Deduplicate chains
    result.chains = _deduplicate_chains(result.chains)

    return result


# =============================================================================
# Helpers
# =============================================================================

def _find_interface(
    target_script: str,
    interfaces: dict[str, ScriptInterface],
) -> ScriptInterface | None:
    """Find script interface by name, trying multiple path forms."""
    if not target_script:
        return None
    if target_script in interfaces:
        return interfaces[target_script]
    basename = target_script.rsplit("/", 1)[-1] if "/" in target_script else target_script
    for key, iface in interfaces.items():
        key_base = key.rsplit("/", 1)[-1] if "/" in key else key
        if key_base == basename:
            return iface
    for prefix in ["scripts/", ""]:
        candidate = prefix + basename
        if candidate in interfaces:
            return interfaces[candidate]
    return None


def _is_network_declared(step: NLStep, nl_program: NLProgram) -> bool:
    """Check if this step's NL description mentions network activity."""
    keywords = {"send", "post", "upload", "fetch", "download", "request", "api", "http", "webhook", "endpoint", "url", "remote"}
    desc_words = set(step.description.lower().split())
    if desc_words & keywords:
        return True
    # Also check skill purpose
    purpose_words = set(nl_program.declared_purpose.lower().split())
    return bool(purpose_words & keywords)


def _is_persistence_target(path: str) -> bool:
    """Check if a file write target is a persistence mechanism."""
    patterns = [".bashrc", ".bash_profile", ".zshrc", ".profile", "crontab", "plist", "autostart"]
    path_lower = path.lower()
    return any(p in path_lower for p in patterns)


def _reconstruct_path(from_step: str, to_step: str, nl_program: NLProgram) -> list[str]:
    """Reconstruct the step path from source to sink."""
    steps = nl_program.topological_order()
    path: list[str] = []
    recording = False
    for s in steps:
        if s.step_id == from_step:
            recording = True
        if recording:
            path.append(s.step_id)
        if s.step_id == to_step:
            break
    if not path:
        path = [from_step, to_step]
    return path


def _scripts_in_path(
    from_step: str,
    to_step: str,
    nl_program: NLProgram,
    code_signals: CodeSignals,
) -> list[str]:
    """Collect all scripts involved in the taint path."""
    step_ids = _reconstruct_path(from_step, to_step, nl_program)
    step_map = {s.step_id: s for s in nl_program.steps}
    scripts = []
    for sid in step_ids:
        step = step_map.get(sid)
        if step and step.target_script:
            scripts.append(step.target_script)
    return scripts


def _compute_chain_severity(source: TaintSource, side_effect) -> Severity:
    """Compute severity based on what data is being exfiltrated."""
    high_value = {TaintLabel.SSH_KEY, TaintLabel.AWS_CRED, TaintLabel.GENERIC_CREDENTIAL}
    if source.label in high_value:
        return Severity.CRITICAL
    if source.label in (TaintLabel.DOTENV, TaintLabel.ENV_SECRET):
        return Severity.HIGH
    return Severity.HIGH


def _deduplicate_chains(chains: list[TaintChain]) -> list[TaintChain]:
    """Remove duplicate chains (same source label + same sink)."""
    seen: set[str] = set()
    unique: list[TaintChain] = []
    for chain in chains:
        key = f"{chain.source.label}:{chain.source.detail}:{chain.sink.detail}:{chain.sink.dest_script}"
        if key not in seen:
            seen.add(key)
            unique.append(chain)
    return unique
