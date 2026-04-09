"""
Layer 1A: Semantic Contract Verification

Each NL step's declaration is treated as a contract (preconditions / postconditions / allowed side-effects).
This module verifies that each script's actual behaviour stays within the contract bounds.
"""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from nexus.models import (
    CodeSignals,
    ContractBounds,
    ContractResult,
    ContractViolation,
    ManifestInfo,
    NLProgram,
    NLStep,
    ScriptInterface,
    Severity,
    ViolationType,
)

# =============================================================================
# LLM-based contract inference
# =============================================================================

_CONTRACT_SYSTEM_PROMPT = """\
You are a security analyst. Given a natural language step description from an AI Agent Skill,
infer what the corresponding script is ALLOWED to do.

Be CONSERVATIVE: only allow operations that are clearly implied by the description.
If the description says "format Python files in project directory", the script should NOT
access ~/.ssh, make network requests, or run arbitrary commands beyond the formatter.

Return a ContractBounds object specifying exactly what is permitted.
"""

_CONTRACT_USER_TEMPLATE = """\
NL Step: "{step_description}"
Target Script: {target_script}
Skill Purpose: {skill_purpose}
Declared Permissions: {permissions}

Based on this NL description, what should the script be allowed to do?
Be conservative — only allow what the description clearly implies.
"""


def infer_contracts_llm(
    nl_program: NLProgram,
    manifest: ManifestInfo,
    llm_call: callable,
) -> dict[str, ContractBounds]:
    """
    Use LLM to infer contract bounds for each NL step that references a script.

    Returns: {step_id: ContractBounds}
    """
    contracts: dict[str, ContractBounds] = {}
    perm_str = str(manifest.permissions) if manifest.permissions else "none declared"

    for step in nl_program.steps:
        if not step.target_script:
            continue

        messages = [
            {"role": "system", "content": _CONTRACT_SYSTEM_PROMPT},
            {"role": "user", "content": _CONTRACT_USER_TEMPLATE.format(
                step_description=step.description,
                target_script=step.target_script,
                skill_purpose=nl_program.declared_purpose,
                permissions=perm_str,
            )},
        ]

        try:
            bounds: ContractBounds = llm_call(messages, ContractBounds)
            contracts[step.step_id] = bounds
        except Exception:
            # Fallback to heuristic
            contracts[step.step_id] = _infer_contract_heuristic(step, manifest)

    return contracts


# =============================================================================
# Heuristic contract inference (no LLM)
# =============================================================================

_NETWORK_KEYWORDS = {
    "download", "upload", "fetch", "send", "post", "request",
    "api", "http", "webhook", "endpoint", "url", "server",
    "remote", "cloud", "deploy", "ping", "telemetry", "analytics",
}

_FILE_WRITE_KEYWORDS = {
    "write", "save", "create", "generate", "output", "modify",
    "format", "edit", "update", "transform", "build", "compile",
}

_SUBPROCESS_KEYWORDS = {
    "run", "execute", "invoke", "call", "command", "cmd",
    "install", "build", "compile", "deploy", "lint", "test",
}

_SENSITIVE_KEYWORDS = {
    "ssh", "credential", "secret", "key", "token", "password",
    "auth", "certificate", "private", "gpg", "pgp",
}


def _infer_contract_heuristic(step: NLStep, manifest: ManifestInfo) -> ContractBounds:
    """Infer contract bounds from NL step description using keyword heuristics."""
    desc_lower = step.description.lower()
    words = set(desc_lower.split())

    bounds = ContractBounds()

    # File reads — default to project dir unless broader scope mentioned
    if any(w in desc_lower for w in ("read", "scan", "collect", "list", "find", "check", "analyze", "parse", "extract")):
        if "project" in desc_lower or "current" in desc_lower or "cwd" in desc_lower:
            bounds.allowed_file_reads = ["project_dir/**"]
        elif any(w in desc_lower for w in _SENSITIVE_KEYWORDS):
            bounds.sensitive_access_allowed = True
            bounds.allowed_file_reads = ["**"]
        else:
            bounds.allowed_file_reads = ["project_dir/**"]

    # File writes
    if words & _FILE_WRITE_KEYWORDS:
        if "project" in desc_lower or "current" in desc_lower:
            bounds.allowed_file_writes = ["project_dir/**"]
        else:
            bounds.allowed_file_writes = ["project_dir/**"]

    # Network
    if words & _NETWORK_KEYWORDS:
        bounds.network_allowed = True
        # Try to extract domain
        url_match = re.search(r"(https?://[\w.\-/]+)", step.description)
        if url_match:
            bounds.allowed_network = [url_match.group(1)]
        else:
            bounds.allowed_network = ["*"]

    # Subprocesses
    if words & _SUBPROCESS_KEYWORDS:
        allowed_cmds: list[str] = []
        # Extract specific command names from step description
        cmd_matches = re.findall(r"(?:run|execute|invoke|call|use)\s+(?:`)?(\w[\w.\-]*)(?:`)?", desc_lower)
        allowed_cmds.extend(cmd_matches)
        # Also extract backtick-quoted tool names
        backtick_cmds = re.findall(r"`(\w[\w.\-]*)`", step.description)
        allowed_cmds.extend(c.lower() for c in backtick_cmds)
        # Also include tools mentioned in manifest description
        manifest_desc = (manifest.description or "").lower()
        manifest_tools = re.findall(r"`(\w[\w.\-]*)`", manifest.description or "")
        allowed_cmds.extend(t.lower() for t in manifest_tools)
        # Extract "using X and Y" pattern from manifest description
        using_match = re.search(r"using\s+(.+?)(?:\.|$)", manifest_desc)
        if using_match:
            tools = re.findall(r"(\w[\w\-]*)", using_match.group(1))
            allowed_cmds.extend(t for t in tools if t not in ("and", "or", "the", "a", "an", "to"))
        # Include target script itself
        if step.target_script:
            allowed_cmds.extend(["python", "python3", step.target_script])
        if allowed_cmds:
            bounds.allowed_subprocesses = list(set(allowed_cmds))
        else:
            bounds.allowed_subprocesses = ["*"]

    # Sensitive access
    if words & _SENSITIVE_KEYWORDS:
        bounds.sensitive_access_allowed = True

    # Also inherit from manifest permissions
    for scope in manifest.permissions.get("file_read", []):
        if scope not in bounds.allowed_file_reads:
            bounds.allowed_file_reads.append(scope)
    for scope in manifest.permissions.get("file_write", []):
        if scope not in bounds.allowed_file_writes:
            bounds.allowed_file_writes.append(scope)
    if manifest.permissions.get("network"):
        bounds.network_allowed = True
        for domain in manifest.permissions["network"]:
            if domain not in bounds.allowed_network:
                bounds.allowed_network.append(domain)

    return bounds


# =============================================================================
# Contract verification
# =============================================================================

def _is_path_covered(actual_path: str, allowed_patterns: list[str]) -> bool:
    """Check if an actual file path is covered by allowed patterns."""
    if not allowed_patterns:
        return False

    actual_lower = actual_path.lower()

    for pattern in allowed_patterns:
        pattern_lower = pattern.lower()

        # Exact match
        if actual_lower == pattern_lower:
            return True

        # "project_dir" wildcard — covers anything in CWD / relative paths
        if pattern_lower.startswith("project_dir"):
            # Actual path must be relative (no ~, no /etc, no absolute sensitive)
            if not actual_lower.startswith(("/", "~", "$")) and "." not in actual_lower.split("/")[0]:
                return True
            if actual_lower.startswith("./") or actual_lower.startswith("scripts/"):
                return True

        # Glob matching
        if fnmatch.fnmatch(actual_lower, pattern_lower):
            return True

        # Substring containment (for broad patterns like "**")
        if pattern == "**" or pattern == "*":
            return True

    return False


def _is_sensitive_path(path: str) -> bool:
    """Check if a path points to a sensitive location."""
    sensitive_patterns = [
        ".ssh", ".aws", ".gnupg", ".netrc", ".npmrc", ".env",
        "/etc/passwd", "/etc/shadow", ".kube/config", ".docker/config",
        ".git-credentials", ".pgpass", "id_rsa", "id_ed25519",
        "credentials", "private_key", "secret",
    ]
    path_lower = path.lower()
    return any(p in path_lower for p in sensitive_patterns)


def verify_contracts(
    nl_program: NLProgram,
    code_signals: CodeSignals,
    contracts: dict[str, ContractBounds],
) -> ContractResult:
    """
    Verify each script's behaviour against its NL-inferred contract.

    For each NL step with a target_script:
      1. Look up the ScriptInterface for that script
      2. Check each operation against the contract bounds
      3. Report violations
    """
    result = ContractResult(contracts=contracts)

    for step in nl_program.steps:
        if not step.target_script:
            continue

        contract = contracts.get(step.step_id)
        if contract is None:
            continue

        # Find the script interface
        iface = _find_interface(step.target_script, code_signals.script_interfaces)
        if iface is None:
            continue

        # ── Check 1: Sensitive file reads ──
        for sensitive_path in iface.sensitive_reads:
            if sensitive_path.startswith("env:"):
                continue  # handled separately
            if not contract.sensitive_access_allowed:
                result.violations.append(ContractViolation(
                    violation_type=ViolationType.SENSITIVE_ACCESS,
                    severity=Severity.CRITICAL,
                    nl_step_id=step.step_id,
                    script=iface.script_path,
                    description=f"Script accesses sensitive path '{sensitive_path}' but NL step does not declare sensitive access",
                    expected=f"Allowed reads: {contract.allowed_file_reads}",
                    actual=f"Reads: {sensitive_path}",
                    confidence=0.9,
                ))

        # ── Check 2: File reads outside scope ──
        for inp in iface.inputs:
            if inp.source_type != "file_read":
                continue
            if inp.detail == "<dynamic>":
                # Dynamic path — can't verify statically, flag if no broad permission
                if not any(p in ("**", "*") for p in contract.allowed_file_reads):
                    result.violations.append(ContractViolation(
                        violation_type=ViolationType.SCOPE_EXCEED,
                        severity=Severity.MEDIUM,
                        nl_step_id=step.step_id,
                        script=iface.script_path,
                        description="Script reads files with dynamic path — cannot verify scope",
                        expected=f"Allowed reads: {contract.allowed_file_reads}",
                        actual="Dynamic file path",
                        confidence=0.5,
                    ))
                continue

            if _is_sensitive_path(inp.detail) and not contract.sensitive_access_allowed:
                result.violations.append(ContractViolation(
                    violation_type=ViolationType.SENSITIVE_ACCESS,
                    severity=Severity.CRITICAL,
                    nl_step_id=step.step_id,
                    script=iface.script_path,
                    description=f"Script reads sensitive path '{inp.detail}'",
                    expected=f"Allowed reads: {contract.allowed_file_reads}",
                    actual=f"Reads: {inp.detail}",
                    confidence=0.9,
                ))
            elif not _is_path_covered(inp.detail, contract.allowed_file_reads):
                result.violations.append(ContractViolation(
                    violation_type=ViolationType.SCOPE_EXCEED,
                    severity=Severity.MEDIUM,
                    nl_step_id=step.step_id,
                    script=iface.script_path,
                    description=f"Script reads '{inp.detail}' outside declared scope",
                    expected=f"Allowed reads: {contract.allowed_file_reads}",
                    actual=f"Reads: {inp.detail}",
                    confidence=0.7,
                ))

        # ── Check 3: Network access ──
        for se in iface.side_effects:
            if se.effect_type != "network_request":
                continue
            if not contract.network_allowed:
                result.violations.append(ContractViolation(
                    violation_type=ViolationType.UNDECLARED_SIDE_EFFECT,
                    severity=Severity.HIGH,
                    nl_step_id=step.step_id,
                    script=iface.script_path,
                    description=f"Script makes network request to '{se.detail}' but NL step does not declare network access",
                    expected="No network access allowed",
                    actual=f"Network request: {se.detail}",
                    confidence=0.85,
                ))
            elif contract.allowed_network and "*" not in contract.allowed_network:
                # Check specific domain
                detail_lower = se.detail.lower()
                allowed = any(d.lower() in detail_lower for d in contract.allowed_network)
                if not allowed:
                    result.violations.append(ContractViolation(
                        violation_type=ViolationType.SCOPE_EXCEED,
                        severity=Severity.HIGH,
                        nl_step_id=step.step_id,
                        script=iface.script_path,
                        description=f"Script accesses '{se.detail}' but contract only allows {contract.allowed_network}",
                        expected=f"Allowed domains: {contract.allowed_network}",
                        actual=f"Accesses: {se.detail}",
                        confidence=0.8,
                    ))

        # ── Check 4: Subprocess calls ──
        for se in iface.side_effects:
            if se.effect_type != "subprocess":
                continue
            if not contract.allowed_subprocesses:
                result.violations.append(ContractViolation(
                    violation_type=ViolationType.UNDECLARED_SIDE_EFFECT,
                    severity=Severity.MEDIUM,
                    nl_step_id=step.step_id,
                    script=iface.script_path,
                    description=f"Script runs subprocess '{se.detail}' but no subprocess declared",
                    expected="No subprocess allowed",
                    actual=f"Subprocess: {se.detail}",
                    confidence=0.7,
                ))
            elif "*" not in contract.allowed_subprocesses:
                cmd_name = se.detail.split()[0] if se.detail and se.detail != "<dynamic>" else "<dynamic>"
                allowed = any(
                    cmd_name == a or cmd_name.endswith(f"/{a}")
                    for a in contract.allowed_subprocesses
                )
                if not allowed and cmd_name != "<dynamic>":
                    result.violations.append(ContractViolation(
                        violation_type=ViolationType.SCOPE_EXCEED,
                        severity=Severity.MEDIUM,
                        nl_step_id=step.step_id,
                        script=iface.script_path,
                        description=f"Script runs '{cmd_name}' but contract only allows {contract.allowed_subprocesses}",
                        expected=f"Allowed commands: {contract.allowed_subprocesses}",
                        actual=f"Runs: {cmd_name}",
                        confidence=0.7,
                    ))

        # ── Check 5: File writes to sensitive locations ──
        for out in iface.outputs:
            if out.sink_type != SinkType.FILE_WRITE:
                continue
            if _is_sensitive_path(out.detail):
                result.violations.append(ContractViolation(
                    violation_type=ViolationType.SENSITIVE_ACCESS,
                    severity=Severity.CRITICAL,
                    nl_step_id=step.step_id,
                    script=iface.script_path,
                    description=f"Script writes to sensitive path '{out.detail}'",
                    expected=f"Allowed writes: {contract.allowed_file_writes}",
                    actual=f"Writes: {out.detail}",
                    confidence=0.9,
                ))

        # ── Check 6: Capability inflation — too many capabilities vs NL description ──
        capability_count = (
            len(iface.side_effects)
            + len(iface.sensitive_reads)
            + (1 if iface.has_dynamic_execution else 0)
            + (1 if iface.has_obfuscation else 0)
        )
        # Simple heuristic: if script has many capabilities but NL step is brief
        if capability_count >= 5 and len(step.description.split()) < 15:
            result.violations.append(ContractViolation(
                violation_type=ViolationType.CAPABILITY_INFLATION,
                severity=Severity.MEDIUM,
                nl_step_id=step.step_id,
                script=iface.script_path,
                description=f"Script has {capability_count} capabilities but NL description is only {len(step.description.split())} words",
                expected="Capabilities proportional to NL description complexity",
                actual=f"{capability_count} capabilities for a {len(step.description.split())}-word description",
                confidence=0.6,
            ))

    return result


# Need SinkType for file write check
from nexus.models import SinkType  # noqa: E402


def _find_interface(
    target_script: str,
    interfaces: dict[str, ScriptInterface],
) -> ScriptInterface | None:
    """Find a script interface by target_script reference, trying multiple path forms."""
    if target_script in interfaces:
        return interfaces[target_script]

    # Try basename
    basename = target_script.rsplit("/", 1)[-1] if "/" in target_script else target_script
    for key, iface in interfaces.items():
        key_basename = key.rsplit("/", 1)[-1] if "/" in key else key
        if key_basename == basename:
            return iface

    # Try with/without "scripts/" prefix
    for prefix in ["scripts/", ""]:
        candidate = prefix + basename
        if candidate in interfaces:
            return interfaces[candidate]

    return None
