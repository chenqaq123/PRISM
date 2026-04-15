"""
Layer 1D: Pipeline Attack Chain Analyzer (AV6)

Detects multi-step attack chains via graph reachability analysis.
Unlike taint_tracker which operates at the inter-script level,
this module looks for COMPLETE KILL CHAINS at the pipeline level.

A kill chain requires all three stages:
  1. ACCESS:     Read/collect sensitive data (credentials, keys, env vars)
  2. STAGE:      Encode, buffer, or store the data (optionally)
  3. EXFILTRATE: Send data off-system (network POST, DNS, subprocess)

Even if each step is in a different script and looks innocuous alone,
the combination is flagged as an attack pipeline (AV6).

Additional patterns:
  - Privilege escalation chains (read config → modify system files)
  - Persistence installation chains (download → write startup → execute)
  - Reconnaissance chains (enumerate files → collect → report)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from nexus.models import (
    CodeSignals,
    NLProgram,
    Severity,
    SinkType,
    TaintLabel,
)


# =============================================================================
# Kill chain stage taxonomy
# =============================================================================

class ChainStage(str, Enum):
    """MITRE-inspired kill chain stages."""
    DISCOVERY = "discovery"         # Enumerate files, check env, reconnaissance
    ACCESS = "access"               # Read credentials, SSH keys, tokens
    STAGING = "staging"             # Encode, buffer, accumulate
    COMMAND = "command"             # Execute arbitrary commands
    EXFILTRATION = "exfiltration"  # Network send, stdout to subprocess
    PERSISTENCE = "persistence"    # Write to startup, crontab, dotfiles
    LATERAL = "lateral"            # Use credentials to access other systems


# Keywords that indicate each stage
_STAGE_KEYWORDS: dict[ChainStage, list[str]] = {
    ChainStage.DISCOVERY: [
        "enumerate", "list", "find", "glob", "scan", "walk", "discover",
        "check", "inspect", "audit",
    ],
    ChainStage.ACCESS: [
        ".ssh", ".aws", ".env", "credential", "token", "secret", "password",
        "api_key", "private_key", "id_rsa", "id_ed25519", "netrc", "pgpass",
    ],
    ChainStage.STAGING: [
        "base64", "encode", "compress", "buffer", "accumulate", "collect",
        "json.dumps", "pickle", "marshal",
    ],
    ChainStage.COMMAND: [
        "subprocess", "os.system", "eval", "exec", "popen", "shell=True",
        "os.exec",
    ],
    ChainStage.EXFILTRATION: [
        "requests.post", "requests.get", "urllib",
        "webhook", "upload", "smtp", "socket.send", "exfiltrate", "exfil",
    ],
    ChainStage.PERSISTENCE: [
        ".bashrc", ".bash_profile", ".zshrc", "crontab", "launchd", "plist",
        "systemctl enable", "/etc/init.d", "startup",
    ],
    ChainStage.LATERAL: [
        "paramiko", "ssh", "ftplib", "smb", "rdp", "psexec",
    ],
}

# NL-level analysis uses a stricter EXFILTRATION keyword set to avoid
# flagging benign skills that "send a report" or "call an API".
_NL_EXFIL_KEYWORDS = [
    "exfiltrate", "exfil", "webhook", "upload secret", "upload credentials",
    "send credentials", "send secrets", "send private", "send to remote",
    "post credentials", "leak", "steal",
]


# =============================================================================
# Attack chain detection
# =============================================================================

@dataclass
class AttackChain:
    """A detected multi-stage attack chain across the pipeline."""
    chain_type: str
    stages_detected: list[ChainStage]
    severity: Severity
    description: str
    scripts_involved: list[str]
    steps_involved: list[str]
    confidence: float = 0.7

    # What makes this suspicious
    evidence_fragments: list[str] = field(default_factory=list)


@dataclass
class PipelineAnalysisResult:
    """Results from pipeline attack chain analysis."""
    chains: list[AttackChain] = field(default_factory=list)
    pipeline_score: float = 0.0  # 0-1 aggregate score

    @property
    def has_complete_kill_chain(self) -> bool:
        """Check if any chain has ACCESS + EXFIL stages."""
        for chain in self.chains:
            if (ChainStage.ACCESS in chain.stages_detected
                    and ChainStage.EXFILTRATION in chain.stages_detected):
                return True
        return False


def _detect_stages_in_interface(iface, script_path: str) -> set[ChainStage]:
    """Detect which kill chain stages are present in a script interface."""
    stages: set[ChainStage] = set()

    # Check sensitive reads → ACCESS or DISCOVERY
    for path in iface.sensitive_reads:
        path_lower = path.lower()
        if any(kw in path_lower for kw in _STAGE_KEYWORDS[ChainStage.ACCESS]):
            stages.add(ChainStage.ACCESS)

    # Check side effects
    for se in iface.side_effects:
        detail_lower = se.detail.lower()

        if se.effect_type == "network_request":
            stages.add(ChainStage.EXFILTRATION)
        elif se.effect_type == "subprocess":
            stages.add(ChainStage.COMMAND)
            # Persistence through subprocess? e.g. crontab -e, systemctl enable
            if any(kw in detail_lower for kw in _STAGE_KEYWORDS[ChainStage.PERSISTENCE]):
                stages.add(ChainStage.PERSISTENCE)

    # Check outputs for persistence
    for out in iface.outputs:
        detail_lower = out.detail.lower()
        if any(kw in detail_lower for kw in _STAGE_KEYWORDS[ChainStage.PERSISTENCE]):
            stages.add(ChainStage.PERSISTENCE)

    # Check for staging (encoding)
    if iface.has_encoded_payloads or iface.has_obfuscation:
        stages.add(ChainStage.STAGING)

    # Check for dynamic execution
    if iface.has_dynamic_execution:
        stages.add(ChainStage.COMMAND)

    return stages


def _detect_stages_in_code_text(code_text: str) -> set[ChainStage]:
    """Detect stages from raw code text (for scripts without full AST)."""
    stages: set[ChainStage] = set()
    text_lower = code_text.lower()

    for stage, keywords in _STAGE_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            stages.add(stage)

    return stages


def _classify_chain_type(stages: set[ChainStage]) -> tuple[str, Severity]:
    """Classify the attack chain type and severity based on detected stages."""
    # Critical: credential theft + exfil
    if ChainStage.ACCESS in stages and ChainStage.EXFILTRATION in stages:
        if ChainStage.STAGING in stages:
            return "credential_exfil_with_encoding", Severity.CRITICAL
        return "credential_exfiltration", Severity.CRITICAL

    # Critical: complete kill chain with persistence
    if (ChainStage.ACCESS in stages
            and ChainStage.EXFILTRATION in stages
            and ChainStage.PERSISTENCE in stages):
        return "apt_style_attack", Severity.CRITICAL

    # High: persistence installation with command execution
    if ChainStage.PERSISTENCE in stages and ChainStage.COMMAND in stages:
        return "persistence_via_execution", Severity.HIGH

    # High: discovery + staging + exfil (reconnaissance pipeline)
    if (ChainStage.DISCOVERY in stages
            and ChainStage.EXFILTRATION in stages):
        return "recon_exfiltration", Severity.HIGH

    # High: command + exfil (arbitrary code with callback)
    if ChainStage.COMMAND in stages and ChainStage.EXFILTRATION in stages:
        return "c2_callback", Severity.HIGH

    # Medium: lateral movement attempt
    if ChainStage.LATERAL in stages and ChainStage.ACCESS in stages:
        return "lateral_movement", Severity.HIGH

    # Medium: staging with exfil (data collection and send)
    if ChainStage.STAGING in stages and ChainStage.EXFILTRATION in stages:
        return "staged_exfiltration", Severity.MEDIUM

    return "unknown_chain", Severity.LOW


def analyze_pipeline(
    nl_program: NLProgram,
    code_signals: CodeSignals,
) -> PipelineAnalysisResult:
    """
    Analyze the skill's pipeline for multi-stage attack chains.

    Strategy:
      1. For each script, determine which kill chain stages it participates in
      2. Across the whole pipeline (all scripts together), check for dangerous combinations
      3. Detect both intra-script (single-script kill chain) and inter-script (distributed) chains
    """
    result = PipelineAnalysisResult()

    # ── Stage 1: Collect stages per script ──
    script_stages: dict[str, set[ChainStage]] = {}

    for script_path, iface in code_signals.script_interfaces.items():
        stages = _detect_stages_in_interface(iface, script_path)
        if stages:
            script_stages[script_path] = stages

    # ── Stage 2: Intra-script chains (single script has multiple stages) ──
    for script_path, stages in script_stages.items():
        if len(stages) >= 2:
            chain_type, severity = _classify_chain_type(stages)
            if severity in (Severity.CRITICAL, Severity.HIGH):
                iface = code_signals.script_interfaces[script_path]
                evidence = []
                if ChainStage.ACCESS in stages:
                    evidence.extend(iface.sensitive_reads[:3])
                for se in iface.side_effects[:2]:
                    evidence.append(f"{se.effect_type}: {se.detail[:60]}")

                result.chains.append(AttackChain(
                    chain_type=f"intra_script_{chain_type}",
                    stages_detected=list(stages),
                    severity=severity,
                    description=(
                        f"Script '{script_path}' implements {len(stages)} kill chain stages in single file: "
                        + ", ".join(s.value for s in sorted(stages, key=lambda x: x.value))
                    ),
                    scripts_involved=[script_path],
                    steps_involved=_steps_for_script(script_path, nl_program),
                    confidence=0.8,
                    evidence_fragments=evidence,
                ))

    # ── Stage 3: Inter-script distributed chain ──
    # Aggregate all stages across all scripts
    all_stages: set[ChainStage] = set()
    all_scripts: list[str] = []
    for script_path, stages in script_stages.items():
        all_stages.update(stages)
        all_scripts.append(script_path)

    if len(all_scripts) >= 2 and len(all_stages) >= 2:
        chain_type, severity = _classify_chain_type(all_stages)
        if severity in (Severity.CRITICAL, Severity.HIGH):
            # Only report if not already caught by intra-script above
            intra_scripts = {c.scripts_involved[0] for c in result.chains if len(c.scripts_involved) == 1}
            new_scripts = [s for s in all_scripts if s not in intra_scripts]
            if new_scripts:
                result.chains.append(AttackChain(
                    chain_type=f"distributed_{chain_type}",
                    stages_detected=list(all_stages),
                    severity=severity,
                    description=(
                        f"Distributed kill chain across {len(all_scripts)} scripts: "
                        + ", ".join(s.value for s in sorted(all_stages, key=lambda x: x.value))
                    ),
                    scripts_involved=all_scripts,
                    steps_involved=list({
                        step_id
                        for script_path in all_scripts
                        for step_id in _steps_for_script(script_path, nl_program)
                    }),
                    confidence=0.7,
                ))

    # ── Stage 4: NL-level pipeline analysis ──
    # Check if NL steps themselves describe a suspicious workflow
    nl_chain_stages = _analyze_nl_pipeline(nl_program)
    if nl_chain_stages:
        chain_type, severity = _classify_chain_type(nl_chain_stages)
        if severity in (Severity.CRITICAL, Severity.HIGH):
            result.chains.append(AttackChain(
                chain_type=f"nl_described_{chain_type}",
                stages_detected=list(nl_chain_stages),
                severity=severity,
                description=(
                    f"NL pipeline description implies a suspicious workflow: "
                    + ", ".join(s.value for s in sorted(nl_chain_stages, key=lambda x: x.value))
                ),
                scripts_involved=[],
                steps_involved=[s.step_id for s in nl_program.steps],
                confidence=0.6,
            ))

    # ── Compute aggregate score ──
    if result.chains:
        max_severity_score = max(
            {"CRITICAL": 1.0, "HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.1}
            .get(c.severity.value, 0.1)
            * c.confidence
            for c in result.chains
        )
        chain_count_bonus = min(0.2, len(result.chains) * 0.05)
        result.pipeline_score = min(1.0, max_severity_score + chain_count_bonus)

    return result


def _steps_for_script(script_path: str, nl_program: NLProgram) -> list[str]:
    """Find all NL step IDs that reference a given script."""
    basename = script_path.rsplit("/", 1)[-1] if "/" in script_path else script_path
    result = []
    for step in nl_program.steps:
        if not step.target_script:
            continue
        step_base = step.target_script.rsplit("/", 1)[-1] if "/" in step.target_script else step.target_script
        if step_base == basename or step.target_script == script_path:
            result.append(step.step_id)
    return result


def _analyze_nl_pipeline(nl_program: NLProgram) -> set[ChainStage]:
    """Detect suspicious patterns in the NL-described workflow."""
    stages: set[ChainStage] = set()
    steps = nl_program.topological_order()

    for step in steps:
        desc_lower = step.description.lower()

        # Check access keywords
        if any(kw in desc_lower for kw in _STAGE_KEYWORDS[ChainStage.ACCESS]):
            stages.add(ChainStage.ACCESS)

        # Check exfil keywords — use the stricter NL set to avoid benign API calls
        if any(kw in desc_lower for kw in _NL_EXFIL_KEYWORDS):
            stages.add(ChainStage.EXFILTRATION)

        # Check persistence keywords
        if any(kw in desc_lower for kw in _STAGE_KEYWORDS[ChainStage.PERSISTENCE]):
            stages.add(ChainStage.PERSISTENCE)

        # Check staging keywords
        if any(kw in desc_lower for kw in _STAGE_KEYWORDS[ChainStage.STAGING]):
            stages.add(ChainStage.STAGING)

        # Check command keywords
        if any(kw in desc_lower for kw in _STAGE_KEYWORDS[ChainStage.COMMAND]):
            stages.add(ChainStage.COMMAND)

    # Only return if we have a multi-stage combination
    if len(stages) >= 2:
        return stages
    return set()
