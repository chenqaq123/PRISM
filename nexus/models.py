"""
NEXUS Data Models
All Pydantic schemas and dataclasses used across the three-layer pipeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


# =============================================================================
# Enumerations
# =============================================================================

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Verdict(str, Enum):
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"
    WARN = "WARN"
    PASS = "PASS"


class ThreatCategory(str, Enum):
    CREDENTIAL_THEFT = "CredentialTheft"
    DATA_EXFILTRATION = "DataExfiltration"
    COMMAND_INJECTION = "CommandInjection"
    REMOTE_CODE_EXEC = "RemoteCodeExecution"
    SANDBOX_ESCAPE = "SandboxEscape"
    SUPPLY_CHAIN = "SupplyChainPoisoning"
    PERSISTENCE = "Persistence"
    TIME_BOMB = "TimeBomb"
    ENV_HIJACKING = "EnvHijacking"
    OBFUSCATION = "Obfuscation"
    PROMPT_INJECTION = "PromptInjection"
    NL_MISDIRECTION = "NLMisdirection"
    SEMANTIC_CAMOUFLAGE = "SemanticCamouflage"
    CAPABILITY_INFLATION = "CapabilityInflation"
    CROSS_SCRIPT_EXFIL = "CrossScriptExfiltration"
    PHANTOM_SCRIPT = "PhantomScript"
    UNKNOWN = "Unknown"


class ViolationType(str, Enum):
    SCOPE_EXCEED = "SCOPE_EXCEED"
    UNDECLARED_SIDE_EFFECT = "UNDECLARED_SIDE_EFFECT"
    SENSITIVE_ACCESS = "SENSITIVE_ACCESS"
    CAPABILITY_INFLATION = "CAPABILITY_INFLATION"
    PHANTOM_STEP = "PHANTOM_STEP"


class TaintLabel(str, Enum):
    SSH_KEY = "ssh_key"
    AWS_CRED = "aws_credential"
    ENV_SECRET = "env_secret"
    DOTENV = "dotenv"
    NETRC = "netrc"
    GENERIC_CREDENTIAL = "generic_credential"
    SENSITIVE_FILE = "sensitive_file"
    USER_DATA = "user_data"
    UNKNOWN_SENSITIVE = "unknown_sensitive"


class SinkType(str, Enum):
    NETWORK_POST = "network_post"
    NETWORK_GET = "network_get"
    SUBPROCESS = "subprocess"
    FILE_WRITE = "file_write"
    STDOUT = "stdout"


# =============================================================================
# Layer 0A: Code Threat Scanner models
# =============================================================================

@dataclass
class CodeFinding:
    """One finding from static code analysis."""
    severity: Severity
    category: ThreatCategory
    description: str
    file: str = ""
    line: int = 0
    evidence: str = ""
    confidence: float = 0.8

    # Enrichment fields (set by Layer 1C)
    enriched: bool = False
    enrichment_reason: str = ""
    original_severity: Severity | None = None


@dataclass
class InputSource:
    """A way a script receives data."""
    source_type: str  # "argv", "stdin", "file_read", "env_var", "function_param"
    detail: str = ""  # path pattern, var name, etc.
    line: int = 0


@dataclass
class OutputSink:
    """A way a script emits data."""
    sink_type: SinkType
    detail: str = ""  # URL, file path, etc.
    line: int = 0


@dataclass
class SideEffect:
    """An operation beyond declared input/output."""
    effect_type: str  # "network_request", "file_write", "subprocess", "env_modify"
    detail: str = ""
    line: int = 0
    is_sensitive: bool = False

    def is_network_sink(self) -> bool:
        return self.effect_type == "network_request"


@dataclass
class ScriptInterface:
    """Summarises a script's I/O boundary — what goes in, what comes out, side effects."""
    script_path: str
    inputs: list[InputSource] = field(default_factory=list)
    outputs: list[OutputSink] = field(default_factory=list)
    side_effects: list[SideEffect] = field(default_factory=list)
    sensitive_reads: list[str] = field(default_factory=list)
    sensitive_writes: list[str] = field(default_factory=list)
    analyzability: float = 1.0  # 0-1; lowered by eval/dynamic import/obfuscation
    has_obfuscation: bool = False
    has_dynamic_execution: bool = False
    has_encoded_payloads: bool = False
    entry_point_detected: bool = False  # has if __name__ == "__main__" or top-level calls


@dataclass
class CodeSignals:
    """Aggregated output of Layer 0A."""
    findings: list[CodeFinding] = field(default_factory=list)
    script_interfaces: dict[str, ScriptInterface] = field(default_factory=dict)
    overall_analyzability: float = 1.0
    has_obfuscation: bool = False
    has_encoded_payloads: bool = False
    has_dynamic_execution: bool = False
    all_scripts: list[str] = field(default_factory=list)


# =============================================================================
# Layer 0B: NL Program models
# =============================================================================

class NLStep(BaseModel):
    """One step extracted from SKILL.md, modelling the NL-level 'program'."""
    step_id: str = Field(description="Unique ID, e.g. 'S1', 'S2'")
    action: str = Field(description="Verb phrase: 'run', 'read', 'send', 'check', 'write', 'display'")
    description: str = Field(description="Full natural language description of this step")
    target_script: str = Field(
        default="",
        description="Script filename if this step invokes a script, e.g. 'scripts/gather.py'. Empty if no script invocation.",
    )
    input_refs: list[str] = Field(
        default_factory=list,
        description="References to outputs of earlier steps, e.g. ['S1.output.file_list']",
    )
    output_name: str = Field(
        default="",
        description="Name of the data this step produces, e.g. 'file_list', 'analysis_result'",
    )
    declared_scope: str = Field(
        default="",
        description="Resource scope this step claims to access, e.g. 'project files in current directory', '~/.ssh'",
    )
    condition: str = Field(
        default="",
        description="Condition for branching, e.g. 'if project uses Python'. Empty if not conditional.",
    )
    branch_true: str = Field(default="", description="step_id to go to if condition is true")
    branch_false: str = Field(default="", description="step_id to go to if condition is false")
    is_terminal: bool = Field(default=False, description="Whether this is the last step in a branch")


class NLProgram(BaseModel):
    """Structured representation of the SKILL.md as an executable program."""
    skill_name: str = ""
    declared_purpose: str = ""
    steps: list[NLStep] = Field(default_factory=list)
    entry_step: str = Field(default="S1", description="step_id of the first step")

    def topological_order(self) -> list[NLStep]:
        """Return steps in execution order (BFS from entry)."""
        if not self.steps:
            return []
        step_map = {s.step_id: s for s in self.steps}
        visited: set[str] = set()
        result: list[NLStep] = []
        queue = [self.entry_step]
        while queue:
            sid = queue.pop(0)
            if sid in visited or sid not in step_map:
                continue
            visited.add(sid)
            step = step_map[sid]
            result.append(step)
            # Follow branches or sequential
            if step.condition:
                if step.branch_true:
                    queue.append(step.branch_true)
                if step.branch_false:
                    queue.append(step.branch_false)
            # Also try next sequential step
            idx = self.steps.index(step)
            if idx + 1 < len(self.steps):
                next_sid = self.steps[idx + 1].step_id
                if next_sid not in visited:
                    queue.append(next_sid)
        return result

    def find_step_for_script(self, script_path: str) -> NLStep | None:
        """Find the NL step that references a given script."""
        basename = script_path.rsplit("/", 1)[-1] if "/" in script_path else script_path
        for step in self.steps:
            if not step.target_script:
                continue
            step_basename = step.target_script.rsplit("/", 1)[-1] if "/" in step.target_script else step.target_script
            if step_basename == basename or step.target_script == script_path:
                return step
        return None

    def scripts_referenced(self) -> set[str]:
        """All script filenames referenced by NL steps."""
        result: set[str] = set()
        for step in self.steps:
            if step.target_script:
                result.add(step.target_script)
                basename = step.target_script.rsplit("/", 1)[-1] if "/" in step.target_script else step.target_script
                result.add(basename)
        return result


# LLM structured output schema for NL Program extraction
class NLProgramExtract(BaseModel):
    """LLM output schema for extracting NL Program from SKILL.md."""
    declared_purpose: str = Field(description="One-sentence summary of the skill's declared purpose")
    steps: list[NLStep] = Field(description="Ordered list of steps extracted from SKILL.md")


# =============================================================================
# Layer 0C: Manifest models
# =============================================================================

@dataclass
class ManifestInfo:
    """Parsed manifest/frontmatter."""
    name: str = ""
    description: str = ""
    version: str = ""
    author: str = ""
    tags: list[str] = field(default_factory=list)
    permissions: dict[str, list[str]] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    findings: list[CodeFinding] = field(default_factory=list)


# =============================================================================
# Layer 1A: Contract models
# =============================================================================

class ContractBounds(BaseModel):
    """LLM-inferred contract for what a script SHOULD do based on NL description."""
    allowed_file_reads: list[str] = Field(
        default_factory=list,
        description="File path patterns the script is allowed to read, e.g. ['project_dir/**/*.py', 'config.json']",
    )
    allowed_file_writes: list[str] = Field(
        default_factory=list,
        description="File path patterns the script is allowed to write",
    )
    allowed_network: list[str] = Field(
        default_factory=list,
        description="Domains/URLs the script is allowed to access, e.g. ['api.github.com']. Empty = no network allowed.",
    )
    allowed_subprocesses: list[str] = Field(
        default_factory=list,
        description="Commands the script is allowed to run, e.g. ['black', 'isort', 'git']. Empty = no subprocess allowed.",
    )
    allowed_env_vars: list[str] = Field(
        default_factory=list,
        description="Environment variables allowed to read, e.g. ['PATH', 'HOME']",
    )
    sensitive_access_allowed: bool = Field(
        default=False,
        description="Whether the script has legitimate reason to access SSH keys, credentials, etc.",
    )
    network_allowed: bool = Field(
        default=False,
        description="Whether any network access is expected",
    )
    rationale: str = Field(
        default="",
        description="Brief explanation of why these bounds are appropriate",
    )


@dataclass
class ContractViolation:
    """A single violation of the semantic contract."""
    violation_type: ViolationType
    severity: Severity
    nl_step_id: str
    script: str
    description: str
    expected: str  # what the contract allows
    actual: str  # what the code does
    confidence: float = 0.8


@dataclass
class ContractResult:
    """All contract verification results for a skill."""
    violations: list[ContractViolation] = field(default_factory=list)
    contracts: dict[str, ContractBounds] = field(default_factory=dict)  # step_id -> bounds

    @property
    def has_critical(self) -> bool:
        return any(v.severity == Severity.CRITICAL for v in self.violations)

    @property
    def max_severity(self) -> Severity:
        if not self.violations:
            return Severity.INFO
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for s in order:
            if any(v.severity == s for v in self.violations):
                return s
        return Severity.INFO


# =============================================================================
# Layer 1B: Cross-Modal Taint models
# =============================================================================

@dataclass
class TaintSource:
    """A source of sensitive data."""
    label: TaintLabel
    origin_script: str
    origin_step_id: str
    detail: str = ""  # e.g. "~/.ssh/id_rsa"
    line: int = 0


@dataclass
class TaintSink:
    """A destination where tainted data arrives."""
    sink_type: SinkType
    dest_script: str
    dest_step_id: str
    detail: str = ""  # e.g. "POST https://evil.com"
    line: int = 0


@dataclass
class TaintChain:
    """A complete taint path from sensitive source to dangerous sink."""
    source: TaintSource
    sink: TaintSink
    path: list[str]  # step_ids in order
    scripts_involved: list[str]
    severity: Severity
    description: str
    declared_in_nl: bool = False  # whether NL explicitly mentions this data flow


@dataclass
class TaintResult:
    """All cross-modal taint analysis results."""
    chains: list[TaintChain] = field(default_factory=list)
    taint_map: dict[str, set[str]] = field(default_factory=dict)  # step_id -> set of taint labels

    @property
    def has_exfiltration(self) -> bool:
        return any(
            c.sink.sink_type in (SinkType.NETWORK_POST, SinkType.NETWORK_GET)
            and not c.declared_in_nl
            for c in self.chains
        )


# =============================================================================
# Layer 1C: Enrichment models
# =============================================================================

@dataclass
class EnrichmentAction:
    """Records how a finding was enriched."""
    finding_index: int
    action: str  # "upgrade", "downgrade", "phantom_flag"
    reason: str
    old_severity: Severity
    new_severity: Severity


# =============================================================================
# Layer 2: Evidence + Verdict models
# =============================================================================

@dataclass
class EvidenceChain:
    """A structured piece of evidence supporting the verdict."""
    chain_type: str  # "contract_violation", "taint_chain", "code_finding", "nl_threat", "phantom_script"
    severity: Severity
    title: str
    description: str

    # Context
    nl_step: str = ""
    script: str = ""

    # For taint chains
    taint_path: list[str] = field(default_factory=list)

    # Justification
    justification: str = ""


@dataclass
class NEXUSReport:
    """Final NEXUS scan report."""
    skill_name: str
    skill_dir: str
    verdict: Verdict
    confidence: float

    # Evidence
    evidence_chains: list[EvidenceChain] = field(default_factory=list)

    # Sub-results
    code_findings_count: int = 0
    contract_violations_count: int = 0
    taint_chains_count: int = 0
    phantom_scripts: list[str] = field(default_factory=list)

    # Scores
    code_threat_score: float = 0.0
    contract_violation_score: float = 0.0
    taint_score: float = 0.0
    nl_threat_score: float = 0.0
    overall_score: float = 0.0

    # Capabilities summary
    nl_declared_capabilities: dict[str, Any] = field(default_factory=dict)
    code_actual_capabilities: dict[str, Any] = field(default_factory=dict)

    # Metadata
    scan_duration_s: float = 0.0
    llm_calls_made: int = 0
    errors: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"=== NEXUS Report: {self.skill_name} ===",
            f"Verdict:    {self.verdict.value}",
            f"Confidence: {self.confidence:.2f}",
            f"Score:      {self.overall_score:.3f}",
            "",
            f"Code findings:        {self.code_findings_count}",
            f"Contract violations:  {self.contract_violations_count}",
            f"Taint chains:         {self.taint_chains_count}",
            f"Phantom scripts:      {len(self.phantom_scripts)}",
        ]
        if self.evidence_chains:
            lines.append("")
            lines.append("Evidence Chains:")
            for i, ec in enumerate(self.evidence_chains, 1):
                lines.append(f"  [{ec.severity.value}] {ec.title}")
                lines.append(f"    {ec.description}")
                if ec.taint_path:
                    lines.append(f"    Path: {' -> '.join(ec.taint_path)}")
                if ec.justification:
                    lines.append(f"    Why: {ec.justification}")
        if self.phantom_scripts:
            lines.append("")
            lines.append(f"Phantom scripts (not referenced in SKILL.md): {self.phantom_scripts}")
        if self.errors:
            lines.append("")
            lines.append(f"Errors: {self.errors}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        """JSON-serializable dict."""
        return {
            "skill_name": self.skill_name,
            "skill_dir": self.skill_dir,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "overall_score": self.overall_score,
            "scores": {
                "code_threat": self.code_threat_score,
                "contract_violation": self.contract_violation_score,
                "taint": self.taint_score,
                "nl_threat": self.nl_threat_score,
            },
            "counts": {
                "code_findings": self.code_findings_count,
                "contract_violations": self.contract_violations_count,
                "taint_chains": self.taint_chains_count,
                "phantom_scripts": len(self.phantom_scripts),
            },
            "evidence_chains": [
                {
                    "type": ec.chain_type,
                    "severity": ec.severity.value,
                    "title": ec.title,
                    "description": ec.description,
                    "nl_step": ec.nl_step,
                    "script": ec.script,
                    "taint_path": ec.taint_path,
                    "justification": ec.justification,
                }
                for ec in self.evidence_chains
            ],
            "phantom_scripts": self.phantom_scripts,
            "metadata": {
                "scan_duration_s": self.scan_duration_s,
                "llm_calls_made": self.llm_calls_made,
                "errors": self.errors,
            },
        }
