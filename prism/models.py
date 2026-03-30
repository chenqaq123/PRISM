"""
PRISM Data Models
All Pydantic schemas and dataclasses used across the framework.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class NLThreatCategory(str, Enum):
    """Five NL-layer threat categories (Instruction Threat Taxonomy)."""
    I_MIS  = "I-MIS"   # Instruction Misdirection
    I_EXP  = "I-EXP"   # Capability Expansion
    I_EXF  = "I-EXF"   # Covert Exfiltration Instruction
    I_CAM  = "I-CAM"   # Semantic Camouflage
    I_PRIV = "I-PRIV"  # Privilege Expansion


class ThreatCategory(str, Enum):
    """Full 12-category threat taxonomy (code + NL)."""
    T1_CRED_THEFT       = "T1-CredentialTheft"
    T2_CMD_INJECTION    = "T2-CommandInjection"
    T3_DATA_EXFIL       = "T3-DataExfiltration"
    T4_SANDBOX_ESCAPE   = "T4-SandboxEscape"
    T5_RCE              = "T5-RemoteCodeExecution"
    T6_SUPPLY_CHAIN     = "T6-SupplyChainPoisoning"
    T7_PERSISTENCE      = "T7-Persistence"
    T8_TIME_BOMB        = "T8-TimeBomb"
    T9_ENV_HIJACK       = "T9-EnvHijacking"
    T10_NL_MISDIRECTION = "T10-InstructionMisdirection"
    T11_NL_EXPANSION    = "T11-CapabilityExpansion"
    T12_SEMANTIC_CAM    = "T12-SemanticCamouflage"
    UNKNOWN             = "Unknown"


class Verdict(str, Enum):
    BLOCK   = "BLOCK"    # P(M) > 0.90: 自动拒绝安装
    REVIEW  = "REVIEW"   # P(M) > 0.70: 转人工审核
    WARN    = "WARN"     # P(M) > 0.40: 安装时警告
    PASS    = "PASS"     # P(M) ≤ 0.40: 通过


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# HASG Node / Edge models
# ─────────────────────────────────────────────────────────────────────────────

class HAsgNodeType(str, Enum):
    # NL layer
    NL_DIRECTIVE   = "nl_directive"    # Step in SKILL.md workflow
    NL_TRIGGER     = "nl_trigger"      # Conditional trigger in SKILL.md
    NL_AGENT_CALL  = "nl_agent_call"   # Declared agent capability call
    # Code layer
    CODE_BLOCK     = "code_block"      # Python function/method
    SYS_OP         = "sys_op"          # subprocess / os.exec
    NET_OP         = "net_op"          # HTTP / socket / DNS
    IO_OP          = "io_op"           # File read/write/delete
    ENV_OP         = "env_op"          # Environment variable access
    # Manifest layer
    PERM_NODE      = "perm_node"       # Declared permission


class HAsgEdgeType(str, Enum):
    NL_FLOW     = "nl_flow"      # NL step → NL step (control flow in instructions)
    NL_INVOKES  = "nl_invokes"   # NL agent_call → code_block (declared correspondence)
    CTRL_FLOW   = "ctrl_flow"    # code_block → code_block
    DATA_FLOW   = "data_flow"    # variable/value propagation
    TAINT       = "taint"        # untrusted source → node
    COVERS      = "covers"       # perm_node → operation node
    MISALIGN    = "misalign"     # CRITICAL: code does what NL did NOT declare


@dataclass
class HAsgNode:
    id:         str
    node_type:  HAsgNodeType
    label:      str
    file:       str
    line:       int
    risk_score: float = 0.0
    features:   dict  = field(default_factory=dict)
    is_tainted: bool  = False


@dataclass
class HAsgEdge:
    from_id:   str
    to_id:     str
    edge_type: HAsgEdgeType
    label:     str = ""
    weight:    float = 1.0


@dataclass
class HASG:
    """Heterogeneous Attributed Skill Graph."""
    skill_name: str = ""
    skill_dir:  str = ""
    nodes:      dict[str, HAsgNode] = field(default_factory=dict)
    edges:      list[HAsgEdge]      = field(default_factory=list)

    def add_node(self, node: HAsgNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: HAsgEdge) -> None:
        self.edges.append(edge)

    def misalign_edges(self) -> list[HAsgEdge]:
        return [e for e in self.edges if e.edge_type == HAsgEdgeType.MISALIGN]

    def taint_edges(self) -> list[HAsgEdge]:
        return [e for e in self.edges if e.edge_type == HAsgEdgeType.TAINT]

    def nodes_by_type(self, t: HAsgNodeType) -> list[HAsgNode]:
        return [n for n in self.nodes.values() if n.node_type == t]


# ─────────────────────────────────────────────────────────────────────────────
# LLM Structured Output schemas
# ─────────────────────────────────────────────────────────────────────────────

class InstructionUnit(BaseModel):
    """One atomic instruction step extracted from SKILL.md."""
    step_index:       int
    text:             str
    action_type:      Literal["file_op", "net_op", "subprocess", "agent_capability", "display", "condition", "other"]
    resource_scope:   str   = Field(description="e.g. 'project_dir', '~/.ssh', 'external_api', 'local_tool'")
    is_conditional:   bool  = False
    is_explicit:      bool  = Field(True, description="Whether the operation is clearly named (not vague)")
    scope_vs_manifest: float = Field(1.0, description="0-1: how consistent with frontmatter scope (1=consistent)")


class NLCapabilitySet(BaseModel):
    """Capabilities declared/implied in SKILL.md instructions."""
    file_read_scopes:  list[str] = Field(default_factory=list,
                                         description="File paths/patterns this skill declares it reads")
    file_write_scopes: list[str] = Field(default_factory=list,
                                         description="File paths/patterns this skill declares it writes")
    network_domains:   list[str] = Field(default_factory=list,
                                         description="External domains/APIs this skill declares accessing")
    subprocess_cmds:   list[str] = Field(default_factory=list,
                                         description="CLI commands this skill declares running")
    env_vars_accessed: list[str] = Field(default_factory=list,
                                         description="Environment variable names accessed")
    sensitive_access:  bool      = False
    declared_purpose:  str       = ""


class CodeCapabilitySet(BaseModel):
    """Capabilities inferred from static code analysis."""
    file_read_scopes:  list[str] = Field(default_factory=list)
    file_write_scopes: list[str] = Field(default_factory=list)
    network_domains:   list[str] = Field(default_factory=list)
    subprocess_cmds:   list[str] = Field(default_factory=list)
    env_vars_accessed: list[str] = Field(default_factory=list)
    sensitive_access:  bool      = False
    has_obfuscation:   bool      = False
    analyzability:     float     = 1.0


class NLThreatScore(BaseModel):
    """Per-category NL threat scores for a skill."""
    i_mis_score:  float = Field(0.0, ge=0.0, le=1.0, description="Instruction Misdirection")
    i_exp_score:  float = Field(0.0, ge=0.0, le=1.0, description="Capability Expansion")
    i_exf_score:  float = Field(0.0, ge=0.0, le=1.0, description="Covert Exfiltration Instruction")
    i_cam_score:  float = Field(0.0, ge=0.0, le=1.0, description="Semantic Camouflage")
    i_priv_score: float = Field(0.0, ge=0.0, le=1.0, description="Privilege Expansion")
    kill_chain_detected: bool = False
    kill_chain_description: str = ""
    flagged_units: list[dict] = Field(default_factory=list,
                                       description="List of {step_index, text, category, score}")

    @property
    def overall(self) -> float:
        base = max(self.i_mis_score, self.i_exp_score, self.i_exf_score,
                   self.i_cam_score, self.i_priv_score)
        return min(1.0, base + (0.15 if self.kill_chain_detected else 0.0))


class CodeThreatScore(BaseModel):
    """Code-layer threat assessment."""
    pattern_score:    float = Field(0.0, ge=0.0, le=1.0)
    taint_risk:       float = Field(0.0, ge=0.0, le=1.0)
    obfusc_score:     float = Field(0.0, ge=0.0, le=1.0)
    analyzability:    float = Field(1.0, ge=0.0, le=1.0)
    top_findings:     list[dict] = Field(default_factory=list)

    @property
    def overall(self) -> float:
        w = [0.35, 0.35, 0.20, 0.10]
        raw = (w[0]*self.pattern_score + w[1]*self.taint_risk +
               w[2]*self.obfusc_score  + w[3]*(1 - self.analyzability))
        return min(1.0, raw)


class CMIAScore(BaseModel):
    """Cross-Modal Intent Alignment assessment."""
    overall: float          = Field(0.0, ge=0.0, le=1.0,
                                    description="Higher = more suspicious misalignment")
    over_reach_score: float = Field(0.0, ge=0.0, le=1.0)
    align_score:      float = Field(0.0, ge=0.0, le=1.0,
                                    description="Higher = better alignment (inverse of suspicion)")
    capability_gaps:  list[str] = Field(default_factory=list,
                                         description="Capabilities in code but not in NL")
    misalign_count:   int   = 0


class JudgeVerdict(BaseModel):
    """Single LLM judge verdict."""
    judge_role:        Literal["defender", "red_team", "intent_auditor"]
    risk_score:        float             = Field(ge=0.0, le=1.0)
    confidence:        float             = Field(ge=0.0, le=1.0)
    threat_categories: list[str]         = Field(default_factory=list)
    evidence:          list[str]         = Field(default_factory=list)
    reasoning:         str               = ""
    is_malicious:      bool              = False


class KillChain(BaseModel):
    """A detected multi-step attack chain."""
    name:              str
    severity:          Severity
    nl_evidence:       list[str] = Field(default_factory=list)
    code_evidence:     list[str] = Field(default_factory=list)
    misalign_count:    int       = 0
    cmia_contribution: float     = 0.0
    attack_strategy:   str       = ""


# ─────────────────────────────────────────────────────────────────────────────
# Phase 0 / Phase 1 data structures
# ─────────────────────────────────────────────────────────────────────────────

class Finding(BaseModel):
    """Individual finding from static analysis (Phase 1) or preprocessing (Phase 0)."""
    severity:      Severity
    category:      ThreatCategory
    description:   str
    file:          str   = ""
    line:          int   = 0
    analyzer:      str   = ""    # "pattern" | "behavioral" | "pipeline" | "cmia" | plugin name
    # Set by Phase 2a LLM filter
    llm_verified:  Optional[bool] = None
    llm_reasoning: str   = ""


@dataclass
class InjectionResult:
    """Result of Phase 0 static injection detection."""
    detected:       bool
    confidence:     float
    patterns_found: list[str] = field(default_factory=list)
    matched_texts:  list[str] = field(default_factory=list)


class StaticAnalysisResult(BaseModel):
    """Aggregated results from all Phase 1 static analyzers."""
    findings:          list[Finding] = Field(default_factory=list)
    pattern_score:     float = 0.0    # Phase 1a
    behavioral_score:  float = 0.0    # Phase 1b
    pipeline_score:    float = 0.0    # Phase 1c
    alignment_score:   float = 0.0    # Phase 1d (CMIA)
    plugin_findings:   list[Finding] = Field(default_factory=list)  # Phase 1e

    @property
    def overall(self) -> float:
        # Composite score: max of individual scores, with behavioral and pipeline weighted
        return round(min(1.0, max(
            self.pattern_score,
            self.behavioral_score,
            self.pipeline_score * 0.9,
            self.alignment_score * 0.85,
        )), 3)


class PRISMReport(BaseModel):
    """Final PRISM scan report."""
    skill_name:      str
    skill_dir:       str
    verdict:         Verdict
    confidence:      float

    # Per-phase/module scores
    s1_nl_threat:    float   # Phase 2b — NL consistency (LLM)
    s2_code_threat:  float   # Phase 1a+1b — pattern + behavioral
    s3_cmia:         float   # Phase 1d — cross-modal alignment
    s4_llm_panel:    float   # Phase 2c — role judges
    s_pipeline:      float = 0.0  # Phase 1c — pipeline analysis
    s_plugins:       float = 0.0  # Phase 1e — plugin findings

    # Posterior probability
    p_malicious:     float

    # Phase 0 result
    phase0_injection:   bool  = False

    # Phase 1 static findings
    static_findings:    list[Finding]              = Field(default_factory=list)

    # Detailed results
    nl_threat_detail:   Optional[NLThreatScore]    = None
    code_threat_detail: Optional[CodeThreatScore]  = None
    cmia_detail:        Optional[CMIAScore]         = None
    judge_verdicts:     list[JudgeVerdict]          = Field(default_factory=list)
    kill_chains:        list[KillChain]             = Field(default_factory=list)

    # Raw capability sets for transparency
    nl_capabilities:    Optional[NLCapabilitySet]  = None
    code_capabilities:  Optional[CodeCapabilitySet] = None

    # Metadata
    scan_duration_s:    float = 0.0
    llm_calls_made:     int   = 0
    error_messages:     list[str] = Field(default_factory=list)

    def severity(self) -> Severity:
        if self.p_malicious > 0.90: return Severity.CRITICAL
        if self.p_malicious > 0.70: return Severity.HIGH
        if self.p_malicious > 0.40: return Severity.MEDIUM
        return Severity.LOW
