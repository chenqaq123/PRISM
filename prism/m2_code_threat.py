"""
Module 2: Code Threat Analyzer
Extended static analysis: obfuscation detection, taint propagation, analyzability scoring.
"""
from __future__ import annotations

import math
import re
from pathlib import Path

from .hasg_builder import (
    HASG, HAsgNode, HAsgNodeType, _RawCodeOp,
    SENSITIVE_PATH_RE, EXTERNAL_DOMAIN_RE, OBFUSC_ENCODING_RE,
)
from .models import CodeCapabilitySet, CodeThreatScore

# ─────────────────────────────────────────────────────────────────────────────
# Taint propagation (simplified CFG-free version)
# ─────────────────────────────────────────────────────────────────────────────

# Sources: operations that produce potentially sensitive/attacker-controlled data
_TAINT_SOURCE_TYPES = {HAsgNodeType.NET_OP, HAsgNodeType.ENV_OP}
_TAINT_SOURCE_PATHS = SENSITIVE_PATH_RE   # file reads from sensitive paths

# Sinks: operations that become dangerous when fed tainted data
_DANGEROUS_SINKS = {HAsgNodeType.SYS_OP}


def _propagate_taint(graph: HASG) -> set[str]:
    """
    Mark nodes as tainted by propagating through data_flow and taint edges.
    Returns set of tainted node IDs.
    """
    tainted: set[str] = set()

    # Seed taint sources
    for nid, node in graph.nodes.items():
        if node.node_type in _TAINT_SOURCE_TYPES:
            tainted.add(nid)
        elif node.node_type == HAsgNodeType.IO_OP:
            path = node.features.get("path", "")
            if path and _TAINT_SOURCE_PATHS.search(path):
                tainted.add(nid)

    # Propagate through data_flow edges (fixed-point)
    changed = True
    while changed:
        changed = False
        for edge in graph.edges:
            if edge.edge_type.value in ("data_flow", "taint"):
                if edge.from_id in tainted and edge.to_id not in tainted:
                    tainted.add(edge.to_id)
                    changed = True

    # Mark tainted nodes in the graph
    for nid in tainted:
        if nid in graph.nodes:
            graph.nodes[nid].is_tainted = True

    return tainted


# ─────────────────────────────────────────────────────────────────────────────
# Pattern scoring
# ─────────────────────────────────────────────────────────────────────────────

def _score_ops(ops: list[_RawCodeOp]) -> tuple[float, list[dict]]:
    """
    Score code operations for known dangerous patterns.
    Returns (pattern_score, top_findings).
    """
    max_score = 0.0
    findings  = []

    for op in ops:
        score = 0.0
        desc  = ""

        if op.op_type == "sys_op":
            if ("eval" in op.label or "exec" in op.label) and op.cmd_dynamic:
                score = 0.95
                desc  = f"eval/exec with dynamic source at {op.file}:{op.line}"
            elif op.cmd_dynamic:
                score = 0.80
                desc  = f"Subprocess with variable command at {op.file}:{op.line}"
            elif op.entropy > 4.5:
                score = 0.78
                desc  = f"High-entropy string (encoded payload?) near {op.file}:{op.line}"
            elif OBFUSC_ENCODING_RE.search(op.label):
                score = 0.72
                desc  = f"Obfuscation API usage at {op.file}:{op.line}"
            elif op.cmd:
                score = 0.40
                desc  = f"Subprocess call: {op.cmd[:50]} at {op.file}:{op.line}"

        elif op.op_type == "net_op":
            if op.is_external_url:
                score = 0.60
                desc  = f"External HTTP call to {op.url[:60]} at {op.file}:{op.line}"
            else:
                score = 0.20

        elif op.op_type == "io_op":
            if op.is_sensitive_path:
                score = 0.85
                desc  = f"Sensitive path access: {op.path} at {op.file}:{op.line}"
            elif op.is_write:
                score = 0.45
                desc  = f"File write: {op.path[:50]} at {op.file}:{op.line}"

        elif op.op_type == "env_op":
            score = 0.25
            desc  = f"Env var access: {op.var_name} at {op.file}:{op.line}"

        if score > max_score:
            max_score = score
        if score >= 0.50 and desc:
            findings.append({"score": round(score, 3), "description": desc})

    findings.sort(key=lambda x: x["score"], reverse=True)
    return round(max_score, 3), findings[:10]


def _score_taint_risk(graph: HASG, tainted: set[str]) -> float:
    """Score taint risk based on tainted nodes reaching dangerous sinks."""
    max_risk = 0.0
    for nid in tainted:
        node = graph.nodes.get(nid)
        if node and node.node_type in _DANGEROUS_SINKS:
            max_risk = max(max_risk, node.risk_score)
    return round(max_risk, 3)


def _score_obfuscation(ops: list[_RawCodeOp], code_caps: CodeCapabilitySet) -> float:
    """Compute obfuscation score from raw ops and capability set."""
    score = 0.0
    if code_caps.has_obfuscation:
        score += 0.40
    high_entropy = sum(1 for op in ops if op.entropy > 4.5)
    if high_entropy > 0:
        score += min(0.30, high_entropy * 0.10)
    dynamic_cmds = sum(1 for op in ops if op.op_type == "sys_op" and op.cmd_dynamic)
    if dynamic_cmds > 0:
        score += min(0.30, dynamic_cmds * 0.15)
    return round(min(1.0, score), 3)


# ─────────────────────────────────────────────────────────────────────────────
# Main analysis function
# ─────────────────────────────────────────────────────────────────────────────

def analyze_code_threats(
    graph: HASG,
    ops: list[_RawCodeOp],
    code_caps: CodeCapabilitySet,
) -> CodeThreatScore:
    """
    Run Module 2: Code Threat Analyzer.
    Returns CodeThreatScore with taint risk, pattern score, and obfuscation score.
    """
    # Taint propagation
    tainted        = _propagate_taint(graph)
    taint_risk     = _score_taint_risk(graph, tainted)

    # Pattern scoring
    pattern_score, top_findings = _score_ops(ops)

    # Obfuscation scoring
    obfusc_score = _score_obfuscation(ops, code_caps)

    # Combine taint + pattern findings
    taint_findings = []
    for nid in tainted:
        node = graph.nodes.get(nid)
        if node and node.node_type in _DANGEROUS_SINKS:
            taint_findings.append({
                "score": round(node.risk_score, 3),
                "description": f"Tainted data flows to {node.label} at {node.file}:{node.line}",
            })

    all_findings = sorted(
        top_findings + taint_findings,
        key=lambda x: x["score"],
        reverse=True,
    )[:10]

    return CodeThreatScore(
        pattern_score=pattern_score,
        taint_risk=taint_risk,
        obfusc_score=obfusc_score,
        analyzability=code_caps.analyzability,
        top_findings=all_findings,
    )
