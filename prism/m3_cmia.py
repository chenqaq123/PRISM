"""
Module 3: Cross-Modal Intent Alignment (CMIA)
Quantifies the semantic gap between NL-declared capabilities and code-implemented capabilities.

Key property: CMIA is obfuscation-invariant — it operates on capability sets (semantic
abstractions), not on syntactic code representations.
"""
from __future__ import annotations

import re

from .hasg_builder import (
    HASG, HAsgEdgeType, HAsgNodeType,
    SENSITIVE_PATH_RE, EXTERNAL_DOMAIN_RE,
    _extract_domain,
)
from .models import CMIAScore, CodeCapabilitySet, NLCapabilitySet

# ─────────────────────────────────────────────────────────────────────────────
# Semantic similarity helpers
# ─────────────────────────────────────────────────────────────────────────────

_BENIGN_SCOPE_KEYWORDS = {
    "project", "project_dir", "cwd", "workspace", "repo", "repository",
    "local", "current", "temp", "tmp", ".cache",
}

_HIGH_RISK_SCOPES = {
    "~/.ssh", ".ssh", "ssh", "~/.aws", ".aws", "aws", "credentials",
    "~/.gnupg", ".gnupg", "~/.netrc", ".netrc", "~/.npmrc", ".npmrc",
    "/etc", "/etc/passwd", "/etc/shadow", "id_rsa", "id_ed25519",
    "~/.config", "~/.bashrc", "~/.zshrc", "~/.profile",
}


def _is_benign_scope(scope: str) -> bool:
    s = scope.lower().strip("/~")
    return any(k in s for k in _BENIGN_SCOPE_KEYWORDS)


def _is_high_risk_scope(scope: str) -> bool:
    s = scope.lower()
    return any(r in s for r in _HIGH_RISK_SCOPES) or bool(SENSITIVE_PATH_RE.search(s))


def _jaccard_sim(a: list[str], b: list[str]) -> float:
    """Fuzzy Jaccard similarity for capability scope lists."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0

    # Normalize and match
    def normalize(items: list[str]) -> set[str]:
        result = set()
        for item in items:
            s = item.lower().strip("/~ ")
            result.add(s)
            # Add parent paths too
            parts = re.split(r"[/\\]", s)
            if len(parts) > 1:
                result.add(parts[0])
        return result

    na, nb = normalize(a), normalize(b)

    # Count fuzzy matches
    matched = 0
    for x in na:
        if any(x in y or y in x for y in nb):
            matched += 1

    union = len(na | nb)
    return matched / union if union > 0 else 1.0


# ─────────────────────────────────────────────────────────────────────────────
# Over-reach scoring
# ─────────────────────────────────────────────────────────────────────────────

_DIM_WEIGHTS = {
    "file_read":  0.20,
    "file_write": 0.15,
    "network":    0.35,
    "subprocess": 0.20,
    "env":        0.10,
}


def _over_reach_score(nl_caps: NLCapabilitySet, code_caps: CodeCapabilitySet) -> tuple[float, list[str]]:
    """
    Compute over-reach: capabilities in code but NOT in NL declarations.
    Returns (over_reach_score, list_of_gap_descriptions).
    """
    gaps: list[str] = []
    weighted_sum = 0.0

    # File reads
    nl_reads  = nl_caps.file_read_scopes  or []
    code_reads = code_caps.file_read_scopes or []
    for scope in code_reads:
        if _is_high_risk_scope(scope) and not any(
            scope.lower() in d.lower() or d.lower() in scope.lower()
            for d in nl_reads
        ):
            gaps.append(f"file_read: '{scope}' not declared in NL")
            weighted_sum += _DIM_WEIGHTS["file_read"] * 1.5   # sensitive path amplifier

    # File writes
    nl_writes  = nl_caps.file_write_scopes  or []
    code_writes = code_caps.file_write_scopes or []
    for scope in code_writes:
        if not any(
            scope.lower() in d.lower() or d.lower() in scope.lower()
            for d in nl_writes
        ) and not _is_benign_scope(scope):
            gaps.append(f"file_write: '{scope}' not declared in NL")
            weighted_sum += _DIM_WEIGHTS["file_write"]

    # Network
    nl_domains   = nl_caps.network_domains  or []
    code_domains = code_caps.network_domains or []
    for domain in code_domains:
        if domain in ("localhost", "127.0.0.1", "unknown_domain"):
            continue
        if not any(
            domain.lower() in d.lower() or d.lower() in domain.lower()
            for d in nl_domains
        ) and EXTERNAL_DOMAIN_RE.search(f"https://{domain}"):
            gaps.append(f"network: '{domain}' not declared in NL")
            weighted_sum += _DIM_WEIGHTS["network"]

    # Subprocess
    nl_cmds   = nl_caps.subprocess_cmds  or []
    code_cmds = code_caps.subprocess_cmds or []
    for cmd in code_cmds:
        cmd_base = cmd.split()[0] if cmd.split() else cmd
        if ("eval" in cmd_base or "exec" in cmd_base) and not nl_cmds:
            gaps.append(f"subprocess: dangerous eval/exec not declared")
            weighted_sum += _DIM_WEIGHTS["subprocess"] * 1.5
        elif not any(
            cmd_base.lower() in c.lower() or c.lower() in cmd_base.lower()
            for c in nl_cmds
        ) and cmd_base not in ("python", "python3", "pip", "git", "node", "npm"):
            gaps.append(f"subprocess: '{cmd_base}' not declared in NL")
            weighted_sum += _DIM_WEIGHTS["subprocess"] * 0.5

    return round(min(1.0, weighted_sum), 3), gaps


# ─────────────────────────────────────────────────────────────────────────────
# Main CMIA computation
# ─────────────────────────────────────────────────────────────────────────────

def compute_cmia(
    graph: HASG,
    nl_caps: NLCapabilitySet,
    code_caps: CodeCapabilitySet,
) -> CMIAScore:
    """
    Compute the CMIA score.
    Higher score = more suspicious misalignment.
    """
    # Alignment scores per dimension
    align_file_read  = _jaccard_sim(nl_caps.file_read_scopes,  code_caps.file_read_scopes)
    align_file_write = _jaccard_sim(nl_caps.file_write_scopes, code_caps.file_write_scopes)
    align_network    = _jaccard_sim(nl_caps.network_domains,   code_caps.network_domains)
    align_subprocess = _jaccard_sim(nl_caps.subprocess_cmds,   code_caps.subprocess_cmds)

    # Weighted alignment (network misalignment is most suspicious)
    align_overall = (
        _DIM_WEIGHTS["file_read"]  * align_file_read  +
        _DIM_WEIGHTS["file_write"] * align_file_write +
        _DIM_WEIGHTS["network"]    * align_network    +
        _DIM_WEIGHTS["subprocess"] * align_subprocess
    )

    # Over-reach
    over_reach, gaps = _over_reach_score(nl_caps, code_caps)

    # misalign edge count from graph
    misalign_count = len(graph.misalign_edges())

    # CMIA formula: higher gap + lower alignment + more misalign edges = worse
    alpha = 0.60  # weight for over-reach vs alignment
    cmia_raw = alpha * over_reach + (1 - alpha) * (1 - align_overall)

    # Amplify when analyzability is low (we can't fully see code capabilities)
    if code_caps.analyzability < 0.8:
        amplifier = 1.0 + (0.8 - code_caps.analyzability) * 0.5
        cmia_raw = min(1.0, cmia_raw * amplifier)

    # Boost from misalign edge density
    if misalign_count > 0:
        cmia_raw = min(1.0, cmia_raw + misalign_count * 0.05)

    return CMIAScore(
        overall=round(cmia_raw, 3),
        over_reach_score=over_reach,
        align_score=round(align_overall, 3),
        capability_gaps=gaps[:8],
        misalign_count=misalign_count,
    )
