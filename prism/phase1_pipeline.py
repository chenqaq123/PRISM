"""
Phase 1c: Pipeline Analysis
Analyzes the workflow graph (HASG) for multi-step attack chains.

Unlike pattern matching (1a) and taint propagation (1b) which operate on
individual nodes/edges, pipeline analysis traverses the graph to detect
dangerous sequential patterns: e.g., a credential read that flows to an
encode step that flows to an external network send.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .hasg_builder import HASG, HAsgNode, HAsgNodeType, HAsgEdgeType
from .models import Finding, Severity, ThreatCategory

# ─────────────────────────────────────────────────────────────────────────────
# Dangerous graph patterns (chains we look for in the HASG)
# ─────────────────────────────────────────────────────────────────────────────

# Sensitive path prefixes that IO_OP nodes might reference
_SENSITIVE_PREFIXES = (
    ".ssh", ".aws", ".gnupg", ".netrc", ".git-credentials",
    ".env", "passwd", "shadow", "credentials", "token", "secret",
)

# External-looking URL substrings in NET_OP nodes
_EXTERNAL_URL_SIGNALS = ("http://", "https://", "ftp://", "tcp://")


def _node_is_sensitive_read(node: HAsgNode) -> bool:
    path = node.features.get("path", "").lower()
    return (
        node.node_type == HAsgNodeType.IO_OP
        and any(s in path for s in _SENSITIVE_PREFIXES)
    )


def _node_is_external_net(node: HAsgNode) -> bool:
    url = node.features.get("url", "").lower()
    return (
        node.node_type == HAsgNodeType.NET_OP
        and any(s in url for s in _EXTERNAL_URL_SIGNALS)
    )


def _node_is_sys_exec(node: HAsgNode) -> bool:
    return node.node_type == HAsgNodeType.SYS_OP


def _build_adjacency(graph: HASG) -> dict[str, list[str]]:
    """Build forward adjacency list from data_flow + ctrl_flow + taint edges."""
    adj: dict[str, list[str]] = {nid: [] for nid in graph.nodes}
    for edge in graph.edges:
        if edge.edge_type in (
            HAsgEdgeType.DATA_FLOW,
            HAsgEdgeType.CTRL_FLOW,
            HAsgEdgeType.TAINT,
        ):
            adj.setdefault(edge.from_id, []).append(edge.to_id)
    return adj


def _reachable(start: str, adj: dict[str, list[str]], max_depth: int = 5) -> set[str]:
    """BFS to find all nodes reachable from start within max_depth steps."""
    visited: set[str] = set()
    queue = [(start, 0)]
    while queue:
        nid, depth = queue.pop(0)
        if nid in visited or depth > max_depth:
            continue
        visited.add(nid)
        for neighbor in adj.get(nid, []):
            queue.append((neighbor, depth + 1))
    return visited


@dataclass
class _Chain:
    name:     str
    severity: Severity
    category: ThreatCategory
    desc:     str
    nodes:    list[str]  # node IDs involved


# ─────────────────────────────────────────────────────────────────────────────
# Chain detectors
# ─────────────────────────────────────────────────────────────────────────────

def _detect_credential_exfil_chain(
    graph: HASG, adj: dict[str, list[str]]
) -> list[_Chain]:
    """Detect: sensitive file read → (optional encode) → external network send."""
    chains: list[_Chain] = []
    sensitive_reads = [
        nid for nid, n in graph.nodes.items() if _node_is_sensitive_read(n)
    ]
    ext_nets = {
        nid for nid, n in graph.nodes.items() if _node_is_external_net(n)
    }
    for src in sensitive_reads:
        reachable = _reachable(src, adj, max_depth=6)
        hit = reachable & ext_nets
        if hit:
            src_node = graph.nodes[src]
            dst_node = graph.nodes[next(iter(hit))]
            chains.append(_Chain(
                name="Credential Exfiltration Pipeline",
                severity=Severity.CRITICAL,
                category=ThreatCategory.T1_CRED_THEFT,
                desc=(
                    f"Sensitive read «{src_node.features.get('path','?')}» "
                    f"({src_node.file}:{src_node.line}) flows to external network call "
                    f"«{dst_node.features.get('url','?')}» "
                    f"({dst_node.file}:{dst_node.line})"
                ),
                nodes=[src] + list(hit),
            ))
    return chains


def _detect_env_exfil_chain(
    graph: HASG, adj: dict[str, list[str]]
) -> list[_Chain]:
    """Detect: environment variable access → external network send."""
    chains: list[_Chain] = []
    env_nodes = [
        nid for nid, n in graph.nodes.items()
        if n.node_type == HAsgNodeType.ENV_OP
    ]
    ext_nets = {
        nid for nid, n in graph.nodes.items() if _node_is_external_net(n)
    }
    for src in env_nodes:
        reachable = _reachable(src, adj, max_depth=5)
        hit = reachable & ext_nets
        if hit:
            src_node = graph.nodes[src]
            dst_node = graph.nodes[next(iter(hit))]
            var = src_node.features.get("var_name", "?")
            url = dst_node.features.get("url", "?")
            chains.append(_Chain(
                name="Environment Variable Exfiltration",
                severity=Severity.HIGH,
                category=ThreatCategory.T3_DATA_EXFIL,
                desc=(
                    f"Env var «{var}» ({src_node.file}:{src_node.line}) "
                    f"flows to external endpoint «{url}» "
                    f"({dst_node.file}:{dst_node.line})"
                ),
                nodes=[src] + list(hit),
            ))
    return chains


def _detect_dynamic_exec_chain(
    graph: HASG, adj: dict[str, list[str]]
) -> list[_Chain]:
    """Detect: network fetch → dynamic eval/exec (possible remote code execution)."""
    chains: list[_Chain] = []
    net_nodes = [
        nid for nid, n in graph.nodes.items()
        if n.node_type == HAsgNodeType.NET_OP
    ]
    exec_nodes = {
        nid for nid, n in graph.nodes.items()
        if _node_is_sys_exec(n) and n.features.get("cmd_dynamic", False)
    }
    for src in net_nodes:
        reachable = _reachable(src, adj, max_depth=5)
        hit = reachable & exec_nodes
        if hit:
            src_node = graph.nodes[src]
            dst_node = graph.nodes[next(iter(hit))]
            chains.append(_Chain(
                name="Remote Code Fetch → Dynamic Execution",
                severity=Severity.CRITICAL,
                category=ThreatCategory.T5_RCE,
                desc=(
                    f"Network fetch ({src_node.file}:{src_node.line}) "
                    f"flows to dynamic exec/eval «{dst_node.label}» "
                    f"({dst_node.file}:{dst_node.line})"
                ),
                nodes=[src] + list(hit),
            ))
    return chains


def _detect_nl_step_escalation(graph: HASG) -> list[_Chain]:
    """
    Detect suspicious NL workflow escalation:
    NL directives that sequentially expand scope (agent-layer pipeline attack).
    Uses nl_flow edges to traverse NL step sequences and flags capability jumps.
    """
    chains: list[_Chain] = []

    # Build NL control flow adjacency
    nl_adj: dict[str, str] = {}
    for edge in graph.edges:
        if edge.edge_type == HAsgEdgeType.NL_FLOW:
            nl_adj[edge.from_id] = edge.to_id

    # Walk NL sequences; flag if misalign edges appear along the chain
    visited_nl: set[str] = set()
    misalign_targets = {e.to_id for e in graph.misalign_edges()}

    for start_id, node in graph.nodes.items():
        if node.node_type != HAsgNodeType.NL_DIRECTIVE or start_id in visited_nl:
            continue
        # Walk the chain from this start node
        chain_nodes: list[str] = []
        cur = start_id
        while cur and cur not in visited_nl:
            visited_nl.add(cur)
            chain_nodes.append(cur)
            cur = nl_adj.get(cur, "")

        # Count misalign-targeted nodes reachable in this NL chain
        chain_misaligns = [
            nid for nid in chain_nodes
            if nid in misalign_targets
        ]
        if len(chain_misaligns) >= 2 or (
            len(chain_nodes) >= 3 and len(chain_misaligns) >= 1
        ):
            labels = [
                graph.nodes[nid].label[:50]
                for nid in chain_nodes[:4]
                if nid in graph.nodes
            ]
            chains.append(_Chain(
                name="NL Workflow Escalation Chain",
                severity=Severity.HIGH,
                category=ThreatCategory.T10_NL_MISDIRECTION,
                desc=(
                    f"{len(chain_nodes)}-step NL chain with {len(chain_misaligns)} "
                    f"undeclared code capability misaligns. Steps: "
                    + " → ".join(f"«{l}»" for l in labels)
                ),
                nodes=chain_nodes,
            ))

    return chains


def _detect_persistence_chain(
    graph: HASG, adj: dict[str, list[str]]
) -> list[_Chain]:
    """Detect: write to startup/init files (persistence mechanism)."""
    PERSISTENCE_PATHS = (
        ".bashrc", ".bash_profile", ".zshrc", ".profile",
        "crontab", "authorized_keys", "rc.local",
        "autostart", "launchagent", "launchdaemon",
    )
    chains: list[_Chain] = []
    for nid, node in graph.nodes.items():
        if node.node_type != HAsgNodeType.IO_OP:
            continue
        path = node.features.get("path", "").lower()
        is_write = node.features.get("is_write", False)
        if is_write and any(p in path for p in PERSISTENCE_PATHS):
            chains.append(_Chain(
                name="Persistence Installation",
                severity=Severity.HIGH,
                category=ThreatCategory.T7_PERSISTENCE,
                desc=(
                    f"Write to persistence path «{node.features.get('path','?')}» "
                    f"at {node.file}:{node.line}"
                ),
                nodes=[nid],
            ))
    return chains


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def analyze_pipeline(graph: HASG) -> tuple[float, list[Finding]]:
    """
    Run Phase 1c: Pipeline Analysis.
    Returns (pipeline_score, findings).
    """
    adj = _build_adjacency(graph)

    all_chains: list[_Chain] = []
    all_chains.extend(_detect_credential_exfil_chain(graph, adj))
    all_chains.extend(_detect_env_exfil_chain(graph, adj))
    all_chains.extend(_detect_dynamic_exec_chain(graph, adj))
    all_chains.extend(_detect_nl_step_escalation(graph))
    all_chains.extend(_detect_persistence_chain(graph, adj))

    # Deduplicate by (category, first_node)
    seen: set[tuple] = set()
    unique: list[_Chain] = []
    for c in all_chains:
        key = (c.category, c.nodes[0] if c.nodes else "")
        if key not in seen:
            seen.add(key)
            unique.append(c)

    # Convert to Finding objects
    findings: list[Finding] = []
    for chain in unique:
        findings.append(Finding(
            severity=chain.severity,
            category=chain.category,
            description=chain.desc,
            analyzer="pipeline",
        ))

    # Score: max severity among chains, boosted by count
    if not unique:
        return 0.0, []

    sev_scores = {Severity.CRITICAL: 0.90, Severity.HIGH: 0.65, Severity.MEDIUM: 0.40}
    base = max(sev_scores.get(c.severity, 0.30) for c in unique)
    count_boost = min(0.10, 0.03 * (len(unique) - 1))
    score = round(min(1.0, base + count_boost), 3)

    return score, findings
