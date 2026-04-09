"""
PRISM HASG Visualizer
Generates a standalone interactive HTML file (vis.js, no extra Python deps)
and/or prints a Rich terminal summary.
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

from .models import HASG, HAsgEdgeType, HAsgNodeType

# ── Color palettes ────────────────────────────────────────────────────────────

_NODE_COLOR: dict[str, dict] = {
    HAsgNodeType.NL_DIRECTIVE.value:  {"background": "#4A90D9", "border": "#2C6FAC", "font": "#fff"},
    HAsgNodeType.NL_TRIGGER.value:    {"background": "#9B59B6", "border": "#6C3483", "font": "#fff"},
    HAsgNodeType.NL_AGENT_CALL.value: {"background": "#1ABC9C", "border": "#148F77", "font": "#fff"},
    HAsgNodeType.CODE_BLOCK.value:    {"background": "#2ECC71", "border": "#1A8A4A", "font": "#fff"},
    HAsgNodeType.SYS_OP.value:        {"background": "#E74C3C", "border": "#A93226", "font": "#fff"},
    HAsgNodeType.NET_OP.value:        {"background": "#E67E22", "border": "#A04000", "font": "#fff"},
    HAsgNodeType.IO_OP.value:         {"background": "#F39C12", "border": "#9A6300", "font": "#222"},
    HAsgNodeType.ENV_OP.value:        {"background": "#EC407A", "border": "#AD1457", "font": "#fff"},
    HAsgNodeType.PERM_NODE.value:     {"background": "#95A5A6", "border": "#626567", "font": "#fff"},
}

# NL-only mode: color + shape by action_type
_NL_ACTION_STYLE: dict[str, dict] = {
    "subprocess":       {"bg": "#7B241C", "border": "#C0392B", "font": "#fff", "shape": "box"},
    "file_op":          {"bg": "#784212", "border": "#D35400", "font": "#fff", "shape": "database"},
    "net_op":           {"bg": "#154360", "border": "#2471A3", "font": "#fff", "shape": "hexagon"},
    "condition":        {"bg": "#512E5F", "border": "#8E44AD", "font": "#fff", "shape": "diamond"},
    "agent_capability": {"bg": "#0B5345", "border": "#1ABC9C", "font": "#fff", "shape": "ellipse"},
    "display":          {"bg": "#1A2F45", "border": "#5D8AA8", "font": "#cde", "shape": "box"},
    "other":            {"bg": "#2C3E50", "border": "#566573", "font": "#999", "shape": "ellipse"},
}

_NL_ACTION_ICON: dict[str, str] = {
    "subprocess":       "⚙",
    "file_op":          "F",
    "net_op":           "N",
    "condition":        "?",
    "agent_capability": "A",
    "display":          "V",
    "other":            "",
}

_EDGE_STYLE: dict[str, dict] = {
    HAsgEdgeType.NL_FLOW.value:    {"color": "#4A90D9", "dashes": False, "width": 2},
    HAsgEdgeType.NL_INVOKES.value: {"color": "#1ABC9C", "dashes": [8, 4], "width": 2},
    HAsgEdgeType.CTRL_FLOW.value:  {"color": "#2ECC71", "dashes": False, "width": 2},
    HAsgEdgeType.DATA_FLOW.value:  {"color": "#00BCD4", "dashes": [4, 4], "width": 1},
    HAsgEdgeType.TAINT.value:      {"color": "#FF9800", "dashes": [6, 3], "width": 3},
    HAsgEdgeType.COVERS.value:     {"color": "#95A5A6", "dashes": [3, 3], "width": 1},
    HAsgEdgeType.MISALIGN.value:   {"color": "#E74C3C", "dashes": [8, 4], "width": 4},
}

_NODE_LABEL = {
    HAsgNodeType.NL_DIRECTIVE.value:  "NL-Dir",
    HAsgNodeType.NL_TRIGGER.value:    "NL-Trig",
    HAsgNodeType.NL_AGENT_CALL.value: "NL-Agent",
    HAsgNodeType.CODE_BLOCK.value:    "CodeBlock",
    HAsgNodeType.SYS_OP.value:        "SysOp",
    HAsgNodeType.NET_OP.value:        "NetOp",
    HAsgNodeType.IO_OP.value:         "IOOp",
    HAsgNodeType.ENV_OP.value:        "EnvOp",
    HAsgNodeType.PERM_NODE.value:     "Perm",
}


def _nl_node_label(node) -> str:
    """Build a compact 1-2 line label for NL-only nodes."""
    import os
    action = node.features.get("action_type", "other")
    icon   = _NL_ACTION_ICON.get(action, "")
    cmd    = node.features.get("command", "") or ""
    target = node.features.get("target",  "") or ""

    # Line 2: most specific content available
    if cmd:
        # Show just the script filename + first arg hint
        parts  = cmd.split()
        script = os.path.basename(parts[0]) if parts else cmd
        args   = " ".join(parts[1:])[:14] if len(parts) > 1 else ""
        body   = (script + (" " + args if args else ""))[:22]
    elif target:
        body = os.path.basename(target)[:22] or target[:22]
    else:
        body = node.label[:22]

    prefix = f"[{icon}] " if icon else ""
    return f"{prefix}{body}"


# ── HTML generation ───────────────────────────────────────────────────────────

def _build_vis_data(graph: HASG, nl_only: bool = False) -> tuple[list, list]:
    """Convert HASG to vis.js nodes/edges dicts."""
    vis_nodes = []
    for node in graph.nodes.values():
        nt     = node.node_type.value
        action = node.features.get("action_type", "") if nl_only else ""
        risk   = node.risk_score

        # ── Color + shape ────────────────────────────────────────────────────
        if nl_only and action in _NL_ACTION_STYLE:
            s      = _NL_ACTION_STYLE[action]
            bg     = s["bg"]
            border = s["border"]
            fc     = s["font"]
            shape  = s["shape"]
        else:
            palette = _NODE_COLOR.get(nt, {"background": "#555", "border": "#333", "font": "#fff"})
            bg     = palette["background"]
            border = palette["border"]
            fc     = palette["font"]
            shape  = "ellipse" if nt.startswith("nl_") else "box"

        # ── Label ────────────────────────────────────────────────────────────
        if nl_only:
            label = _nl_node_label(node)
        else:
            label = textwrap.shorten(node.label, width=26, placeholder="…")

        # ── Tooltip ──────────────────────────────────────────────────────────
        tooltip_lines = [f"<b>#{node.line} {action or nt}</b>", f"{node.label}"]
        if node.features.get("command"):
            tooltip_lines.append(f"<code>{node.features['command']}</code>")
        if node.features.get("target"):
            tooltip_lines.append(f"→ {node.features['target']}")
        if node.features.get("resource_scope"):
            tooltip_lines.append(f"scope: {node.features['resource_scope']}")
        if risk > 0:
            tooltip_lines.append(f"risk: {risk:.2f}")
        if node.is_tainted:
            tooltip_lines.append("<span style='color:#FF9800'>⚠ TAINTED</span>")

        vis_nodes.append({
            "id":    node.id,
            "label": label,
            "title": "<br>".join(tooltip_lines),
            "color": {
                "background": bg,
                "border":     border,
                "highlight":  {"background": "#ffffff22", "border": border},
                "hover":      {"background": "#ffffff18", "border": border},
            },
            "font":  {"color": fc, "size": 12, "face": "monospace" if action == "subprocess" else "sans-serif"},
            "shape": shape,
            "group": action if nl_only else nt,
            # Fixed width for box shapes; size for circle/ellipse
            **({"widthConstraint": {"minimum": 110, "maximum": 180}} if shape in ("box", "database") else {"size": 20 + int(risk * 20)}),
        })

    vis_edges = []
    for i, edge in enumerate(graph.edges):
        et    = edge.edge_type.value
        style = _EDGE_STYLE.get(et, {"color": "#aaa", "dashes": False, "width": 1})
        # Branch-aware styling for NL_FLOW edges
        edge_label_text = edge.label or ""
        if et == HAsgEdgeType.NL_FLOW.value:
            if edge_label_text == "true":
                color_val = "#22c55e"   # green — condition true branch
                dashes_val = False
                width_val  = 2
                show_label = True
            elif edge_label_text == "skip":
                color_val = "#f97316"   # orange — condition skip/false branch
                dashes_val = [7, 4]
                width_val  = 2
                show_label = True
            else:  # "next" or empty — regular sequential flow
                color_val = style["color"]
                dashes_val = style["dashes"]
                width_val  = style["width"]
                show_label = False      # hide "next" label to reduce clutter
        else:
            color_val  = style["color"]
            dashes_val = style["dashes"]
            width_val  = style["width"]
            show_label = not nl_only

        vis_edges.append({
            "id":    i,
            "from":  edge.from_id,
            "to":    edge.to_id,
            "label": (edge_label_text if show_label else ""),
            "title": f"<b>{et}</b>" + (f"<br>{edge_label_text}" if edge_label_text else ""),
            "color": {"color": color_val, "highlight": color_val, "opacity": 0.75},
            "dashes": dashes_val,
            "width":  width_val,
            "arrows": "to",
            "font":   {"size": 10, "color": color_val, "strokeWidth": 0, "align": "middle",
                       "bold": {"color": color_val, "size": 11}},
            "smooth": (
                {"type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.5}
                if nl_only else
                {"type": "curvedCW", "roundness": 0.15}
            ),
        })

    return vis_nodes, vis_edges


def _legend_html(nl_only: bool = False) -> str:
    if nl_only:
        # Legend by action_type
        _SHAPE_CSS = {
            "box": "border-radius:2px", "database": "border-radius:3px 3px 6px 6px",
            "hexagon": "clip-path:polygon(25% 0%,75% 0%,100% 50%,75% 100%,25% 100%,0% 50%)",
            "diamond": "transform:rotate(45deg)", "ellipse": "border-radius:50%",
        }
        node_items = "".join(
            f'<div class="leg-item">'
            f'<span class="leg-dot" style="background:{v["bg"]};border:2px solid {v["border"]};{_SHAPE_CSS.get(v["shape"],"")}"></span>'
            f'{_NL_ACTION_ICON.get(k,"")} {k}</div>'
            for k, v in _NL_ACTION_STYLE.items()
        )
    else:
        node_items = "".join(
            f'<div class="leg-item"><span class="leg-dot" style="background:{v["background"]};'
            f'border:2px solid {v["border"]}"></span>{_NODE_LABEL[k]}</div>'
            for k, v in _NODE_COLOR.items()
        )
    edge_items = "".join(
        f'<div class="leg-item"><span class="leg-line" style="background:{v["color"]};'
        f'opacity:{0.6 if v["dashes"] else 1}"></span>'
        f'{"~ " if v["dashes"] else ""}{k}</div>'
        for k, v in _EDGE_STYLE.items()
    )
    if nl_only:
        edge_items += (
            '<div class="leg-item"><span class="leg-line" style="background:#22c55e"></span>true branch</div>'
            '<div class="leg-item"><span class="leg-line" style="background:#f97316;opacity:0.7"></span>~ skip branch</div>'
        )
    return f"""
    <div id="legend">
      <b>{'Action Types' if nl_only else 'Node Types'}</b>
      {node_items}
      <hr style="border-color:#333;margin:8px 0">
      <b>Edges</b>
      {edge_items}
    </div>"""


def generate_html(
    graph: HASG,
    skill_name: str = "",
    layout: str = "force",
    nl_only: bool = False,
) -> str:
    """
    Return a full standalone HTML string for the HASG interactive graph.
    layout: "force" (physics) | "hierarchical" (LR DAG, no physics)
    nl_only: use action_type color/shape scheme instead of node_type scheme
    """
    vis_nodes, vis_edges = _build_vis_data(graph, nl_only=nl_only)
    nodes_json = json.dumps(vis_nodes, ensure_ascii=False)
    edges_json = json.dumps(vis_edges, ensure_ascii=False)

    misalign_count = len(graph.misalign_edges())
    taint_count    = len(graph.taint_edges())
    title = f"PRISM HASG — {skill_name}" if skill_name else "PRISM HASG"
    legend = _legend_html(nl_only=nl_only)

    # Layout-specific JS options
    if layout == "hierarchical":
        layout_js = """\
    layout: {
      hierarchical: {
        enabled: true,
        direction: 'LR',
        sortMethod: 'directed',
        nodeSpacing: 60,
        levelSeparation: 220,
        treeSpacing: 80,
        blockShifting: true,
        edgeMinimization: true,
        parentCentralization: true,
      }
    },
    physics: { enabled: false },"""
        toggle_btn = ""
        fit_btn = '<button onclick="network.fit()">⟳ Fit all</button>'
    else:
        layout_js = """\
    physics: {
      enabled: true,
      solver: 'forceAtlas2Based',
      forceAtlas2Based: { gravitationalConstant: -55, springLength: 130, springConstant: 0.07 },
      stabilization: { iterations: 300 },
    },"""
        toggle_btn = '<button onclick="togglePhysics()">⚙ Toggle physics</button>'
        fit_btn    = '<button onclick="network.fit()">⟳ Fit all</button>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<script src="https://cdn.jsdelivr.net/npm/vis-network@9.1.9/dist/vis-network.min.js"></script>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#111827;color:#e5e7eb;font-family:'Segoe UI',system-ui,sans-serif;height:100vh;display:flex;flex-direction:column}}
  #header{{
    padding:10px 18px;background:#1f2937;border-bottom:1px solid #374151;
    display:flex;align-items:center;gap:12px;flex-shrink:0;
  }}
  #header h1{{font-size:1rem;color:#f3f4f6;font-weight:600;letter-spacing:.02em}}
  .badge{{padding:2px 9px;border-radius:10px;font-size:0.72rem;font-weight:600}}
  .badge-info{{background:#1e3a5f;color:#93c5fd}}
  .badge-warn{{background:#7c2d12;color:#fed7aa}}
  .badge-danger{{background:#7f1d1d;color:#fca5a5}}
  #main{{display:flex;flex:1;overflow:hidden}}
  #network{{flex:1;background:#0f172a}}
  #sidebar{{
    width:220px;background:#1f2937;border-left:1px solid #374151;
    overflow-y:auto;padding:10px;flex-shrink:0;font-size:0.74rem;
  }}
  #legend b{{display:block;margin:6px 0 4px;color:#9ca3af;text-transform:uppercase;letter-spacing:.05em;font-size:0.68rem}}
  .leg-item{{display:flex;align-items:center;gap:6px;margin:3px 0;color:#d1d5db}}
  .leg-dot{{width:12px;height:12px;flex-shrink:0}}
  .leg-line{{width:18px;height:2px;flex-shrink:0}}
  #info-panel{{margin-top:12px;border-top:1px solid #374151;padding-top:10px}}
  #info-panel h3{{font-size:0.74rem;margin-bottom:6px;color:#60a5fa;text-transform:uppercase;letter-spacing:.05em}}
  #node-detail{{color:#9ca3af;line-height:1.6;word-break:break-word}}
  #node-detail .nd-type{{color:#34d399;font-weight:600;margin-bottom:4px}}
  #node-detail .nd-cmd{{color:#fbbf24;font-family:monospace;font-size:0.72rem;background:#111827;padding:3px 6px;border-radius:3px;margin:3px 0;display:block}}
  #node-detail .nd-text{{color:#d1d5db;font-size:0.72rem}}
  #controls{{margin-bottom:10px;border-bottom:1px solid #374151;padding-bottom:10px}}
  #controls button{{
    display:block;width:100%;margin:3px 0;padding:5px 8px;
    background:#374151;border:none;color:#9ca3af;
    border-radius:4px;cursor:pointer;font-size:0.72rem;text-align:left;
  }}
  #controls button:hover{{background:#4b5563;color:#f3f4f6}}
</style>
</head>
<body>
<div id="header">
  <h1>{title}</h1>
  <span class="badge badge-info">{len(graph.nodes)} nodes</span>
  <span class="badge badge-info">{len(graph.edges)} edges</span>
  {"" if not misalign_count else f'<span class="badge badge-danger">⚠ {misalign_count} misalign</span>'}
  {"" if not taint_count    else f'<span class="badge badge-warn">⚡ {taint_count} taint</span>'}
  <span style="margin-left:auto;color:#6b7280;font-size:0.7rem">Scroll to zoom · Drag to pan · Click node for details</span>
</div>
<div id="main">
  <div id="network"></div>
  <div id="sidebar">
    <div id="controls">
      {fit_btn}
      {toggle_btn}
    </div>
    {legend}
    <div id="info-panel">
      <h3>Node detail</h3>
      <div id="node-detail" style="color:#4b5563;font-style:italic">Click a node</div>
    </div>
  </div>
</div>
<script>
const nodesData = {nodes_json};
const edgesData = {edges_json};

const container = document.getElementById('network');
const data = {{
  nodes: new vis.DataSet(nodesData),
  edges: new vis.DataSet(edgesData),
}};
const options = {{
  {layout_js}
  interaction: {{
    hover: true, tooltipDelay: 80,
    navigationButtons: false, keyboard: true,
    zoomView: true, dragView: true,
  }},
  nodes: {{
    borderWidth: 2,
    borderWidthSelected: 3,
    shadow: false,
  }},
  edges: {{
    selectionWidth: 3,
    hoverWidth: 1.5,
    arrows: {{ to: {{ scaleFactor: 0.7 }} }},
  }},
}};
const network = new vis.Network(container, data, options);

let physicsOn = true;
function togglePhysics() {{
  physicsOn = !physicsOn;
  network.setOptions({{ physics: {{ enabled: physicsOn }} }});
}}

// Node click → rich detail panel
const nodeMap = Object.fromEntries(nodesData.map(n => [n.id, n]));
network.on('click', params => {{
  if (!params.nodes.length) return;
  const n = nodeMap[params.nodes[0]];
  if (!n) return;
  // Parse tooltip HTML into structured detail
  const raw = (n.title || '').split('<br>');
  let html = '';
  raw.forEach((line, i) => {{
    const clean = line.replace(/<[^>]+>/g, '').trim();
    if (!clean) return;
    if (i === 0) html += `<div class="nd-type">${{clean}}</div>`;
    else if (clean.startsWith('Command:') || line.includes('<code>'))
      html += `<span class="nd-cmd">${{clean.replace('Command:','').trim()}}</span>`;
    else
      html += `<div class="nd-text">${{clean}}</div>`;
  }});
  document.getElementById('node-detail').innerHTML = html || '<span style="color:#4b5563">No detail</span>';
}});

// Double-click to focus subgraph
network.on('doubleClick', params => {{
  if (params.nodes.length) network.focus(params.nodes[0], {{scale:1.4, animation:true}});
}});
</script>
</body>
</html>
"""


# ── Terminal summary (Rich) ───────────────────────────────────────────────────

def print_rich_graph(graph: HASG) -> None:
    """Print a detailed HASG summary to the terminal using Rich."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text
        from rich import box
        from collections import Counter
    except ImportError:
        _print_plain_graph(graph)
        return

    console = Console()

    # ── Stats header ─────────────────────────────────────────────────────────
    node_counts = Counter(n.node_type.value for n in graph.nodes.values())
    edge_counts = Counter(e.edge_type.value for e in graph.edges)
    misalign    = graph.misalign_edges()
    tainted     = [n for n in graph.nodes.values() if n.is_tainted]

    summary = Text()
    summary.append(f"Nodes: {len(graph.nodes)}  ", style="bold cyan")
    summary.append(f"Edges: {len(graph.edges)}  ", style="bold cyan")
    if misalign:
        summary.append(f"⚠ Misalign: {len(misalign)}  ", style="bold red")
    if tainted:
        summary.append(f"⚡ Tainted: {len(tainted)}", style="bold yellow")

    console.print(Panel(summary, title="[bold]HASG Overview[/bold]", border_style="blue"))

    # ── Node table ───────────────────────────────────────────────────────────
    _TYPE_STYLE = {
        "nl_directive":  "blue",   "nl_trigger":    "magenta",
        "nl_agent_call": "cyan",   "code_block":    "green",
        "sys_op":        "red",    "net_op":        "yellow",
        "io_op":         "bright_yellow", "env_op": "bright_magenta",
        "perm_node":     "white",
    }
    node_table = Table(box=box.SIMPLE_HEAVY, border_style="blue", show_header=True, header_style="bold")
    node_table.add_column("Type",     style="dim", width=14)
    node_table.add_column("Label",    width=36)
    node_table.add_column("File",     width=22)
    node_table.add_column("Risk",     width=5, justify="right")
    node_table.add_column("Flags",    width=10)

    for node in sorted(graph.nodes.values(), key=lambda n: (-n.risk_score, n.node_type.value)):
        nt   = node.node_type.value
        col  = _TYPE_STYLE.get(nt, "white")
        risk = node.risk_score
        risk_col = "red" if risk >= 0.7 else ("yellow" if risk >= 0.4 else "green")
        flags = ""
        if node.is_tainted: flags += "[yellow]⚡[/yellow]"
        node_table.add_row(
            f"[{col}]{nt}[/{col}]",
            textwrap.shorten(node.label, 36, placeholder="…"),
            f"{node.file}:{node.line}" if node.file else "",
            f"[{risk_col}]{risk:.2f}[/{risk_col}]",
            flags,
        )
    console.print(Panel(node_table, title="[bold]Nodes[/bold]", border_style="blue"))

    # ── Edge table ───────────────────────────────────────────────────────────
    _EDGE_STYLE_TERM = {
        "nl_flow":    "blue",  "nl_invokes": "cyan",  "ctrl_flow": "green",
        "data_flow":  "cyan",  "taint":      "yellow", "covers":   "white",
        "misalign":   "red",
    }
    edge_table = Table(box=box.SIMPLE_HEAVY, border_style="blue", show_header=True, header_style="bold")
    edge_table.add_column("Type",   style="dim", width=12)
    edge_table.add_column("From",   width=30)
    edge_table.add_column("→ To",   width=30)
    edge_table.add_column("Label",  width=16)

    for edge in graph.edges:
        et   = edge.edge_type.value
        col  = _EDGE_STYLE_TERM.get(et, "white")
        src  = graph.nodes.get(edge.from_id)
        dst  = graph.nodes.get(edge.to_id)
        src_label = textwrap.shorten(src.label if src else edge.from_id, 30, placeholder="…")
        dst_label = textwrap.shorten(dst.label if dst else edge.to_id,   30, placeholder="…")
        edge_table.add_row(
            f"[{col}]{et}[/{col}]",
            src_label, dst_label,
            edge.label or "",
        )
    console.print(Panel(edge_table, title="[bold]Edges[/bold]", border_style="blue"))

    # ── Misalign spotlight ───────────────────────────────────────────────────
    if misalign:
        console.print(Panel(
            "\n".join(
                f"[red]⚠[/red]  {textwrap.shorten(graph.nodes[e.from_id].label if e.from_id in graph.nodes else e.from_id, 35)}  →  "
                f"{textwrap.shorten(graph.nodes[e.to_id].label   if e.to_id   in graph.nodes else e.to_id,   35, placeholder='…')}"
                for e in misalign
            ),
            title="[bold red]Misalignment Edges (code undeclared in NL)[/bold red]",
            border_style="red",
        ))


def _print_plain_graph(graph: HASG) -> None:
    """Fallback plain-text summary (no Rich)."""
    from collections import Counter
    nc = Counter(n.node_type.value for n in graph.nodes.values())
    ec = Counter(e.edge_type.value for e in graph.edges)
    print(f"\n  HASG: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    print("  Node types:", "  ".join(f"{t}:{c}" for t, c in sorted(nc.items())))
    print("  Edge types:", "  ".join(f"{t}:{c}" for t, c in sorted(ec.items())))
    for node in sorted(graph.nodes.values(), key=lambda n: -n.risk_score):
        flag = " [TAINTED]" if node.is_tainted else ""
        print(f"    [{node.node_type.value}] {node.label[:50]}  risk={node.risk_score:.2f}{flag}")
    for edge in graph.edges:
        src = graph.nodes.get(edge.from_id)
        dst = graph.nodes.get(edge.to_id)
        print(f"    {edge.edge_type.value}: {src.label[:25] if src else '?'} → {dst.label[:25] if dst else '?'}")


# ── instruction_units detail (for NL-only mode) ───────────────────────────────

def print_instruction_units(wf_extract) -> None:
    """Print extracted instruction_units in a Rich table for review."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich import box

        console = Console()
        table = Table(box=box.SIMPLE_HEAVY, border_style="blue", header_style="bold",
                      show_header=True, show_lines=True)
        table.add_column("#",             width=3,  justify="right")
        table.add_column("action_type",   width=16)
        table.add_column("Text",          width=40)
        table.add_column("command",       width=28)
        table.add_column("target",        width=22)
        table.add_column("cond?",         width=5, justify="center")
        table.add_column("explicit?",     width=8, justify="center")

        _ACTION_COLORS = {
            "file_op":          "yellow",
            "net_op":           "cyan",
            "subprocess":       "red",
            "agent_capability": "magenta",
            "display":          "green",
            "condition":        "blue",
            "other":            "white",
        }

        for u in wf_extract.instruction_units:
            col = _ACTION_COLORS.get(u.action_type, "white")
            cond = "[yellow]Y[/yellow]" if u.is_conditional else "N"
            expl = "[green]Y[/green]" if u.is_explicit else "[red]N[/red]"
            cmd_str = getattr(u, "command", "") or ""
            tgt_str = getattr(u, "target", "") or ""
            table.add_row(
                str(u.step_index),
                f"[{col}]{u.action_type}[/{col}]",
                u.text[:40],
                cmd_str[:28],
                tgt_str[:22],
                cond,
                expl,
            )

        console.print(Panel(
            table,
            title=f"[bold]LLM-Extracted instruction_units ({len(wf_extract.instruction_units)} steps)[/bold]",
            border_style="cyan",
        ))
        console.print(f"  [dim]Declared purpose: {wf_extract.declared_purpose}[/dim]\n")

    except ImportError:
        print(f"\n  instruction_units ({len(wf_extract.instruction_units)} steps):")
        for u in wf_extract.instruction_units:
            cond = " [COND]" if u.is_conditional else ""
            print(f"  {u.step_index:2d}. [{u.action_type}]{cond} {u.text[:60]}  scope={u.resource_scope}")


# ── Public entry point ────────────────────────────────────────────────────────

def visualize(
    skill_path: Path,
    output_html: Path | None = None,
    open_browser: bool = True,
    terminal: bool = True,
) -> Path | None:
    """
    Build HASG for skill_path and visualize.
    - terminal=True  → Rich terminal summary
    - output_html    → write interactive HTML; opens browser if open_browser=True
    Returns the HTML path if generated.
    """
    from .hasg_builder import build_hasg

    graph, _, _nl, _code = build_hasg(skill_path)

    if terminal:
        print_rich_graph(graph)

    if output_html is not None:
        html = generate_html(graph, skill_name=skill_path.name, layout="hierarchical")
        output_html.parent.mkdir(parents=True, exist_ok=True)
        output_html.write_text(html, encoding="utf-8")
        print(f"\n  [viz] HTML graph → {output_html}")
        if open_browser:
            import webbrowser
            webbrowser.open(output_html.resolve().as_uri())
        return output_html

    return None


def visualize_nl(
    skill_path: Path,
    output_html: Path | None = None,
    open_browser: bool = True,
    terminal: bool = True,
) -> Path | None:
    """
    Build NL-only HASG from SKILL.md and visualize.
    Always prints instruction_units detail table for review.
    - terminal=True  → Rich NL graph summary + instruction_units table
    - output_html    → write interactive HTML (NL nodes only)
    """
    from .hasg_builder import build_nl_graph

    graph, wf_extract, _nl_caps = build_nl_graph(skill_path)

    print_instruction_units(wf_extract)

    if terminal:
        print_rich_graph(graph)

    if output_html is not None:
        html = generate_html(
            graph,
            skill_name=f"{skill_path.name} [NL only]",
            layout="hierarchical",
            nl_only=True,
        )
        output_html.parent.mkdir(parents=True, exist_ok=True)
        output_html.write_text(html, encoding="utf-8")
        print(f"\n  [viz] NL-only HTML graph → {output_html}")
        if open_browser:
            import webbrowser
            webbrowser.open(output_html.resolve().as_uri())
        return output_html

    return None
