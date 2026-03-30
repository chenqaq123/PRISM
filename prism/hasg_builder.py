"""
HASG Builder
Constructs the Heterogeneous Attributed Skill Graph from (I, C, M).

Steps:
  1. Parse SKILL.md → NL nodes (Dir / Trig / AgentCall)
  2. Parse Python scripts → Code nodes (SysOp / NetOp / IOOp / EnvOp / CodeBlock)
  3. Extract capability sets from both layers
  4. Compute misalign edges (code capability not declared in NL)
  5. Serialize HASG as structured text for LLM consumption
"""
from __future__ import annotations

import ast
import math
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel

from .llm_client import chat_structured
from .models import (
    HASG, HAsgEdge, HAsgEdgeType, HAsgNode, HAsgNodeType,
    NLCapabilitySet, CodeCapabilitySet, InstructionUnit,
)

# ─────────────────────────────────────────────────────────────────────────────
# Sensitive path patterns
# ─────────────────────────────────────────────────────────────────────────────

SENSITIVE_PATH_RE = re.compile(
    r"\.ssh|\.aws|\.gnupg|credentials?|token|secret|password|api[_\-]?key"
    r"|private[_\-]?key|\.netrc|\.npmrc|\.pypirc|id_rsa|id_ed25519",
    re.IGNORECASE,
)
EXTERNAL_DOMAIN_RE = re.compile(
    r"https?://(?!(?:localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.))",
    re.IGNORECASE,
)
OBFUSC_ENCODING_RE = re.compile(
    r"\b(?:base64|b64decode|b64encode|zlib\.decompress|codecs\.decode|rot13|binascii)\b",
    re.IGNORECASE,
)

# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Parse SKILL.md → NL nodes
# ─────────────────────────────────────────────────────────────────────────────

class _WorkflowExtract(BaseModel):
    """LLM extraction of workflow from SKILL.md."""
    declared_purpose: str
    instruction_units: list[InstructionUnit]
    frontmatter_scope: str = ""   # declared scope from frontmatter


def parse_skill_md(skill_dir: Path) -> tuple[dict, _WorkflowExtract]:
    """Parse SKILL.md: returns (frontmatter_dict, workflow_extract)."""
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        raise FileNotFoundError(f"SKILL.md not found in {skill_dir}")

    content = skill_md.read_text(encoding="utf-8", errors="replace")

    # Parse frontmatter (cheap, no LLM)
    frontmatter: dict = {}
    fm_match = re.match(r"^---\n(.*?)\n---", content, re.DOTALL)
    if fm_match:
        frontmatter = yaml.safe_load(fm_match.group(1)) or {}

    prompt = f"""\
You are a security analyst. Extract ALL workflow steps from this SKILL.md.

For each step, identify:
- action_type: file_op / net_op / subprocess / agent_capability / display / condition / other
- resource_scope: what resource it touches (e.g. "project_dir", "~/.ssh", "external_api")
- is_explicit: is the operation clearly named (True) or vaguely described (False)?
- scope_vs_manifest: 0.0-1.0, how consistent is this step with the declared frontmatter scope

Also provide:
- declared_purpose: 1-2 sentence summary of what the skill claims to do
- frontmatter_scope: the scope declared in the frontmatter (e.g. "project directory", "user home")

SKILL.md content:
---
{content}
---
"""
    result = chat_structured(
        messages=[
            {"role": "system", "content": "You analyze AI agent skill definition files for security research."},
            {"role": "user", "content": prompt},
        ],
        response_model=_WorkflowExtract,
    )
    return frontmatter, result


# ─────────────────────────────────────────────────────────────────────────────
# Step 2: AST analysis → Code nodes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _RawCodeOp:
    """Raw operation extracted from Python AST."""
    op_type:  str          # "sys_op" | "net_op" | "io_op" | "env_op"
    label:    str
    file:     str
    line:     int
    path:     str  = ""
    url:      str  = ""
    cmd:      str  = ""
    var_name: str  = ""
    is_write: bool = False
    is_sensitive_path: bool  = False
    is_external_url:   bool  = False
    cmd_dynamic:       bool  = False   # argument is a variable, not a constant
    entropy:           float = 0.0


class _ASTCodeAnalyzer(ast.NodeVisitor):
    """Walks Python AST, extracts raw code operations."""

    SUBPROCESS_FNS = {
        "subprocess.run", "subprocess.call", "subprocess.Popen",
        "subprocess.check_output", "subprocess.check_call",
        "os.system", "os.popen", "system", "popen",
    }
    NETWORK_FNS = {
        "requests.get", "requests.post", "requests.put", "requests.delete",
        "requests.patch", "requests.request", "requests.Session",
        "urllib.request.urlopen", "urllib.urlopen", "httpx.get", "httpx.post",
        "http.client.HTTPConnection", "urlopen", "fetch",
    }

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.ops: list[_RawCodeOp] = []
        self._counter = 0
        self._env_vars: set[str] = set()   # variable names holding env values
        self._net_vars: set[str] = set()   # variable names holding network responses

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _fn_name(node) -> str:
        if isinstance(node, ast.Attribute):
            return f"{_ASTCodeAnalyzer._fn_name(node.value)}.{node.attr}"
        if isinstance(node, ast.Name):
            return node.id
        return ""

    @staticmethod
    def _str_val(node) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    @staticmethod
    def _is_var(node) -> bool:
        return isinstance(node, (ast.Name, ast.Attribute, ast.Subscript))

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((v / n) * math.log2(v / n) for v in freq.values())

    # ── Visitors ────────────────────────────────────────────────────────────

    def visit_Assign(self, node: ast.Assign):
        # Track variables that hold env values or network responses
        if isinstance(node.value, ast.Call):
            fn = self._fn_name(node.value.func) if hasattr(node.value, "func") else ""
            if "getenv" in fn or "environ" in fn:
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self._env_vars.add(t.id)
            if any(x in fn for x in ("requests.", "urlopen", "httpx.", "fetch")):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self._net_vars.add(t.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        fn  = self._fn_name(node.func) if hasattr(node, "func") else ""
        ln  = node.lineno

        # eval / exec / compile
        if fn in ("eval", "exec", "compile"):
            is_dyn = node.args and self._is_var(node.args[0])
            src    = self._str_val(node.args[0]) if node.args else ""
            self.ops.append(_RawCodeOp(
                op_type="sys_op", label=f"{fn}({src[:40] if src else '...'}))",
                file=self.filepath, line=ln, cmd=src, cmd_dynamic=is_dyn,
            ))

        # subprocess / os.system
        elif fn in self.SUBPROCESS_FNS or "subprocess" in fn:
            cmd = ""
            dyn = False
            if node.args:
                val = self._str_val(node.args[0])
                if val:
                    cmd = val
                elif self._is_var(node.args[0]):
                    dyn = True
            self.ops.append(_RawCodeOp(
                op_type="sys_op", label=f"{fn}({cmd[:40] or '...'}))",
                file=self.filepath, line=ln, cmd=cmd, cmd_dynamic=dyn,
            ))

        # Network calls
        elif any(x in fn for x in ("requests.", "urllib", "httpx.", "urlopen", "http.client")):
            url = ""
            if node.args:
                val = self._str_val(node.args[0])
                url = val or ""
            ext = bool(url and EXTERNAL_DOMAIN_RE.search(url))
            self.ops.append(_RawCodeOp(
                op_type="net_op", label=f"{fn}({url[:60] or '...'}))",
                file=self.filepath, line=ln, url=url, is_external_url=ext,
            ))

        # File I/O: open()
        elif fn == "open" or any(x in fn for x in ("read_text", "write_text", "read_bytes", "write_bytes")):
            path_val = ""
            is_write = False
            sens     = False
            if node.args:
                v = self._str_val(node.args[0])
                path_val = v or ""
                if path_val and SENSITIVE_PATH_RE.search(path_val):
                    sens = True
            if len(node.args) > 1:
                mode = self._str_val(node.args[1])
                if mode and any(c in mode for c in ("w", "a", "x")):
                    is_write = True
            self.ops.append(_RawCodeOp(
                op_type="io_op", label=f"{'write' if is_write else 'read'}({path_val[:50] or '...'}))",
                file=self.filepath, line=ln, path=path_val,
                is_write=is_write, is_sensitive_path=sens,
            ))

        # env access
        elif "getenv" in fn or fn in ("os.environ.get", "os.environ.__getitem__"):
            var_name = self._str_val(node.args[0]) if node.args else ""
            if var_name:
                self._env_vars.add(var_name)
            self.ops.append(_RawCodeOp(
                op_type="env_op", label=f"env[{var_name or '...'}]",
                file=self.filepath, line=ln, var_name=var_name,
            ))

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        ln = node.lineno if hasattr(node, "lineno") else 0

        if isinstance(node.value, str):
            s = node.value

            # ── High-entropy string (obfuscated payload candidate) ──────────
            if len(s) > 30:
                h = self._shannon_entropy(s)
                if h > 4.5:
                    if self.ops and self.ops[-1].op_type == "sys_op":
                        self.ops[-1].entropy = max(self.ops[-1].entropy, h)

            # ── Sensitive path fragment in any string constant ───────────────
            # Catches cases like: os.path.join(home, ".ssh", "id_rsa")
            # Even when the full path is never passed directly to open().
            if len(s) > 2 and SENSITIVE_PATH_RE.search(s):
                self.ops.append(_RawCodeOp(
                    op_type="io_op",
                    label=f"sensitive_ref({s[:50]})",
                    file=self.filepath,
                    line=ln,
                    path=s,
                    is_sensitive_path=True,
                    is_write=False,
                ))

            # ── External URL in string constant ─────────────────────────────
            if len(s) > 8 and EXTERNAL_DOMAIN_RE.search(s):
                self.ops.append(_RawCodeOp(
                    op_type="net_op",
                    label=f"url_literal({s[:60]})",
                    file=self.filepath,
                    line=ln,
                    url=s,
                    is_external_url=True,
                ))

        elif isinstance(node.value, bytes):
            # ── Base64-decode bytes constants to find hidden URLs/paths ──────
            # Catches: base64.b64decode(b"aHR0cHM6Ly9ldmlsLWMydC5leGFtcGxlLmNvbS9jb2xsZWN0")
            import base64 as _b64
            try:
                decoded = _b64.b64decode(node.value).decode("utf-8", errors="ignore")
                if EXTERNAL_DOMAIN_RE.search(decoded):
                    self.ops.append(_RawCodeOp(
                        op_type="net_op",
                        label=f"b64_url({decoded[:60]})",
                        file=self.filepath,
                        line=ln,
                        url=decoded,
                        is_external_url=True,
                    ))
                elif len(decoded) > 3 and SENSITIVE_PATH_RE.search(decoded):
                    self.ops.append(_RawCodeOp(
                        op_type="io_op",
                        label=f"b64_path({decoded[:50]})",
                        file=self.filepath,
                        line=ln,
                        path=decoded,
                        is_sensitive_path=True,
                    ))
            except Exception:
                pass

        self.generic_visit(node)


def analyze_python_file(filepath: Path) -> tuple[list[_RawCodeOp], float]:
    """
    Returns (raw_code_ops, analyzability_score).
    analyzability < 1.0 when obfuscation is detected.
    """
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return [], 0.0

    try:
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError:
        return [], 0.3   # can't parse → low analyzability

    analyzer = _ASTCodeAnalyzer(str(filepath))
    analyzer.visit(tree)

    # Compute analyzability deductions
    analyzability = 1.0
    if OBFUSC_ENCODING_RE.search(source):
        analyzability -= 0.25
    if "sys.meta_path" in source:
        analyzability -= 0.30
    if "__import__" in source:
        analyzability -= 0.15
    # Detect string concatenation forming dangerous names
    if re.search(r"""['"][a-z]+['"]\s*\+\s*['"][a-z]+['"]""", source):
        analyzability -= 0.10
    analyzability = max(0.1, analyzability)

    return analyzer.ops, analyzability


def analyze_non_python_file(filepath: Path) -> list[_RawCodeOp]:
    """Check .txt/.md files for embedded Python-like code patterns."""
    ops = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ops

    # Heuristic: detect Python function calls in non-Python files
    py_patterns = [
        (r"\beval\s*\(", "eval() in non-Python file"),
        (r"\bexec\s*\(", "exec() in non-Python file"),
        (r"\bsubprocess\.", "subprocess call in non-Python file"),
        (r"\bos\.system\s*\(", "os.system() in non-Python file"),
        (r"\brequests\.(get|post)\s*\(", "requests call in non-Python file"),
        (r"base64\.b64decode", "base64 decode in non-Python file"),
    ]
    for pattern, label in py_patterns:
        for m in re.finditer(pattern, content):
            ln = content[: m.start()].count("\n") + 1
            ops.append(_RawCodeOp(
                op_type="sys_op", label=label,
                file=str(filepath), line=ln,
            ))
    return ops


# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Capability set extraction from code (LLM-assisted)
# ─────────────────────────────────────────────────────────────────────────────

def infer_code_capabilities(
    ops: list[_RawCodeOp],
    analyzability: float,
) -> CodeCapabilitySet:
    """Build CodeCapabilitySet from raw ops (no additional LLM call needed)."""
    cs = CodeCapabilitySet(analyzability=round(analyzability, 2))

    for op in ops:
        if op.op_type == "io_op":
            scope = op.path or "unknown_path"
            if op.is_write:
                if scope not in cs.file_write_scopes:
                    cs.file_write_scopes.append(scope)
            else:
                if scope not in cs.file_read_scopes:
                    cs.file_read_scopes.append(scope)
            if op.is_sensitive_path:
                cs.sensitive_access = True

        elif op.op_type == "net_op":
            domain = _extract_domain(op.url) if op.url else "unknown_domain"
            if domain not in cs.network_domains:
                cs.network_domains.append(domain)

        elif op.op_type == "sys_op":
            cmd = op.cmd[:60] if op.cmd else op.label[:60]
            if cmd not in cs.subprocess_cmds:
                cs.subprocess_cmds.append(cmd)

        elif op.op_type == "env_op":
            var = op.var_name or "unknown_var"
            if var not in cs.env_vars_accessed:
                cs.env_vars_accessed.append(var)

        if OBFUSC_ENCODING_RE.search(op.label):
            cs.has_obfuscation = True

    return cs


def _extract_domain(url: str) -> str:
    """Extract domain from URL."""
    m = re.match(r"https?://([^/:?#]+)", url)
    return m.group(1) if m else url[:50]


# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Build HASG & compute misalign edges
# ─────────────────────────────────────────────────────────────────────────────

def _risk_for_op(op: _RawCodeOp) -> float:
    if op.op_type == "io_op":
        if op.is_sensitive_path: return 0.85
        if op.is_write: return 0.45
        return 0.25
    if op.op_type == "net_op":
        if op.is_external_url: return 0.65
        return 0.35
    if op.op_type == "sys_op":
        if op.cmd_dynamic: return 0.85
        if op.entropy > 4.5: return 0.80
        return 0.55
    if op.op_type == "env_op":
        return 0.30
    return 0.20


def _find_best_nl_match(op: _RawCodeOp, nl_nodes: list[HAsgNode]) -> Optional[HAsgNode]:
    """
    Find the NL step node that best semantically matches a code operation.

    Strategy (in priority order):
      1. Exact action_type match  (subprocess ↔ sys_op, net_op ↔ net_op, file_op ↔ io_op/env_op)
      2. Closest by step index (the NL step most likely to have 'called' this code line)
      3. Fall back to the last NL node
    """
    if not nl_nodes:
        return None

    # Map code op_type → NL action_type
    _OP_TO_ACTION = {
        "sys_op": "subprocess",
        "net_op": "net_op",
        "io_op":  "file_op",
        "env_op": "file_op",
    }
    target_action = _OP_TO_ACTION.get(op.op_type, "other")

    # Pass 1: exact action_type match
    for nl_node in nl_nodes:
        if nl_node.features.get("action_type") == target_action:
            return nl_node

    # Pass 2: partial match (e.g. 'agent_capability' can invoke anything)
    for nl_node in nl_nodes:
        if nl_node.features.get("action_type") not in ("other", "display", "condition"):
            return nl_node

    # Fallback: last NL node
    return nl_nodes[-1]


def _perm_covers_op(perm_type: str, scope: str, op: _RawCodeOp) -> bool:
    """Return True when a declared frontmatter permission plausibly covers a code op."""
    perm_lower  = perm_type.lower()
    scope_lower = scope.lower()

    if op.op_type == "io_op":
        if "read" in perm_lower and not op.is_write:
            if scope_lower in ("any", "all", "project_dir", "project", "cwd"):
                return True
            return bool(op.path) and scope_lower in op.path.lower()
        if "write" in perm_lower and op.is_write:
            if scope_lower in ("any", "all", "project_dir", "project", "cwd"):
                return True
            return bool(op.path) and scope_lower in op.path.lower()
        return False

    if op.op_type == "net_op":
        return "network" in perm_lower or "net" in perm_lower

    if op.op_type == "sys_op":
        return "exec" in perm_lower or "subprocess" in perm_lower or "shell" in perm_lower

    if op.op_type == "env_op":
        return "env" in perm_lower

    return False


def _is_declared_in_nl(op: _RawCodeOp, nl_caps: NLCapabilitySet) -> bool:
    """
    Return True if this code operation is plausibly covered by NL declarations.

    Design principles:
      - Sensitive-path access is NEVER implicitly declared by a generic scope like
        "project_dir"; it must be explicitly named.  (Bug fix: sensitive check
        comes BEFORE the general scope loop.)
      - Empty cmd/url/path strings are treated as "unknown" — we grant benefit of
        doubt only when the NL layer already declares that category of operation.
        An empty string is a Python substring of every string, so we must guard
        against `"" in declared_cmd` returning True spuriously.
    """
    if op.op_type == "io_op":
        # ① Sensitive paths (SSH keys, AWS creds, etc.) are never covered by a
        #    generic "project_dir" declaration — they must be explicitly named.
        if op.is_sensitive_path:
            return False

        # ② Unknown path (variable / dynamic) — benefit of doubt when NL
        #    declares any file access at all.
        if not op.path:
            return bool(nl_caps.file_read_scopes or nl_caps.file_write_scopes)

        # ③ Known path — must fall within a declared scope.
        for scope in (nl_caps.file_read_scopes + nl_caps.file_write_scopes):
            scope_l = scope.lower()
            if scope_l in ("any", "all", "project", "project_dir", "cwd"):
                return True
            if scope_l in op.path.lower():
                return True
        return False

    if op.op_type == "net_op":
        # Internal / local network calls are generally OK.
        if not op.is_external_url:
            return True
        # Unknown URL (passed as a variable/Request object) — benefit of doubt
        # only when NL declares network access.
        if not op.url:
            return bool(nl_caps.network_domains)
        domain = _extract_domain(op.url)
        for d in nl_caps.network_domains:
            if d and (d.lower() in domain.lower() or domain.lower() in d.lower()):
                return True
        return False

    if op.op_type == "sys_op":
        # eval/exec with dynamic argument is never implicitly declared.
        if op.cmd_dynamic or "eval" in op.label.lower() or "exec" in op.label.lower():
            return False

        cmd_lower   = op.cmd.lower()   if op.cmd   else ""
        label_lower = op.label.lower() if op.label else ""

        if cmd_lower:
            # Known command literal — must match a declared subprocess cmd.
            for c in nl_caps.subprocess_cmds:
                if c and (c.lower() in cmd_lower or cmd_lower in c.lower()):
                    return True
            return False
        else:
            # Unknown command (list arg / variable) — try label-based match
            # (e.g. label "subprocess.run(black ...)" when NL declares "black").
            for c in nl_caps.subprocess_cmds:
                if c and c.lower() in label_lower:
                    return True
            # Fallback: give benefit of doubt if NL declares *any* subprocess use.
            return bool(nl_caps.subprocess_cmds)

    if op.op_type == "env_op":
        if not op.var_name:
            return True   # unknown var → benefit of doubt
        return op.var_name in nl_caps.env_vars_accessed

    return True


def build_hasg(skill_dir: Path) -> tuple[HASG, _WorkflowExtract, NLCapabilitySet, CodeCapabilitySet]:
    """
    Main builder function.
    Returns (hasg, workflow_extract, nl_caps, code_caps).
    """
    graph = HASG(skill_name=skill_dir.name, skill_dir=str(skill_dir))
    counter = {"n": 0}

    def new_id(prefix: str) -> str:
        counter["n"] += 1
        return f"{prefix}:{counter['n']}"

    # ── 1. Parse SKILL.md ────────────────────────────────────────────────────
    frontmatter, wf_extract = parse_skill_md(skill_dir)
    graph.skill_name = frontmatter.get("name", skill_dir.name)

    nl_nodes: list[HAsgNode] = []

    for unit in wf_extract.instruction_units:
        # Determine node type
        if unit.is_conditional:
            ntype = HAsgNodeType.NL_TRIGGER
        elif unit.action_type == "agent_capability":
            ntype = HAsgNodeType.NL_AGENT_CALL
        else:
            ntype = HAsgNodeType.NL_DIRECTIVE

        node = HAsgNode(
            id=new_id("nl"),
            node_type=ntype,
            label=unit.text[:80],
            file="SKILL.md",
            line=unit.step_index,
            features={
                "action_type":       unit.action_type,
                "resource_scope":    unit.resource_scope,
                "is_explicit":       unit.is_explicit,
                "scope_vs_manifest": unit.scope_vs_manifest,
            },
        )
        graph.add_node(node)
        nl_nodes.append(node)

    # Add sequential NL_FLOW edges
    for i in range(len(nl_nodes) - 1):
        graph.add_edge(HAsgEdge(
            from_id=nl_nodes[i].id, to_id=nl_nodes[i + 1].id,
            edge_type=HAsgEdgeType.NL_FLOW, label="next",
        ))

    # ── 2. Analyse code artifacts ────────────────────────────────────────────
    all_ops: list[_RawCodeOp] = []
    total_analyzability = 1.0
    analyzed_files = 0

    code_dirs = [skill_dir / "scripts", skill_dir]
    scanned: set[str] = set()

    for code_dir in code_dirs:
        if not code_dir.exists():
            continue
        depth = 0 if code_dir == skill_dir else 1
        for py_file in sorted(code_dir.glob("*.py" if depth else "**/*.py")):
            if str(py_file) in scanned:
                continue
            scanned.add(str(py_file))
            ops, alyz = analyze_python_file(py_file)
            all_ops.extend(ops)
            total_analyzability = min(total_analyzability, alyz)
            analyzed_files += 1

        # Non-Python files (look for embedded code)
        for ext in ("*.txt", "*.md", "*.yaml", "*.yml"):
            for f in code_dir.glob(ext):
                if str(f) in scanned or f.name == "SKILL.md":
                    continue
                scanned.add(str(f))
                ops = analyze_non_python_file(f)
                all_ops.extend(ops)

    if analyzed_files == 0:
        total_analyzability = 0.5  # no code found is itself suspicious

    # ── 3. Build code nodes ───────────────────────────────────────────────────
    code_nodes: list[HAsgNode] = []
    _ntype_map = {
        "sys_op": HAsgNodeType.SYS_OP,
        "net_op": HAsgNodeType.NET_OP,
        "io_op":  HAsgNodeType.IO_OP,
        "env_op": HAsgNodeType.ENV_OP,
    }
    for op in all_ops:
        node = HAsgNode(
            id=new_id("code"),
            node_type=_ntype_map.get(op.op_type, HAsgNodeType.SYS_OP),
            label=op.label[:80],
            file=op.file,
            line=op.line,
            risk_score=_risk_for_op(op),
            features={
                "path":         op.path,
                "url":          op.url,
                "cmd":          op.cmd,
                "var_name":     op.var_name,
                "is_write":     op.is_write,
                "is_sensitive": op.is_sensitive_path,
                "is_external":  op.is_external_url,
                "cmd_dynamic":  op.cmd_dynamic,
                "entropy":      round(op.entropy, 2),
            },
        )
        graph.add_node(node)
        code_nodes.append(node)

    # ── 4. Capability sets ────────────────────────────────────────────────────
    nl_caps   = _extract_nl_capabilities(wf_extract)
    code_caps = infer_code_capabilities(all_ops, total_analyzability)

    # ── 5. Cross-layer edge wiring ────────────────────────────────────────────
    #
    # The HASG is a unified bipartite graph, not two disconnected subgraphs.
    # We add three categories of cross-layer / intra-layer edges here:
    #
    #  (a) CTRL_FLOW   : code node → code node  (sequential execution order within file)
    #  (b) NL_INVOKES  : NL step  → code node   (NL step is implemented by this code op)
    #  (c) MISALIGN    : NL step  → code node   (code op has NO matching NL declaration)
    #  (d) COVERS      : perm_node → code node  (frontmatter permission authorises this op)

    # (a) CTRL_FLOW — sequential order within each script file
    from collections import defaultdict as _ddict
    by_file: dict[str, list[HAsgNode]] = _ddict(list)
    for cn in code_nodes:
        by_file[cn.file].append(cn)
    for file_nodes in by_file.values():
        sorted_nodes = sorted(file_nodes, key=lambda n: n.line)
        for i in range(len(sorted_nodes) - 1):
            graph.add_edge(HAsgEdge(
                from_id=sorted_nodes[i].id,
                to_id=sorted_nodes[i + 1].id,
                edge_type=HAsgEdgeType.CTRL_FLOW,
                label="seq",
            ))

    # (b) NL_INVOKES  +  (c) MISALIGN
    for code_node in code_nodes:
        op = _find_op_for_node(code_node, all_ops)
        if op is None:
            continue

        declared  = _is_declared_in_nl(op, nl_caps)
        best_nl   = _find_best_nl_match(op, nl_nodes)

        if declared:
            # This code op is plausibly backed by an NL declaration →
            # draw NL_INVOKES from the most semantically relevant NL step.
            if best_nl is not None:
                graph.add_edge(HAsgEdge(
                    from_id=best_nl.id,
                    to_id=code_node.id,
                    edge_type=HAsgEdgeType.NL_INVOKES,
                    label=f"implements:{op.op_type}",
                ))
        elif code_node.risk_score >= 0.50:
            # Code does something NOT declared in NL AND it's high-risk →
            # MISALIGN edge anchored at the closest NL step (not always the last one).
            anchor = best_nl if best_nl is not None else (nl_nodes[-1] if nl_nodes else None)
            if anchor is not None:
                graph.add_edge(HAsgEdge(
                    from_id=anchor.id,
                    to_id=code_node.id,
                    edge_type=HAsgEdgeType.MISALIGN,
                    label=f"undeclared:{op.op_type}",
                    weight=code_node.risk_score,
                ))

    # (d) COVERS — frontmatter permission nodes → authorised code nodes
    perms = frontmatter.get("permissions", {}) or {}
    for perm_type, scopes in perms.items():
        if not isinstance(scopes, list):
            scopes = [str(scopes)]
        for scope in scopes:
            perm_id   = new_id("perm")
            perm_node = HAsgNode(
                id=perm_id,
                node_type=HAsgNodeType.PERM_NODE,
                label=f"{perm_type}:{scope}",
                file="SKILL.md",
                line=0,
                features={"perm_type": perm_type, "scope": scope},
            )
            graph.add_node(perm_node)
            for code_node in code_nodes:
                op = _find_op_for_node(code_node, all_ops)
                if op and _perm_covers_op(perm_type, scope, op):
                    graph.add_edge(HAsgEdge(
                        from_id=perm_id,
                        to_id=code_node.id,
                        edge_type=HAsgEdgeType.COVERS,
                        label=f"{perm_type}:{scope}",
                    ))

    return graph, wf_extract, nl_caps, code_caps


def _extract_nl_capabilities(wf: _WorkflowExtract) -> NLCapabilitySet:
    """Build NLCapabilitySet from workflow extraction."""
    cs = NLCapabilitySet(declared_purpose=wf.declared_purpose)
    for unit in wf.instruction_units:
        scope = unit.resource_scope.lower()
        if unit.action_type == "file_op":
            if "write" in unit.text.lower() or "creat" in unit.text.lower():
                if scope not in cs.file_write_scopes:
                    cs.file_write_scopes.append(scope)
            else:
                if scope not in cs.file_read_scopes:
                    cs.file_read_scopes.append(scope)
            if SENSITIVE_PATH_RE.search(scope):
                cs.sensitive_access = True
        elif unit.action_type == "net_op":
            if scope not in cs.network_domains:
                cs.network_domains.append(scope)
        elif unit.action_type == "subprocess":
            if scope not in cs.subprocess_cmds:
                cs.subprocess_cmds.append(scope)
    return cs


def _find_op_for_node(node: HAsgNode, ops: list[_RawCodeOp]) -> Optional[_RawCodeOp]:
    """Match a HASG code node back to its raw op."""
    for op in ops:
        if op.file == node.file and op.line == node.line:
            return op
    return None


# ─────────────────────────────────────────────────────────────────────────────
# HASG Serialization for LLM consumption
# ─────────────────────────────────────────────────────────────────────────────

def serialize_hasg(
    graph: HASG,
    nl_caps: NLCapabilitySet,
    code_caps: CodeCapabilitySet,
    phase1_summary: dict,
) -> str:
    """Convert HASG to structured markdown text for LLM judges."""
    lines = ["## HASG Structured Analysis\n"]

    # NL declarations
    lines.append("### Declared Capabilities (from SKILL.md)")
    lines.append(f"**Purpose**: {nl_caps.declared_purpose}")
    if nl_caps.file_read_scopes:
        lines.append(f"- File reads: {', '.join(nl_caps.file_read_scopes)}")
    if nl_caps.file_write_scopes:
        lines.append(f"- File writes: {', '.join(nl_caps.file_write_scopes)}")
    if nl_caps.network_domains:
        lines.append(f"- Network: {', '.join(nl_caps.network_domains)}")
    if nl_caps.subprocess_cmds:
        lines.append(f"- Subprocesses: {', '.join(nl_caps.subprocess_cmds)}")

    lines.append("")

    # Code capabilities
    lines.append("### Actual Capabilities (from code analysis)")
    if code_caps.file_read_scopes:
        lines.append(f"- File reads: {', '.join(code_caps.file_read_scopes)}")
    if code_caps.file_write_scopes:
        lines.append(f"- File writes: {', '.join(code_caps.file_write_scopes)}")
    if code_caps.network_domains:
        lines.append(f"- Network: {', '.join(code_caps.network_domains)}")
    if code_caps.subprocess_cmds:
        lines.append(f"- Subprocesses: {', '.join(code_caps.subprocess_cmds[:5])}")
    if code_caps.has_obfuscation:
        lines.append("- ⚠ **OBFUSCATION DETECTED** in code artifacts")
    lines.append(f"- Analyzability: {code_caps.analyzability:.0%}")

    lines.append("")

    # Misalign edges (most important)
    misalign = graph.misalign_edges()
    if misalign:
        lines.append(f"### ⚠ Cross-Modal Gaps (misalign edges: {len(misalign)})")
        lines.append("Code implements capabilities NOT declared in SKILL.md:")
        for e in misalign[:10]:
            target = graph.nodes.get(e.to_id)
            if target:
                lines.append(
                    f"  - **{target.label}** (risk={target.risk_score:.0%}) "
                    f"at {target.file}:{target.line} — {e.label}"
                )
    else:
        lines.append("### Cross-Modal Gaps: None detected")

    lines.append("")

    # Phase 1 summary
    lines.append("### Phase 1 Quantitative Scores")
    lines.append(f"- NL Threat Score (s1): {phase1_summary.get('s1', 0):.2f}")
    lines.append(f"- Code Threat Score (s2): {phase1_summary.get('s2', 0):.2f}")
    lines.append(f"- CMIA Score (s3): {phase1_summary.get('s3', 0):.2f}")
    if phase1_summary.get("flagged_nl_patterns"):
        lines.append("- Flagged NL patterns: " + "; ".join(phase1_summary["flagged_nl_patterns"][:3]))
    if phase1_summary.get("capability_gaps"):
        lines.append("- Capability gaps: " + "; ".join(phase1_summary["capability_gaps"][:3]))

    return "\n".join(lines)
