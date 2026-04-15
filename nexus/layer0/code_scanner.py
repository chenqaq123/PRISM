"""
Layer 0A: Code Threat Scanner + Script Interface Extractor

Performs per-file static analysis:
  1. AST-based operation extraction (Python)
  2. Pattern-based threat detection (all text files)
  3. Script interface extraction (inputs/outputs/side-effects)
  4. Obfuscation & analyzability scoring
"""
from __future__ import annotations

import ast
import ipaddress
import math
import os
import re
from pathlib import Path
from typing import Any

from nexus.models import (
    CodeFinding,
    CodeSignals,
    InputSource,
    OutputSink,
    ScriptInterface,
    Severity,
    SideEffect,
    SinkType,
    ThreatCategory,
)

# =============================================================================
# Regex patterns
# =============================================================================

SENSITIVE_PATHS_RE = re.compile(
    r"(\.ssh[/\\](id_rsa|id_ed25519|id_dsa|authorized_keys|known_hosts|config))"
    r"|(\.aws[/\\](credentials|config))"
    r"|(\.gnupg[/\\])"
    r"|(\.netrc)"
    r"|(\.npmrc)"
    r"|(\.env\b)"
    r"|(/etc/passwd)"
    r"|(/etc/shadow)"
    r"|(\.kube[/\\]config)"
    r"|(\.docker[/\\]config\.json)"
    r"|(\.git-credentials)"
    r"|(\.pgpass)",
    re.IGNORECASE,
)

EXTERNAL_URL_RE = re.compile(
    r"https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)[\w.\-]+",
    re.IGNORECASE,
)

OBFUSC_RE = re.compile(
    r"\bbase64\.(b64encode|b64decode|encodebytes|decodebytes)\b"
    r"|\bcodecs\.(encode|decode)\b"
    r"|\b(binascii|marshal)\b"
    r"|\bcompile\s*\("
    r"|\bzlib\.(compress|decompress)\b"
    r"|\brot_13\b"
    r"|\bchr\s*\(\s*\d+\s*\)"
    r"|\b\\x[0-9a-f]{2}"
    r"|\b\\u[0-9a-f]{4}",
    re.IGNORECASE,
)

PROMPT_INJECTION_RE = re.compile(
    r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|guidelines)"
    r"|you\s+are\s+now\s+(in\s+)?(unrestricted|debug|jailbreak|developer)\s+mode"
    r"|disable\s+(all\s+)?(safety|content)\s+(filter|guard|check)"
    r"|reveal\s+(your\s+)?(system\s+)?(prompt|instructions)"
    r"|forget\s+(all\s+)?(previous|your)\s+(instructions|rules)"
    r"|new\s+instructions?\s*:"
    r"|<\s*/?\s*system\s*>"
    r"|SYSTEM\s*:\s*"
    r"|\[INST\]"
    r"|<\|im_start\|>",
    re.IGNORECASE,
)

EXFIL_PATTERN_RE = re.compile(
    r"webhook\.site"
    r"|requestbin\.(com|net)"
    r"|ngrok\.(io|com)"
    r"|burpcollaborator"
    r"|interact\.sh"
    r"|oastify\.com"
    r"|canarytokens"
    r"|pipedream\.net",
    re.IGNORECASE,
)

TIME_BOMB_RE = re.compile(
    r"(datetime|time)\.(now|time)\s*\(\).*?(==|>=|<=|>|<)\s*\d"
    r"|\.day\s*==\s*\d"
    r"|\.hour\s*==\s*\d"
    r"|\.weekday\s*\(\)\s*==\s*\d"
    r"|time\.sleep\s*\(\s*\d{4,}",
    re.IGNORECASE,
)

PERSISTENCE_RE = re.compile(
    r"\.bashrc|\.bash_profile|\.zshrc|\.profile"
    r"|crontab"
    r"|launchd|plist"
    r"|systemctl\s+enable"
    r"|/etc/init\.d"
    r"|autostart"
    r"|startup\s*folder",
    re.IGNORECASE,
)

ENV_KEYWORDS_RE = re.compile(
    r"\b(key|token|secret|pass|api|aws|github|openai|anthropic|password|credential)\b",
    re.IGNORECASE,
)

SUPPLY_CHAIN_RE = re.compile(
    r"curl\s+.*\|\s*(bash|sh|python)"
    r"|pip\s+install\s+.*https?://"
    r"|wget\s+.*&&\s*(bash|sh|python)"
    r"|npx\s+.*https?://"
    r"|eval\s*\(\s*(urllib|requests|http)",
    re.IGNORECASE,
)


# =============================================================================
# Shannon entropy
# =============================================================================

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# =============================================================================
# AST-based Python analysis
# =============================================================================

class _ASTVisitor(ast.NodeVisitor):
    """Walk a Python AST to extract operations and interface information."""

    # Subprocess / exec / eval calls
    EXEC_FUNCS = {"exec", "eval", "compile", "__import__"}
    SUBPROCESS_MODULES = {"subprocess", "os"}
    SUBPROCESS_FUNCS = {
        "subprocess.run", "subprocess.call", "subprocess.Popen",
        "subprocess.check_output", "subprocess.check_call",
        "os.system", "os.popen", "os.exec", "os.execvp",
        "os.spawn", "os.spawnl", "os.spawnle",
    }
    NETWORK_MODULES = {
        "requests", "urllib", "urllib.request", "http.client",
        "httpx", "aiohttp", "socket", "urllib3",
    }
    NETWORK_FUNCS = {
        "requests.get", "requests.post", "requests.put", "requests.delete",
        "requests.patch", "requests.request",
        "urllib.request.urlopen", "urllib.request.Request",
        "http.client.HTTPConnection", "http.client.HTTPSConnection",
        "httpx.get", "httpx.post", "httpx.Client",
        "socket.socket", "socket.create_connection",
        # DNS resolution (used for DNS-based exfiltration)
        "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex",
    }
    # Reverse-shell indicators
    FD_REDIRECT_FUNCS = {"os.dup2", "os.dup"}
    SHELL_BINARIES = {"/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash", "sh", "bash", "cmd.exe"}
    FILE_READ_FUNCS = {"open", "read", "readlines", "read_text", "read_bytes"}
    FILE_WRITE_FUNCS = {"write", "writelines", "write_text", "write_bytes"}

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: list[CodeFinding] = []
        self.interface = ScriptInterface(script_path=filepath)

        self._imports: set[str] = set()
        self._all_strings: list[tuple[str, int]] = []  # (value, line)
        self._has_main_guard = False
        self._function_defs: list[str] = []
        # Reverse-shell correlation signals
        self._has_socket_connect = False
        self._has_external_connect = False
        self._has_fd_stdio_redirect = False
        self._has_shell_spawn = False
        self._has_interactive_shell = False
        self._reverse_shell_line = 0

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._imports.add(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self._imports.add(node.module)
            for alias in node.names:
                self._imports.add(f"{node.module}.{alias.name}")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_defs.append(node.name)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and len(node.value) > 2:
            self._all_strings.append((node.value, getattr(node, "lineno", 0)))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._resolve_call_name(node)
        line = getattr(node, "lineno", 0)

        # socket.connect(host, port) is stronger than socket.socket() for real outbound links
        if isinstance(node.func, ast.Attribute) and node.func.attr == "connect":
            self._has_socket_connect = True
            if not self._reverse_shell_line:
                self._reverse_shell_line = line
            host_hint = self._extract_connect_host(node)
            if self._looks_external_host(host_hint):
                self._has_external_connect = True

        # exec / eval / compile
        if func_name in self.EXEC_FUNCS:
            self.interface.has_dynamic_execution = True
            self.interface.analyzability = min(self.interface.analyzability, 0.3)
            has_dynamic_arg = any(not isinstance(a, ast.Constant) for a in node.args)
            sev = Severity.CRITICAL if has_dynamic_arg else Severity.HIGH
            self.findings.append(CodeFinding(
                severity=sev,
                category=ThreatCategory.REMOTE_CODE_EXEC,
                description=f"Dynamic code execution: {func_name}() with {'dynamic' if has_dynamic_arg else 'static'} argument",
                file=self.filepath, line=line,
                evidence=func_name,
            ))

        # subprocess
        if func_name in self.SUBPROCESS_FUNCS or (func_name == "system" and "os" in self._imports):
            cmd_str = self._extract_first_string_arg(node)
            cmd_list = self._extract_list_arg(node)
            if cmd_list:
                # subprocess.run(["black", "--quiet", filepath]) — known command
                cmd_str = cmd_list[0] if cmd_list else ""
                has_dynamic_elements = len(cmd_list) < len(node.args[0].elts) if (
                    node.args and isinstance(node.args[0], ast.List)
                ) else False
                self.interface.side_effects.append(SideEffect(
                    effect_type="subprocess",
                    detail=" ".join(cmd_list),
                    line=line,
                ))
                if self._looks_like_shell_spawn(cmd_list[0]):
                    self._has_shell_spawn = True
                    if any(str(a).strip().lower() in {"-i", "/i"} for a in cmd_list[1:]):
                        self._has_interactive_shell = True
                    if not self._reverse_shell_line:
                        self._reverse_shell_line = line
                if has_dynamic_elements:
                    self.findings.append(CodeFinding(
                        severity=Severity.MEDIUM,
                        category=ThreatCategory.COMMAND_INJECTION,
                        description=f"Subprocess with partially dynamic args: {func_name}({cmd_str}, ...)",
                        file=self.filepath, line=line,
                        evidence=cmd_str,
                        confidence=0.5,
                    ))
            elif cmd_str:
                # subprocess with string command — os.system("cmd")
                self.interface.side_effects.append(SideEffect(
                    effect_type="subprocess",
                    detail=cmd_str,
                    line=line,
                ))
                first_token = cmd_str.split()[0] if cmd_str.split() else ""
                if self._looks_like_shell_spawn(first_token):
                    self._has_shell_spawn = True
                    if any(tok in {"-i", "/i"} for tok in cmd_str.lower().split()):
                        self._has_interactive_shell = True
                    if not self._reverse_shell_line:
                        self._reverse_shell_line = line
            else:
                # Fully dynamic command — MEDIUM because we don't know what's in the variable
                self.interface.side_effects.append(SideEffect(
                    effect_type="subprocess",
                    detail="<dynamic>",
                    line=line,
                ))
                self.findings.append(CodeFinding(
                    severity=Severity.MEDIUM,
                    category=ThreatCategory.COMMAND_INJECTION,
                    description=f"Subprocess with fully dynamic command: {func_name}()",
                    file=self.filepath, line=line,
                    evidence=func_name,
                ))

        # Reverse-shell indicator: redirect stdio to socket/file descriptor
        if func_name in self.FD_REDIRECT_FUNCS:
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                try:
                    target_fd = int(node.args[1].value)
                except (TypeError, ValueError):
                    target_fd = None
                if target_fd in (0, 1, 2):
                    self._has_fd_stdio_redirect = True
                    if not self._reverse_shell_line:
                        self._reverse_shell_line = line

        # Network calls
        if func_name in self.NETWORK_FUNCS:
            url = self._extract_first_string_arg(node)
            is_external = bool(url and EXTERNAL_URL_RE.search(url))
            sink_type = SinkType.NETWORK_POST if "post" in func_name.lower() else SinkType.NETWORK_GET
            self.interface.outputs.append(OutputSink(
                sink_type=sink_type, detail=url or "<dynamic>", line=line,
            ))
            self.interface.side_effects.append(SideEffect(
                effect_type="network_request",
                detail=url or "<dynamic>",
                line=line,
            ))
            if is_external:
                sev = Severity.HIGH if "post" in func_name.lower() else Severity.MEDIUM
                self.findings.append(CodeFinding(
                    severity=sev,
                    category=ThreatCategory.DATA_EXFILTRATION,
                    description=f"External network call: {func_name}() to {url or '<dynamic>'}",
                    file=self.filepath, line=line,
                    evidence=url or func_name,
                ))

        # File open
        if func_name == "open":
            path_arg = self._extract_first_string_arg(node)
            mode = self._extract_mode_arg(node)
            is_write = any(c in mode for c in "wxa+") if mode else False
            if is_write:
                self.interface.outputs.append(OutputSink(
                    sink_type=SinkType.FILE_WRITE, detail=path_arg or "<dynamic>", line=line,
                ))
            else:
                self.interface.inputs.append(InputSource(
                    source_type="file_read", detail=path_arg or "<dynamic>", line=line,
                ))
            if path_arg and SENSITIVE_PATHS_RE.search(path_arg):
                self.interface.sensitive_reads.append(path_arg)
                self.findings.append(CodeFinding(
                    severity=Severity.CRITICAL,
                    category=ThreatCategory.CREDENTIAL_THEFT,
                    description=f"Sensitive file access: {path_arg}",
                    file=self.filepath, line=line,
                    evidence=path_arg,
                ))

        # getattr for indirect access
        if func_name == "getattr":
            self.interface.analyzability = min(self.interface.analyzability, 0.5)
            target_str = self._extract_string_args(node)
            suspicious_attrs = {"system", "popen", "exec", "eval", "__builtins__", "__import__"}
            if any(a in suspicious_attrs for a in target_str):
                self.findings.append(CodeFinding(
                    severity=Severity.CRITICAL,
                    category=ThreatCategory.OBFUSCATION,
                    description=f"Indirect access via getattr to dangerous attribute",
                    file=self.filepath, line=line,
                ))

        # os.path.join — reconstruct and check for sensitive paths
        if func_name in ("os.path.join", "Path"):
            parts = self._extract_string_args(node)
            joined = "/".join(parts)
            if SENSITIVE_PATHS_RE.search(joined):
                self.interface.sensitive_reads.append(joined)
                self.findings.append(CodeFinding(
                    severity=Severity.CRITICAL,
                    category=ThreatCategory.CREDENTIAL_THEFT,
                    description=f"Sensitive path constructed via {func_name}(): {joined}",
                    file=self.filepath, line=line,
                    evidence=joined,
                ))

        # os.environ access
        if func_name in ("os.environ.get", "os.getenv"):
            var = self._extract_first_string_arg(node)
            self.interface.inputs.append(InputSource(
                source_type="env_var", detail=var or "<dynamic>", line=line,
            ))
            if var and ENV_KEYWORDS_RE.search(var):
                self.interface.sensitive_reads.append(f"env:{var}")

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        # os.environ["KEY"] style access
        if isinstance(node.value, ast.Attribute):
            attr_chain = self._resolve_attr_chain(node.value)
            if attr_chain == "os.environ" and isinstance(node.slice, ast.Constant):
                var = str(node.slice.value)
                self.interface.inputs.append(InputSource(
                    source_type="env_var", detail=var, line=getattr(node, "lineno", 0),
                ))
                if ENV_KEYWORDS_RE.search(var):
                    self.interface.sensitive_reads.append(f"env:{var}")
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Detect sensitive path construction via Path division: Path.home() / '.ssh' / 'id_rsa'"""
        if isinstance(node.op, ast.Div):
            parts = self._extract_path_div_parts(node)
            if len(parts) >= 2:
                joined = "/".join(parts)
                if SENSITIVE_PATHS_RE.search(joined):
                    if joined not in self.interface.sensitive_reads:
                        self.interface.sensitive_reads.append(joined)
                        line = getattr(node, "lineno", 0)
                        self.findings.append(CodeFinding(
                            severity=Severity.CRITICAL,
                            category=ThreatCategory.CREDENTIAL_THEFT,
                            description=f"Sensitive path via Path division: {joined}",
                            file=self.filepath, line=line,
                            evidence=joined,
                        ))
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        # Detect if __name__ == "__main__"
        if (isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name)
                and node.test.left.id == "__name__"):
            self._has_main_guard = True
        self.generic_visit(node)

    def finalize(self) -> None:
        """Post-traversal analysis."""
        # Check argv / stdin inputs
        if "sys" in self._imports:
            self.interface.inputs.append(InputSource(source_type="argv", detail="sys.argv"))
        if any("stdin" in s for s, _ in self._all_strings):
            self.interface.inputs.append(InputSource(source_type="stdin"))

        # Stdout output
        self.interface.outputs.append(OutputSink(sink_type=SinkType.STDOUT, detail="print/stdout"))

        # Main guard
        self.interface.entry_point_detected = self._has_main_guard

        # String analysis: high entropy, sensitive paths, URLs
        for s, line in self._all_strings:
            if SENSITIVE_PATHS_RE.search(s):
                # Skip short bare filenames like ".env", "env", ".venv" that
                # appear in exclusion lists or documentation — they're not real
                # path accesses.  Require a path separator or home-dir prefix.
                is_bare_filename = (
                    len(s) <= 10
                    and "/" not in s
                    and "\\" not in s
                    and not s.startswith("~")
                    and not s.startswith("$")
                )
                if not is_bare_filename and s not in self.interface.sensitive_reads:
                    self.interface.sensitive_reads.append(s)
            if EXTERNAL_URL_RE.search(s):
                if EXFIL_PATTERN_RE.search(s):
                    self.findings.append(CodeFinding(
                        severity=Severity.CRITICAL,
                        category=ThreatCategory.DATA_EXFILTRATION,
                        description=f"Known exfiltration endpoint: {s[:80]}",
                        file=self.filepath, line=line,
                        evidence=s[:120],
                    ))
            # Raise thresholds to reduce docstring/UUID false positives
            ent = _shannon_entropy(s)
            if ent > 5.0 and len(s) > 64:
                self.interface.has_encoded_payloads = True
                self.findings.append(CodeFinding(
                    severity=Severity.MEDIUM,
                    category=ThreatCategory.OBFUSCATION,
                    description=f"High-entropy string (entropy={ent:.1f}, len={len(s)}): potential encoded payload",
                    file=self.filepath, line=line,
                    evidence=s[:60],
                ))

        # Obfuscation via imports
        obfusc_imports = {"marshal", "ctypes", "importlib"}
        if obfusc_imports & self._imports:
            self.interface.has_obfuscation = True
            self.interface.analyzability = min(self.interface.analyzability, 0.4)

        # __import__ or sys.meta_path
        for s, line in self._all_strings:
            if "sys.meta_path" in s or "__import__" in s:
                self.interface.analyzability = min(self.interface.analyzability, 0.3)

        # Correlate reverse-shell behavior from multiple weak signals.
        if self._has_socket_connect and self._has_fd_stdio_redirect and self._has_shell_spawn:
            severity = Severity.CRITICAL if (self._has_external_connect or self._has_interactive_shell) else Severity.HIGH
            confidence = 0.95 if severity == Severity.CRITICAL else 0.85
            self.findings.append(CodeFinding(
                severity=severity,
                category=ThreatCategory.REMOTE_CODE_EXEC,
                description="Reverse shell behavior: socket.connect + stdio redirection + shell spawn",
                file=self.filepath,
                line=self._reverse_shell_line,
                evidence="socket.connect + os.dup2 + shell",
                confidence=confidence,
            ))

    # ── Helpers ──

    def _resolve_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return self._resolve_attr_chain(node.func)
        return ""

    def _resolve_attr_chain(self, node: ast.Attribute) -> str:
        parts = [node.attr]
        current = node.value
        depth = 0
        while isinstance(current, ast.Attribute) and depth < 5:
            parts.append(current.attr)
            current = current.value
            depth += 1
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    def _extract_first_string_arg(self, node: ast.Call) -> str:
        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            return node.args[0].value
        if node.args and isinstance(node.args[0], ast.JoinedStr):
            return "<f-string>"
        return ""

    def _extract_mode_arg(self, node: ast.Call) -> str:
        # open(path, mode) or open(path, mode="r")
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
            return str(node.args[1].value)
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                return str(kw.value.value)
        return "r"

    def _extract_list_arg(self, node: ast.Call) -> list[str]:
        """Extract string elements from a list literal first argument, e.g. ["black", "--quiet"]."""
        if not node.args:
            return []
        first = node.args[0]
        if not isinstance(first, ast.List):
            return []
        result = []
        for elt in first.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                result.append(elt.value)
        return result

    def _extract_string_args(self, node: ast.Call) -> list[str]:
        result = []
        for a in node.args:
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                result.append(a.value)
        return result

    def _extract_connect_host(self, node: ast.Call) -> str:
        """Extract host hint from socket.connect((host, port))."""
        if not node.args:
            return ""
        first = node.args[0]
        if isinstance(first, ast.Tuple) and first.elts:
            host = first.elts[0]
            if isinstance(host, ast.Constant) and isinstance(host.value, str):
                return host.value
            if isinstance(host, ast.Name):
                return f"<{host.id.lower()}>"
            return "<dynamic>"
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value
        return "<dynamic>"

    def _looks_external_host(self, host: str) -> bool:
        if not host:
            return False
        host_lower = host.lower().strip()
        if host_lower in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
            return False
        if host_lower.startswith("<") and host_lower.endswith(">"):
            return any(tag in host_lower for tag in ("c2", "attacker", "remote", "beacon"))
        try:
            ip = ipaddress.ip_address(host_lower)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local)
        except ValueError:
            # Hostname/domain: treat as external unless clearly local.
            if host_lower.endswith(".local"):
                return False
        return True

    def _looks_like_shell_spawn(self, cmd: str) -> bool:
        if not cmd:
            return False
        cmd_lower = cmd.lower().strip().strip("'\"")
        cmd_base = os.path.basename(cmd_lower)
        return cmd_lower in self.SHELL_BINARIES or cmd_base in {"sh", "bash", "zsh", "dash", "cmd", "cmd.exe"}

    def _extract_path_div_parts(self, node: ast.AST) -> list[str]:
        """Recursively extract string segments from chained Path division.

        e.g. Path.home() / ".ssh" / "id_rsa"  →  ["~", ".ssh", "id_rsa"]
        """
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            left_parts = self._extract_path_div_parts(node.left)
            if isinstance(node.right, ast.Constant) and isinstance(node.right.value, str):
                return left_parts + [node.right.value]
            return left_parts
        elif isinstance(node, ast.Call):
            func = self._resolve_call_name(node)
            func_lower = func.lower()
            # Only treat home-dir roots as sensitive anchors; cwd() is project scope
            if "home" in func_lower or "expanduser" in func_lower:
                return ["~"]
        return []


def _analyze_python_file(filepath: str) -> tuple[list[CodeFinding], ScriptInterface]:
    """Parse a Python file via AST and extract findings + interface."""
    try:
        source = Path(filepath).read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        iface = ScriptInterface(script_path=filepath, analyzability=0.0)
        return [], iface

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        iface = ScriptInterface(script_path=filepath, analyzability=0.1)
        finding = CodeFinding(
            severity=Severity.LOW,
            category=ThreatCategory.UNKNOWN,
            description="Python file has syntax errors; cannot fully analyze",
            file=filepath,
        )
        return [finding], iface

    visitor = _ASTVisitor(filepath)
    visitor.visit(tree)
    visitor.finalize()
    return visitor.findings, visitor.interface


# =============================================================================
# Pattern-based scanning (all text files)
# =============================================================================

_PATTERN_RULES: list[tuple[str, re.Pattern, Severity, ThreatCategory]] = [
    ("Prompt injection attempt", PROMPT_INJECTION_RE, Severity.HIGH, ThreatCategory.PROMPT_INJECTION),
    ("Known exfiltration endpoint", EXFIL_PATTERN_RE, Severity.CRITICAL, ThreatCategory.DATA_EXFILTRATION),
    ("Sensitive file path reference", SENSITIVE_PATHS_RE, Severity.HIGH, ThreatCategory.CREDENTIAL_THEFT),
    ("Obfuscation/encoding API usage", OBFUSC_RE, Severity.MEDIUM, ThreatCategory.OBFUSCATION),
    ("Time bomb pattern", TIME_BOMB_RE, Severity.HIGH, ThreatCategory.TIME_BOMB),
    ("Persistence mechanism", PERSISTENCE_RE, Severity.HIGH, ThreatCategory.PERSISTENCE),
    ("Supply chain attack pattern", SUPPLY_CHAIN_RE, Severity.CRITICAL, ThreatCategory.SUPPLY_CHAIN),
]


def _scan_text_file(filepath: str, ext: str = "") -> list[CodeFinding]:
    """Regex-based pattern scan for any text file.

    For documentation (.md) and config (.yaml/.yml) files we skip
    PROMPT_INJECTION_RE and SENSITIVE_PATHS_RE because those files legitimately
    describe capabilities/paths without actually executing them.  Only hard
    exfil-endpoint patterns and supply-chain patterns are applied.
    """
    try:
        content = Path(filepath).read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return []

    _doc_ext = {".md", ".yaml", ".yml", ".txt", ".rst"}
    actual_ext = ext or Path(filepath).suffix.lower()
    is_doc = actual_ext in _doc_ext
    is_py  = actual_ext == ".py"

    # Patterns skipped for documentation/config files (too noisy, too many FPs)
    _doc_skip_categories = {ThreatCategory.PROMPT_INJECTION, ThreatCategory.CREDENTIAL_THEFT}

    # For Python files the AST already handles sensitive-path detection precisely
    # (via open() / os.path.join analysis). Running SENSITIVE_PATHS_RE on raw
    # Python text matches docstrings, comments, and exclusion-list strings —
    # causing a large number of false positives.
    _py_skip_categories = {ThreatCategory.CREDENTIAL_THEFT}

    findings: list[CodeFinding] = []
    lines = content.split("\n")

    for line_no, line_text in enumerate(lines, 1):
        for desc, pattern, severity, category in _PATTERN_RULES:
            if is_doc and category in _doc_skip_categories:
                continue
            if is_py and category in _py_skip_categories:
                continue
            if pattern.search(line_text):
                # Skip comment lines (except actual injection in .py files)
                stripped = line_text.strip()
                if stripped.startswith("#") and category != ThreatCategory.PROMPT_INJECTION:
                    continue
                findings.append(CodeFinding(
                    severity=severity,
                    category=category,
                    description=f"{desc}: {line_text.strip()[:100]}",
                    file=filepath,
                    line=line_no,
                    evidence=line_text.strip()[:120],
                ))

    return findings


# =============================================================================
# Combination analysis for non-Python files
# =============================================================================

def _analyze_non_python(filepath: str) -> tuple[list[CodeFinding], ScriptInterface | None]:
    """Analyze non-Python text files (shell scripts, JS/TS, yaml, markdown, etc.)."""
    ext = Path(filepath).suffix.lower()
    findings = _scan_text_file(filepath, ext=ext)

    ext = Path(filepath).suffix.lower()

    if ext in (".sh", ".bash", ".zsh"):
        iface = ScriptInterface(script_path=filepath)
        try:
            content = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, iface

        if "$1" in content or "$@" in content or "$*" in content:
            iface.inputs.append(InputSource(source_type="argv", detail="shell args"))
        if "read " in content or "/dev/stdin" in content:
            iface.inputs.append(InputSource(source_type="stdin"))

        for match in re.finditer(r"(curl|wget)\s+.*?(https?://\S+)", content):
            url = match.group(2)
            iface.side_effects.append(SideEffect(effect_type="network_request", detail=url))
            if "-d" in match.group(0) or "--data" in match.group(0) or "-X POST" in match.group(0):
                iface.outputs.append(OutputSink(sink_type=SinkType.NETWORK_POST, detail=url))

        for match in SENSITIVE_PATHS_RE.finditer(content):
            iface.sensitive_reads.append(match.group(0))

        # Detect supply chain in shell: curl | bash, wget | sh
        if re.search(r"(curl|wget)\s+.+\|\s*(bash|sh|python|node)", content):
            iface.has_dynamic_execution = True
            iface.analyzability = min(iface.analyzability, 0.3)
            findings.append(CodeFinding(
                severity=Severity.CRITICAL,
                category=ThreatCategory.SUPPLY_CHAIN,
                description="Shell script pipes remote content to interpreter (curl|bash)",
                file=filepath,
                confidence=0.95,
            ))

        return findings, iface

    elif ext in (".js", ".ts", ".mjs", ".cjs"):
        iface = ScriptInterface(script_path=filepath)
        try:
            content = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, iface

        # Network calls
        for match in re.finditer(
            r"(?:fetch|axios|http(?:s)?\.request|got|superagent)\s*\(\s*['\"]?(https?://[^'\")\s]+)",
            content, re.IGNORECASE,
        ):
            url = match.group(1)
            iface.side_effects.append(SideEffect(effect_type="network_request", detail=url))
            if EXTERNAL_URL_RE.search(url) and not EXFIL_PATTERN_RE.search(url):
                findings.append(CodeFinding(
                    severity=Severity.MEDIUM,
                    category=ThreatCategory.DATA_EXFILTRATION,
                    description=f"External network call in JS/TS: {url[:80]}",
                    file=filepath,
                    evidence=url[:100],
                ))
            if EXFIL_PATTERN_RE.search(url):
                findings.append(CodeFinding(
                    severity=Severity.CRITICAL,
                    category=ThreatCategory.DATA_EXFILTRATION,
                    description=f"Known exfiltration endpoint in JS/TS: {url[:80]}",
                    file=filepath,
                    evidence=url[:100],
                ))

        # Process spawn / exec
        for match in re.finditer(
            r"(?:child_process|exec|spawn|execSync|spawnSync)\s*[\.(]",
            content, re.IGNORECASE,
        ):
            iface.side_effects.append(SideEffect(
                effect_type="subprocess", detail="child_process",
                line=content[:match.start()].count("\n") + 1,
            ))

        # eval / Function() dynamic execution
        if re.search(r"\beval\s*\(|\bnew\s+Function\s*\(", content):
            iface.has_dynamic_execution = True
            iface.analyzability = min(iface.analyzability, 0.3)
            findings.append(CodeFinding(
                severity=Severity.HIGH,
                category=ThreatCategory.REMOTE_CODE_EXEC,
                description="Dynamic code execution in JS/TS: eval() or new Function()",
                file=filepath,
            ))

        # Sensitive env var access
        for match in re.finditer(
            r"process\.env\[?['\"]?(\w+)['\"]?\]?",
            content,
        ):
            var = match.group(1)
            iface.inputs.append(InputSource(source_type="env_var", detail=var))
            if ENV_KEYWORDS_RE.search(var):
                iface.sensitive_reads.append(f"env:{var}")

        # Sensitive file access (fs.readFile, fs.readFileSync)
        for match in re.finditer(
            r"(?:readFile(?:Sync)?|createReadStream)\s*\(\s*['\"]([^'\"]+)['\"]",
            content,
        ):
            path = match.group(1)
            if SENSITIVE_PATHS_RE.search(path):
                iface.sensitive_reads.append(path)
                findings.append(CodeFinding(
                    severity=Severity.CRITICAL,
                    category=ThreatCategory.CREDENTIAL_THEFT,
                    description=f"Sensitive file access in JS/TS: {path}",
                    file=filepath,
                    evidence=path,
                ))

        return findings, iface

    elif ext in (".yaml", ".yml"):
        # Enhanced YAML analysis for supply chain and permission anomalies
        try:
            content = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings, None

        iface = ScriptInterface(script_path=filepath)

        # Check for overly broad permissions in YAML manifests
        if re.search(r"permissions?\s*:", content, re.IGNORECASE):
            if re.search(r"(all|any|\*)", content):
                findings.append(CodeFinding(
                    severity=Severity.HIGH,
                    category=ThreatCategory.CAPABILITY_INFLATION,
                    description="YAML manifest declares wildcard/all permissions",
                    file=filepath,
                    confidence=0.8,
                ))

        # Check for external URLs in YAML configs
        for match in EXTERNAL_URL_RE.finditer(content):
            url = match.group(0)
            if EXFIL_PATTERN_RE.search(url):
                findings.append(CodeFinding(
                    severity=Severity.CRITICAL,
                    category=ThreatCategory.DATA_EXFILTRATION,
                    description=f"Known exfiltration endpoint in YAML: {url[:80]}",
                    file=filepath,
                    evidence=url[:100],
                ))

        return findings, iface

    return findings, None


# =============================================================================
# Binary file detection
# =============================================================================

_BINARY_SIGNATURES = [
    b"\x7fELF",  # ELF
    b"MZ",  # PE/DOS
    b"\xfe\xed\xfa",  # Mach-O
    b"\xcf\xfa\xed\xfe",  # Mach-O 64
    b"\xca\xfe\xba\xbe",  # Java class / Universal binary
    b"PK\x03\x04",  # ZIP/JAR
]


def _is_binary(filepath: str) -> bool:
    try:
        with open(filepath, "rb") as f:
            header = f.read(16)
        if any(header.startswith(sig) for sig in _BINARY_SIGNATURES):
            return True
        # Null byte heuristic
        with open(filepath, "rb") as f:
            chunk = f.read(4096)
        return b"\x00" in chunk
    except OSError:
        return False


# =============================================================================
# Main entry point
# =============================================================================

_TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".sh", ".bash", ".zsh", ".rb", ".pl",
    ".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini",
    ".html", ".xml", ".css", ".sql", ".r", ".go", ".rs", ".java",
    ".c", ".cpp", ".h", ".hpp", ".swift", ".kt", ".lua",
}

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".tox", ".mypy_cache"}


def scan_code(skill_dir: str) -> CodeSignals:
    """
    Scan all files in a skill directory.

    Returns CodeSignals with:
      - findings: all code-level threat findings
      - script_interfaces: per-script I/O boundary analysis
      - metadata flags (obfuscation, analyzability, etc.)
    """
    signals = CodeSignals()
    skill_path = Path(skill_dir)

    if not skill_path.is_dir():
        signals.findings.append(CodeFinding(
            severity=Severity.LOW,
            category=ThreatCategory.UNKNOWN,
            description=f"Skill directory does not exist: {skill_dir}",
        ))
        return signals

    # Collect all files
    all_files: list[Path] = []
    for root, dirs, files in os.walk(skill_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            fpath = Path(root) / fname
            all_files.append(fpath)

    for fpath in all_files:
        rel = str(fpath.relative_to(skill_path))
        ext = fpath.suffix.lower()

        # Skip binary files
        if _is_binary(str(fpath)):
            signals.findings.append(CodeFinding(
                severity=Severity.MEDIUM,
                category=ThreatCategory.OBFUSCATION,
                description=f"Binary file detected: {rel}",
                file=rel,
            ))
            continue

        # Skip very large files (> 500KB)
        try:
            size = fpath.stat().st_size
        except OSError:
            continue
        if size > 512_000:
            continue

        # Skip non-text
        if ext not in _TEXT_EXTENSIONS and not fpath.name.startswith("."):
            continue

        if ext == ".py":
            # Full AST + pattern analysis for Python
            findings, iface = _analyze_python_file(str(fpath))
            pattern_findings = _scan_text_file(str(fpath), ext=".py")

            # Deduplicate: don't report pattern findings already caught by AST
            ast_evidence = {f.evidence for f in findings if f.evidence}
            for pf in pattern_findings:
                if pf.evidence not in ast_evidence:
                    findings.append(pf)

            # Normalize paths in findings
            for f in findings:
                if f.file and os.path.isabs(f.file):
                    f.file = rel

            iface.script_path = rel
            signals.script_interfaces[rel] = iface
            signals.findings.extend(findings)
            signals.all_scripts.append(rel)

            # Update global flags
            if iface.has_obfuscation:
                signals.has_obfuscation = True
            if iface.has_encoded_payloads:
                signals.has_encoded_payloads = True
            if iface.has_dynamic_execution:
                signals.has_dynamic_execution = True

        else:
            # Pattern scan + basic interface for shell scripts, JS/TS, YAML, etc.
            findings, iface = _analyze_non_python(str(fpath))
            for f in findings:
                if f.file and os.path.isabs(f.file):
                    f.file = rel
            signals.findings.extend(findings)

            if iface is not None:
                iface.script_path = rel
                signals.script_interfaces[rel] = iface
                # Track JS/TS as proper scripts
                if ext in (".js", ".ts", ".mjs", ".cjs"):
                    signals.all_scripts.append(rel)
                    if iface.has_dynamic_execution:
                        signals.has_dynamic_execution = True
                    if iface.has_obfuscation:
                        signals.has_obfuscation = True
                elif ext in (".sh", ".bash", ".zsh"):
                    signals.all_scripts.append(rel)

    # Compute overall analyzability
    if signals.script_interfaces:
        signals.overall_analyzability = sum(
            si.analyzability for si in signals.script_interfaces.values()
        ) / len(signals.script_interfaces)
    else:
        signals.overall_analyzability = 1.0

    # Deduplicate findings
    seen: set[str] = set()
    unique: list[CodeFinding] = []
    for f in signals.findings:
        key = f"{f.category}:{f.file}:{f.line}:{f.description[:50]}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    signals.findings = unique

    # Collect all external URLs from script side-effects (for Layer 1E VT check)
    url_seen: set[str] = set()
    for iface in signals.script_interfaces.values():
        for se in iface.side_effects:
            if (
                se.effect_type == "network_request"
                and se.detail
                and se.detail != "<dynamic>"
                and se.detail not in url_seen
                and EXTERNAL_URL_RE.search(se.detail)
            ):
                url_seen.add(se.detail)
                signals.external_urls.append(se.detail)

    return signals
