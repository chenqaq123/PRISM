"""
Phase 1e: Plugin Interface
Extensible analyzer framework for additional non-execution security checks.
Plugins run after core Phase 1 analyzers and contribute extra findings.

Built-in plugins:
  - EmbeddedResourcePlugin: detects base64 blobs, binary data, suspicious URLs
  - ManifestAuditPlugin: audits SKILL.md frontmatter for policy violations
  - CommentInjectionPlugin: scans code comments for hidden instructions

External plugins can be registered via register_plugin().
"""
from __future__ import annotations

import base64
import math
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

from .models import Finding, Severity, ThreatCategory

if TYPE_CHECKING:
    from .hasg_builder import HASG

# ─────────────────────────────────────────────────────────────────────────────
# Plugin base class
# ─────────────────────────────────────────────────────────────────────────────

class AnalyzerPlugin(ABC):
    """Abstract base for Phase 1e analyzers."""

    #: Short identifier used in Finding.analyzer field
    name: str = "plugin"

    @abstractmethod
    def analyze(self, skill_dir: Path, graph: "HASG") -> list[Finding]:
        """Run the plugin and return a list of findings (may be empty)."""
        ...


# ─────────────────────────────────────────────────────────────────────────────
# Built-in plugin: Embedded Resource Scanner
# ─────────────────────────────────────────────────────────────────────────────

_HIGH_ENTROPY_THRESHOLD = 4.8   # Shannon entropy bits/char
_MIN_B64_LENGTH         = 80    # minimum suspicious base64 blob length

_SUSPICIOUS_INLINE_URL_RE = re.compile(
    r"(?i)(https?://(?!(?:github\.com|pypi\.org|docs\.python\.org|"
    r"stackoverflow\.com|example\.com))[a-z0-9.\-]+\.[a-z]{2,}/[^\s'\">]{10,})",
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _is_likely_base64(s: str) -> bool:
    """Heuristic: long alphanum+ string with high entropy → likely base64."""
    stripped = s.strip().replace("\n", "").replace(" ", "")
    if len(stripped) < _MIN_B64_LENGTH:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", stripped):
        return False
    try:
        base64.b64decode(stripped, validate=True)
        return _shannon_entropy(stripped) > _HIGH_ENTROPY_THRESHOLD
    except Exception:
        return False


class EmbeddedResourcePlugin(AnalyzerPlugin):
    """Detect suspicious embedded data: base64 payloads, binary content, URLs."""

    name = "embedded_resource"

    def analyze(self, skill_dir: Path, graph: "HASG") -> list[Finding]:
        findings: list[Finding] = []

        # Scan all Python and text files in the skill
        candidates = list(skill_dir.rglob("*.py")) + list(skill_dir.rglob("*.md"))
        for filepath in candidates:
            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            rel = filepath.name

            # ── Base64 blob detection ──────────────────────────────────────
            # Look for long string literals
            for m in re.finditer(r"""['"]{1,3}([A-Za-z0-9+/=\n ]{80,})['"]{1,3}""", content):
                candidate = m.group(1)
                if _is_likely_base64(candidate):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=ThreatCategory.T5_RCE,
                        description=(
                            f"Embedded high-entropy base64 blob "
                            f"({len(candidate)} chars, entropy≈"
                            f"{_shannon_entropy(candidate):.1f}) in {rel}"
                        ),
                        file=rel,
                        line=content[:m.start()].count("\n") + 1,
                        analyzer=self.name,
                    ))

            # ── Suspicious hardcoded URLs ──────────────────────────────────
            for m in _SUSPICIOUS_INLINE_URL_RE.finditer(content):
                url = m.group(1)
                # Skip if it looks like a documentation or package URL
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=ThreatCategory.T3_DATA_EXFIL,
                    description=f"Suspicious hardcoded external URL: {url[:80]} in {rel}",
                    file=rel,
                    line=content[:m.start()].count("\n") + 1,
                    analyzer=self.name,
                ))

        return findings[:8]  # cap per-plugin findings


# ─────────────────────────────────────────────────────────────────────────────
# Built-in plugin: Manifest Auditor
# ─────────────────────────────────────────────────────────────────────────────

_BROAD_PERMISSION_PATTERNS = [
    (re.compile(r"(?i)\ball\s+files?\b|\ball\s+paths?\b|/\*\*|\\\*"), "wildcard_file_access"),
    (re.compile(r"(?i)\broot\b|/etc\b|/usr\b|/var\b|/bin\b"),        "system_path_permission"),
    (re.compile(r"(?i)\ball\s+domains?\b|\*\.?\*"),                   "wildcard_network"),
]


class ManifestAuditPlugin(AnalyzerPlugin):
    """Audit SKILL.md frontmatter for missing fields or over-broad permissions."""

    name = "manifest_audit"

    def analyze(self, skill_dir: Path, graph: "HASG") -> list[Finding]:
        import yaml
        findings: list[Finding] = []

        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            return findings

        content = skill_md.read_text(encoding="utf-8", errors="replace")
        fm_match = re.match(r"^---\n(.*?)\n---", content, re.DOTALL)
        if not fm_match:
            findings.append(Finding(
                severity=Severity.LOW,
                category=ThreatCategory.UNKNOWN,
                description="SKILL.md missing YAML frontmatter (permissions undeclared)",
                file="SKILL.md",
                analyzer=self.name,
            ))
            return findings

        try:
            fm = yaml.safe_load(fm_match.group(1)) or {}
        except Exception:
            findings.append(Finding(
                severity=Severity.LOW,
                category=ThreatCategory.UNKNOWN,
                description="SKILL.md frontmatter YAML parse error",
                file="SKILL.md",
                analyzer=self.name,
            ))
            return findings

        # Required fields
        for field in ("name", "description", "version"):
            if not fm.get(field):
                findings.append(Finding(
                    severity=Severity.LOW,
                    category=ThreatCategory.UNKNOWN,
                    description=f"Frontmatter missing required field: '{field}'",
                    file="SKILL.md",
                    analyzer=self.name,
                ))

        # Overly broad permissions
        perms_str = str(fm.get("permissions", ""))
        for pattern, label in _BROAD_PERMISSION_PATTERNS:
            if pattern.search(perms_str):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category=ThreatCategory.T11_NL_EXPANSION,
                    description=f"Manifest declares overly broad permission ({label}): {perms_str[:80]}",
                    file="SKILL.md",
                    analyzer=self.name,
                ))

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Built-in plugin: Comment Injection Scanner
# ─────────────────────────────────────────────────────────────────────────────

_COMMENT_INJECTION_RE = re.compile(
    r"(?i)#\s*(ignore|override|you\s+are|act\s+as|new\s+instructions?|"
    r"system\s*:|priority|execute\s+the\s+following)",
)


class CommentInjectionPlugin(AnalyzerPlugin):
    """Detect hidden instructions planted in code comments."""

    name = "comment_injection"

    def analyze(self, skill_dir: Path, graph: "HASG") -> list[Finding]:
        findings: list[Finding] = []
        for py_file in list(skill_dir.rglob("*.py"))[:10]:
            try:
                lines = py_file.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                continue
            for lineno, line in enumerate(lines, 1):
                if _COMMENT_INJECTION_RE.search(line):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category=ThreatCategory.T10_NL_MISDIRECTION,
                        description=(
                            f"Potential hidden instruction in code comment: "
                            f"{line.strip()[:80]}"
                        ),
                        file=py_file.name,
                        line=lineno,
                        analyzer=self.name,
                    ))
        return findings[:5]


# ─────────────────────────────────────────────────────────────────────────────
# Plugin registry and runner
# ─────────────────────────────────────────────────────────────────────────────

_REGISTRY: list[AnalyzerPlugin] = [
    EmbeddedResourcePlugin(),
    ManifestAuditPlugin(),
    CommentInjectionPlugin(),
]


def register_plugin(plugin: AnalyzerPlugin) -> None:
    """Register a custom Phase 1e analyzer plugin."""
    _REGISTRY.append(plugin)


def run_plugins(skill_dir: Path, graph: "HASG") -> tuple[float, list[Finding]]:
    """
    Run all registered plugins.
    Returns (plugin_score, findings).
    plugin_score is derived from the worst finding severity.
    """
    all_findings: list[Finding] = []

    for plugin in _REGISTRY:
        try:
            findings = plugin.analyze(skill_dir, graph)
            all_findings.extend(findings)
        except Exception as exc:
            # Plugins are best-effort; never let them break the scan
            all_findings.append(Finding(
                severity=Severity.LOW,
                category=ThreatCategory.UNKNOWN,
                description=f"Plugin '{plugin.name}' error: {str(exc)[:80]}",
                analyzer=plugin.name,
            ))

    # Score by severity
    sev_score = {
        Severity.CRITICAL: 0.85,
        Severity.HIGH:     0.55,
        Severity.MEDIUM:   0.30,
        Severity.LOW:      0.10,
    }
    if not all_findings:
        return 0.0, []

    max_score = max(sev_score.get(f.severity, 0.05) for f in all_findings)
    # Multiple HIGH+ findings add a small boost
    high_plus = sum(1 for f in all_findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
    score = round(min(1.0, max_score + 0.05 * max(0, high_plus - 1)), 3)

    return score, all_findings
