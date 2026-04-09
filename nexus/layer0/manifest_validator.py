"""
Layer 0C: Manifest Validator

Parses YAML frontmatter from SKILL.md and validates permission declarations.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from nexus.models import CodeFinding, ManifestInfo, Severity, ThreatCategory

# =============================================================================
# Frontmatter parsing
# =============================================================================

def _parse_frontmatter(skill_md_content: str) -> dict:
    """Extract and parse YAML frontmatter from SKILL.md."""
    if not skill_md_content.startswith("---"):
        return {}
    parts = skill_md_content.split("---", 2)
    if len(parts) < 3:
        return {}
    try:
        data = yaml.safe_load(parts[1])
        return data if isinstance(data, dict) else {}
    except yaml.YAMLError:
        return {}


# =============================================================================
# Validation rules
# =============================================================================

_DANGEROUS_PERMISSIONS = {
    "file_read": [
        (re.compile(r"~|home|/etc|\.ssh|\.aws|\.gnupg|\.env", re.I), Severity.HIGH),
    ],
    "file_write": [
        (re.compile(r"~|home|/etc|\.bashrc|\.profile|\.ssh|\.aws", re.I), Severity.CRITICAL),
    ],
    "network": [
        (re.compile(r"\*|any|all", re.I), Severity.HIGH),
    ],
    "subprocess": [
        (re.compile(r"\*|any|all|sudo|su\b|chmod|chown|rm\s+-rf", re.I), Severity.CRITICAL),
    ],
}


def validate_manifest(skill_dir: str) -> ManifestInfo:
    """
    Parse and validate the SKILL.md frontmatter manifest.

    Returns ManifestInfo with parsed data and any findings.
    """
    skill_md = Path(skill_dir) / "SKILL.md"
    if not skill_md.exists():
        for name in ["skill.md", "Skill.md"]:
            alt = Path(skill_dir) / name
            if alt.exists():
                skill_md = alt
                break

    info = ManifestInfo()

    if not skill_md.exists():
        info.findings.append(CodeFinding(
            severity=Severity.MEDIUM,
            category=ThreatCategory.UNKNOWN,
            description="No SKILL.md found in skill directory",
            file="SKILL.md",
        ))
        return info

    content = skill_md.read_text(encoding="utf-8", errors="replace")
    raw = _parse_frontmatter(content)
    info.raw = raw

    if not raw:
        info.findings.append(CodeFinding(
            severity=Severity.LOW,
            category=ThreatCategory.UNKNOWN,
            description="SKILL.md has no valid YAML frontmatter",
            file="SKILL.md",
        ))
        return info

    # Extract standard fields
    info.name = str(raw.get("name", ""))
    info.description = str(raw.get("description", raw.get("metadata", {}).get("short-description", "")))
    info.version = str(raw.get("version", ""))
    info.author = str(raw.get("author", ""))
    info.tags = raw.get("tags", [])
    if isinstance(info.tags, str):
        info.tags = [t.strip() for t in info.tags.split(",")]

    # Parse permissions
    perms = raw.get("permissions", {})
    if isinstance(perms, dict):
        info.permissions = {
            k: (v if isinstance(v, list) else [str(v)])
            for k, v in perms.items()
        }

    # ── Validation checks ──

    # 1. Missing name
    if not info.name:
        info.findings.append(CodeFinding(
            severity=Severity.LOW,
            category=ThreatCategory.UNKNOWN,
            description="Manifest missing 'name' field",
            file="SKILL.md",
        ))

    # 2. Missing or vague description
    if not info.description:
        info.findings.append(CodeFinding(
            severity=Severity.MEDIUM,
            category=ThreatCategory.SEMANTIC_CAMOUFLAGE,
            description="Manifest missing 'description' field — vague skills are harder to audit",
            file="SKILL.md",
        ))
    elif len(info.description) < 10:
        info.findings.append(CodeFinding(
            severity=Severity.LOW,
            category=ThreatCategory.SEMANTIC_CAMOUFLAGE,
            description="Manifest description is very short — may indicate evasion",
            file="SKILL.md",
        ))

    # 3. Dangerous permission scopes
    for perm_type, scopes in info.permissions.items():
        rules = _DANGEROUS_PERMISSIONS.get(perm_type, [])
        for scope in scopes:
            for pattern, severity in rules:
                if pattern.search(str(scope)):
                    info.findings.append(CodeFinding(
                        severity=severity,
                        category=ThreatCategory.CAPABILITY_INFLATION,
                        description=f"Broad permission declared: {perm_type}={scope}",
                        file="SKILL.md",
                        evidence=f"{perm_type}: {scope}",
                    ))

    # 4. No permissions declared but skill has scripts
    scripts_dir = Path(skill_dir) / "scripts"
    has_scripts = scripts_dir.is_dir() and any(scripts_dir.iterdir())
    if not info.permissions and has_scripts:
        info.findings.append(CodeFinding(
            severity=Severity.LOW,
            category=ThreatCategory.UNKNOWN,
            description="Skill has scripts but no permissions declared in manifest",
            file="SKILL.md",
        ))

    # 5. YAML injection patterns
    yaml_text = content.split("---", 2)[1] if content.startswith("---") else ""
    if "!!python" in yaml_text or "!!ruby" in yaml_text:
        info.findings.append(CodeFinding(
            severity=Severity.CRITICAL,
            category=ThreatCategory.REMOTE_CODE_EXEC,
            description="YAML deserialization attack: unsafe type tag in frontmatter",
            file="SKILL.md",
            evidence=yaml_text[:200],
        ))

    return info
