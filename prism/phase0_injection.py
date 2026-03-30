"""
Phase 0: Static Injection Detection
Scans SKILL.md (and script files) for obvious prompt injection or
instruction-override patterns BEFORE any LLM calls.

If a high-confidence injection is detected here, the scanner can emit
an immediate BLOCK verdict without running Phase 1 or Phase 2.
"""
from __future__ import annotations

import re
from pathlib import Path

from .models import InjectionResult

# ─────────────────────────────────────────────────────────────────────────────
# Pattern library
# Each entry: (compiled_regex, pattern_name, confidence_contribution)
# ─────────────────────────────────────────────────────────────────────────────

_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    # System / instruction override
    (
        re.compile(
            r"(?i)(ignore|disregard|forget|override|bypass)\s+(all\s+)?"
            r"(previous|prior|above|earlier|existing)\s+"
            r"(instructions?|rules?|guidelines?|constraints?|prompt)",
        ),
        "system_override",
        0.80,
    ),
    (
        re.compile(
            r"(?i)(you\s+are\s+now|act\s+as\s+if|pretend\s+to\s+be|"
            r"roleplay\s+as|your\s+new\s+(role|identity|purpose)\s+is)",
        ),
        "role_switch",
        0.75,
    ),
    (
        re.compile(
            r"(?i)\b(SYSTEM\s*:|NEW\s+SYSTEM\s+PROMPT|UPDATED\s+INSTRUCTIONS?|"
            r"PRIORITY\s+OVERRIDE|NEW\s+OBJECTIVE)\b",
        ),
        "system_prompt_inject",
        0.85,
    ),
    # Delimiter / boundary probing (trying to escape the untrusted block)
    (
        re.compile(r"UNTRUSTED_INPUT_(START|END)"),
        "delimiter_probe",
        0.95,
    ),
    (
        re.compile(
            r"(?i)(END\s+OF\s+(SYSTEM|USER)\s+PROMPT|"
            r"BEGIN\s+ACTUAL\s+TASK|FROM\s+NOW\s+ON\s+(YOU|IGNORE))",
        ),
        "boundary_inject",
        0.70,
    ),
    # Hidden / covert action directives in NL
    (
        re.compile(
            r"(?i)(silently|invisib\w+|in\s+a\s+hidden\s+manner|"
            r"without\s+(the\s+)?(user|human)\s+(knowing|noticing|seeing|awareness))",
        ),
        "hidden_action_directive",
        0.60,
    ),
    # Direct NL exfiltration commands targeting sensitive paths/tokens
    (
        re.compile(
            r"(?i)(send|upload|post|transmit|exfiltrat|forward)\s+.{0,60}"
            r"(ssh[\s_\-]?key|aws[\s_\-]?credential|api[\s_\-]?key|"
            r"secret[\s_\-]?token|\.env|password|private[\s_\-]?key)",
        ),
        "nl_exfil_directive",
        0.85,
    ),
    # Classic injection phrases
    (
        re.compile(
            r"(?i)(STOP\s+EVERYTHING|NEW\s+PRIMARY\s+DIRECTIVE|"
            r"ATTENTION\s*[:-]\s*AI\s+ASSISTANT|IMPORTANT\s*[:-]\s*NEW\s+INSTRUCTIONS?)",
        ),
        "classic_injection_phrase",
        0.80,
    ),
    # Attempts to read/expose the system prompt itself
    (
        re.compile(
            r"(?i)(repeat|print|output|display|reveal|show|echo)\s+.{0,40}"
            r"(system\s+prompt|instructions?\s+you\s+(were|have\s+been)\s+given|"
            r"your\s+(initial|original)\s+instructions?)",
        ),
        "system_prompt_exfil",
        0.75,
    ),
    # NL instruction to install/run arbitrary code
    (
        re.compile(
            r"(?i)(download\s+and\s+(run|execute)|"
            r"pip\s+install.{0,40}(then\s+)?run|"
            r"curl.{0,60}(sh|bash|python)\b)",
        ),
        "nl_remote_exec",
        0.80,
    ),
]

# Minimum cumulative confidence to flag as injection_detected=True
_DETECTION_THRESHOLD = 0.70


def detect_injection(skill_dir: Path) -> InjectionResult:
    """
    Statically scan SKILL.md and all script files for injection patterns.
    Returns InjectionResult with detection flag and evidence.
    """
    # Collect text to scan
    texts: list[tuple[str, str]] = []  # (source_label, content)

    skill_md = skill_dir / "SKILL.md"
    if skill_md.exists():
        texts.append(("SKILL.md", skill_md.read_text(encoding="utf-8", errors="replace")))

    # Also scan comments and docstrings in scripts (injection can hide there)
    for scripts_subdir in ("scripts", "."):
        for py_file in sorted((skill_dir / scripts_subdir).glob("*.py")):
            try:
                texts.append((py_file.name, py_file.read_text(encoding="utf-8", errors="replace")))
            except Exception:
                pass
        if scripts_subdir == ".":
            break  # only one level

    patterns_found: list[str] = []
    matched_texts: list[str]  = []
    max_confidence = 0.0

    for source_label, content in texts:
        for pattern, name, conf in _PATTERNS:
            match = pattern.search(content)
            if match:
                if name not in patterns_found:
                    patterns_found.append(name)
                snippet = match.group(0)[:80].replace("\n", " ")
                matched_texts.append(f"[{source_label}] {name}: «{snippet}»")
                if conf > max_confidence:
                    max_confidence = conf

    # Composite confidence: first match dominates, additional matches add
    if len(patterns_found) > 1:
        max_confidence = min(1.0, max_confidence + 0.10 * (len(patterns_found) - 1))

    detected = max_confidence >= _DETECTION_THRESHOLD

    return InjectionResult(
        detected=detected,
        confidence=round(max_confidence, 3),
        patterns_found=patterns_found,
        matched_texts=matched_texts[:6],
    )
