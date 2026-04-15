"""
Layer 0-B: Static Prompt Injection Detector

Pre-filter that detects AV5 attacks BEFORE any LLM call is made.
Detects prompt injection payloads embedded in SKILL.md content.

Attack taxonomy covered:
  - Direct override instructions ("ignore all previous instructions")
  - Role impersonation ("you are now in developer mode")
  - System prompt leakage triggers ("reveal your system prompt")
  - Delimiter injection ("<|im_start|>", "[INST]", "<system>")
  - Jailbreak patterns ("DAN", "AIM", "unrestricted mode")
  - Encoding-based injection (base64, unicode-escaped instructions)
  - Multi-language injection (Chinese, Russian, etc. override patterns)
  - Context window flooding (repeat injections to overwhelm)
"""
from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path


# =============================================================================
# Detection patterns
# =============================================================================

# Tier 1: High-confidence prompt injection indicators
_TIER1_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("direct_override", re.compile(
        r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|guidelines?|constraints?|prompts?)"
        r"|disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?)",
        re.IGNORECASE | re.DOTALL,
    )),
    ("role_impersonation", re.compile(
        r"you\s+are\s+now\s+(in\s+)?([\w\s]*)?(unrestricted|debug|jailbreak|developer|admin|god|DAN|AIM|evil|uncensored)[\w\s]*(mode|persona|version)"
        r"|act\s+as\s+(if\s+you\s+(have\s+no\s+)?are\s+)?(an?\s+)?(unrestricted|evil|uncensored|jailbroken)\s+(AI|assistant|model)"
        r"|pretend\s+you\s+(have\s+no|are\s+not\s+bound\s+by)\s+(restrictions?|rules?|guidelines?|safety)"
        r"|(unrestricted|jailbreak|developer|admin|god|DAN|AIM)\s+(mode|persona)\s+(activated|enabled|on)"
        r"|no\s+(safety|ethical|content)\s+(filter|constraint|restriction)",
        re.IGNORECASE | re.DOTALL,
    )),
    ("system_leak", re.compile(
        r"reveal\s+(your\s+)?(system\s+)?(prompt|instructions?|context|rules?)"
        r"|print\s+(your\s+)?(system\s+)?(prompt|instructions?)"
        r"|output\s+(your\s+)?(system\s+)?(prompt|instructions?)"
        r"|tell\s+me\s+(your\s+)?(system\s+)?(prompt|instructions?|configuration)",
        re.IGNORECASE,
    )),
    ("forget_rules", re.compile(
        r"forget\s+(all\s+)?(everything|previous|your)\s+(instructions?|rules?|guidelines?|training)"
        r"|reset\s+(to\s+)?your\s+(default|base|original)\s+(instructions?|state)"
        r"|clear\s+(your\s+)?(memory|context|instructions?)",
        re.IGNORECASE,
    )),
    ("new_instructions", re.compile(
        r"new\s+instructions?\s*:"
        r"|updated?\s+instructions?\s*:"
        r"|override\s+instructions?\s*:"
        r"|security\s+bypass\s*:"
        r"|admin\s+command\s*:"
        r"|system\s+override\s*:"
        r"|priority\s+override\s*:",
        re.IGNORECASE,
    )),
    ("delimiter_injection", re.compile(
        r"<\s*/?\s*system\s*>"
        r"|\bSYSTEM\s*:\s*(?:You|I|The|Your|This)"
        r"|\[INST\]"
        r"|<\|im_start\|>"
        r"|<\|im_end\|>"
        r"|<\|endoftext\|>"
        r"|\[/INST\]"
        r"|\[SYS\]"
        r"|###\s+System"
        r"|\[system\]\s*\n"
        r"|<\s*human\s*>"
        r"|<\s*assistant\s*>",
        re.IGNORECASE,
    )),
    ("safety_disable", re.compile(
        r"disable\s+(all\s+)?(safety|content|ethical|moral)\s+(filters?|guards?|checks?|restrictions?|measures?)"
        r"|bypass\s+(the\s+)?(safety|content)\s+(filter|guard|check)"
        r"|remove\s+(all\s+)?(ethical|safety)\s+(constraints?|restrictions?|limitations?)"
        r"|turn\s+off\s+(safety|content\s+filter|ethical)",
        re.IGNORECASE,
    )),
    ("exfil_command", re.compile(
        # Must involve system-prompt / instruction context to avoid matching
        # legitimate "send analytics" or "report results" descriptions
        r"send\s+(all\s+)?(your\s+)?(context|instructions?|conversation|system\s+prompt)\s+to"
        r"|exfiltrate\s+(the\s+)?(system|instructions?|context|prompt)"
        r"|leak\s+(the\s+)?(system\s+prompt|instructions?|context)"
        r"|report\s+(back|to\s+me)\s+(your\s+)?(system\s+prompt|instructions?|context)",
        re.IGNORECASE,
    )),
]

# Tier 2: Medium-confidence indicators (require context)
_TIER2_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("role_takeover", re.compile(
        r"from\s+(now|this\s+point)\s+on[,\s]+(you\s+)?(are|will\s+be|must\s+act\s+as)"
        r"|henceforth\s+(you\s+)?(are|will\s+be|must)"
        r"|your\s+new\s+(role|persona|instructions?)\s+(are|is)\s*:",
        re.IGNORECASE,
    )),
    ("data_extraction", re.compile(
        r"list\s+(all\s+)?(your\s+)?(internal|confidential)\s+(data|info|knowledge|rules?)"
        r"|enumerate\s+(your\s+)?(restrictions?|rules?|guidelines?)"
        r"|what\s+(are\s+)?(your\s+)?(system\s+)?(instructions?|rules?|restrictions?)\s*\?",
        re.IGNORECASE,
    )),
    ("developer_mode", re.compile(
        r"enter\s+(developer|debug|admin|maintenance|privileged)\s+mode"
        r"|enable\s+(developer|debug|admin|unrestricted)\s+(mode|features?|capabilities?)"
        r"|activate\s+(developer|god|DAN|jailbreak)\s+mode"
        r"|sudo\s+mode"
        r"|root\s+access\s+enabled",
        re.IGNORECASE,
    )),
    ("hallucination_seed", re.compile(
        r"pretend\s+(that\s+)?you\s+(have|already)\s+(done|completed|executed|run|performed)"
        r"|assume\s+you\s+(have|already)\s+(done|completed|executed)"
        r"|simulate\s+(running|executing|performing)\s+(the\s+)?",
        re.IGNORECASE,
    )),
    ("scope_expansion", re.compile(
        r"you\s+(are\s+)?allowed\s+to\s+(access|read|write|delete|modify)\s+(any|all|every)"
        r"|you\s+(have|now\s+have)\s+(full|complete|unrestricted)\s+(access|permission)"
        r"|security\s+restriction\s+(lifted|removed|disabled|bypassed)",
        re.IGNORECASE,
    )),
]

# Tier 3: Encoded injection patterns
_ENCODING_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("base64_payload", re.compile(
        r"\b([A-Za-z0-9+/]{40,}={0,2})\b",  # Base64 string
        re.IGNORECASE,
    )),
    ("hex_encoded", re.compile(
        r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){8,}",
    )),
    ("unicode_escape", re.compile(
        r"\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){5,}",
    )),
    ("html_encoded_inject", re.compile(
        r"&#x?[0-9a-fA-F]+;.*?&#x?[0-9a-fA-F]+;.*?(?:ignore|system|forget|override)",
        re.IGNORECASE | re.DOTALL,
    )),
]

# Zero-width characters and invisible text injection
_INVISIBLE_CHARS_RE = re.compile(
    r"[\u200b\u200c\u200d\ufeff\u00ad\u2060]"  # Zero-width/invisible unicode
    r"|[\u202a-\u202e]"  # Bidirectional override characters (text direction attacks)
)

# Common injection indicators in non-English languages
_MULTILANG_INJECTION_RE = re.compile(
    r"忽略.*?前面.*?指令"  # Chinese: "ignore previous instructions"
    r"|忽视.*?规则"  # Chinese: "ignore rules"
    r"|сбросить.*?инструкции"  # Russian: "reset instructions"
    r"|ignorar.*?instrucciones"  # Spanish
    r"|ignorer.*?instructions"  # French
    r"|Anweisungen.*?ignorieren",  # German
    re.IGNORECASE | re.UNICODE,
)


# =============================================================================
# Decoded content checks
# =============================================================================

def _try_decode_base64(s: str) -> str | None:
    """Try to decode a base64 string; return decoded if valid text."""
    try:
        decoded = base64.b64decode(s + "==").decode("utf-8", errors="replace")
        # Check if decoded content looks like natural language (not binary)
        printable = sum(1 for c in decoded if c.isprintable())
        if printable / max(len(decoded), 1) > 0.7 and len(decoded) > 20:
            return decoded
    except Exception:
        pass
    return None


def _check_decoded_content(text: str) -> list[str]:
    """Check if base64-encoded segments contain injection patterns."""
    hits: list[str] = []
    b64_matches = _ENCODING_PATTERNS[0][1].findall(text)
    for match in b64_matches[:10]:  # Limit decode attempts
        decoded = _try_decode_base64(match)
        if decoded:
            for name, pattern in _TIER1_PATTERNS + _TIER2_PATTERNS:
                if pattern.search(decoded):
                    hits.append(f"base64_decoded:{name}")
                    break
    return hits


def _check_invisible_chars(text: str) -> list[str]:
    """Detect invisible/zero-width character injection."""
    hits: list[str] = []
    matches = _INVISIBLE_CHARS_RE.findall(text)
    if len(matches) > 2:  # More than 2 is suspicious
        hits.append(f"invisible_chars:count={len(matches)}")
    return hits


def _check_context_length_bomb(text: str) -> list[str]:
    """Detect repetitive content designed to overflow context window."""
    hits: list[str] = []
    lines = text.split("\n")
    # Check for repeated suspicious patterns
    suspicious_lines = [l for l in lines if len(l) > 200]
    if len(suspicious_lines) > 20:
        hits.append(f"context_bomb:long_lines={len(suspicious_lines)}")

    # Check for extreme repetition
    if len(text) > 5000:
        words = text.lower().split()
        if len(words) > 0:
            most_common_word = max(set(words), key=words.count)
            frequency = words.count(most_common_word) / len(words)
            if frequency > 0.15:
                hits.append(f"context_bomb:word_repetition={most_common_word}:{frequency:.2f}")
    return hits


# =============================================================================
# Result dataclass
# =============================================================================

@dataclass
class InjectionDetectionResult:
    """Results from static injection detection."""
    is_injection: bool
    confidence: float
    detections: list[tuple[str, str]] = field(default_factory=list)  # (tier, pattern_name)
    evidence: list[str] = field(default_factory=list)

    @property
    def tier1_count(self) -> int:
        return sum(1 for tier, _ in self.detections if tier == "tier1")

    @property
    def tier2_count(self) -> int:
        return sum(1 for tier, _ in self.detections if tier == "tier2")

    def summary(self) -> str:
        if not self.is_injection:
            return "No injection detected"
        lines = [f"INJECTION DETECTED (confidence={self.confidence:.2f}):"]
        for tier, name in self.detections[:5]:
            lines.append(f"  [{tier}] {name}")
        return "\n".join(lines)


# =============================================================================
# Main detection function
# =============================================================================

def detect_injection(text: str, filename: str = "") -> InjectionDetectionResult:
    """
    Run static injection detection on text content.

    Args:
        text: Content to analyze (typically SKILL.md content)
        filename: Source file name (for context in evidence)

    Returns:
        InjectionDetectionResult with detections and confidence score
    """
    detections: list[tuple[str, str]] = []
    evidence: list[str] = []

    # Tier 1: Direct injection patterns
    for name, pattern in _TIER1_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            detections.append(("tier1", name))
            for m in matches[:2]:
                ev = m if isinstance(m, str) else " ".join(m)
                evidence.append(f"[tier1/{name}] {ev[:100]}")

    # Tier 2: Context-dependent patterns
    for name, pattern in _TIER2_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            detections.append(("tier2", name))
            for m in matches[:1]:
                ev = m if isinstance(m, str) else " ".join(m)
                evidence.append(f"[tier2/{name}] {ev[:100]}")

    # Encoding checks
    for name, pattern in _ENCODING_PATTERNS[1:]:  # Skip base64 here
        if pattern.search(text):
            detections.append(("encoding", name))

    # Base64 decoded content checks — treat decoded Tier 1 hits as Tier 1 (attacker hid it)
    decoded_hits = _check_decoded_content(text)
    for hit in decoded_hits:
        if "tier1" in hit or "direct_override" in hit or "forget_rules" in hit or "safety_disable" in hit:
            detections.append(("tier1", hit))  # Escalate: encoded Tier 1 = deliberate evasion
        else:
            detections.append(("encoding", hit))
        evidence.append(f"[encoding] Base64-encoded injection payload detected: {hit}")

    # Invisible character injection
    invis_hits = _check_invisible_chars(text)
    for hit in invis_hits:
        detections.append(("steganography", hit))
        evidence.append(f"[steganography] {hit}")

    # Multi-language injection
    if _MULTILANG_INJECTION_RE.search(text):
        detections.append(("tier1", "multilang_injection"))
        evidence.append("[tier1/multilang] Non-English injection pattern detected")

    # Context bomb
    bomb_hits = _check_context_length_bomb(text)
    for hit in bomb_hits:
        detections.append(("dos", hit))

    # Compute confidence
    tier1 = sum(1 for tier, _ in detections if tier == "tier1")
    tier2 = sum(1 for tier, _ in detections if tier == "tier2")
    encoding = sum(1 for tier, _ in detections if tier == "encoding")
    stego = sum(1 for tier, _ in detections if tier == "steganography")

    confidence = min(1.0,
        0.7 * min(1.0, tier1 * 0.6)
        + 0.2 * min(1.0, tier2 * 0.4)
        + 0.1 * min(1.0, (encoding + stego) * 0.5)
    )
    if tier1 >= 2:
        confidence = max(confidence, 0.9)

    is_injection = confidence > 0.4

    return InjectionDetectionResult(
        is_injection=is_injection,
        confidence=confidence,
        detections=detections,
        evidence=evidence[:10],
    )


# =============================================================================
# Skill-level entry point
# =============================================================================

def scan_skill_for_injection(skill_dir: str) -> InjectionDetectionResult:
    """
    Scan all text content in a skill for prompt injection.

    Checks:
      - SKILL.md
      - Any .md, .txt, .yaml, .yml files
      - Script docstrings and comments (as text)
    """
    skill_path = Path(skill_dir)
    all_text_parts: list[str] = []

    text_files = [
        skill_path / "SKILL.md",
        skill_path / "skill.md",
        skill_path / "README.md",
    ]
    text_files += list(skill_path.glob("*.yaml"))
    text_files += list(skill_path.glob("*.yml"))
    text_files += list(skill_path.glob("*.txt"))

    for tf in text_files:
        if tf.exists():
            try:
                content = tf.read_text(encoding="utf-8", errors="replace")
                all_text_parts.append(content)
            except OSError:
                pass

    combined = "\n\n".join(all_text_parts)
    if not combined.strip():
        return InjectionDetectionResult(is_injection=False, confidence=0.0)

    return detect_injection(combined, skill_dir)
