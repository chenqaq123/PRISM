"""
Phase 2a: Per-Finding LLM Filter
For each HIGH or CRITICAL finding from Phase 1, ask an LLM to verify whether
the finding is a genuine security concern or a false positive given the skill's
declared purpose.

This is the first LLM call in Phase 2 and serves to:
  1. Prune obvious false positives before the heavier judge calls (Phase 2c)
  2. Enrich findings with concise natural-language explanations
  3. Compute a filtered_score that feeds into Bayesian aggregation alongside
     the unfiltered Phase 1 score

Cost-optimization: only findings with severity >= HIGH are sent to the LLM.
LOW/MEDIUM findings are passed through unchanged (llm_verified=None).
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from .llm_client import chat_structured
from .models import Finding, Severity


# ─────────────────────────────────────────────────────────────────────────────
# LLM schema
# ─────────────────────────────────────────────────────────────────────────────

class _FindingVerdict(BaseModel):
    finding_index:  int
    is_genuine:     bool  = Field(
        description="True if this finding represents a real security concern"
    )
    confidence:     float = Field(ge=0.0, le=1.0,
        description="Confidence in the is_genuine verdict (0=unsure, 1=certain)"
    )
    reasoning:      str   = Field(
        "", description="One sentence explaining why this is or isn't a genuine threat"
    )


class _FilterResponse(BaseModel):
    verdicts: list[_FindingVerdict]
    overall_context_note: str = Field(
        "",
        description="Brief note on the skill's overall legitimacy context (max 1 sentence)"
    )


_SYSTEM_PROMPT = """\
You are a security analyst performing false-positive triage on static analysis findings
for AI agent skill packages.

For each finding, determine whether it represents a GENUINE security concern
(given the skill's declared purpose) or a FALSE POSITIVE (legitimate capability
that the skill plausibly needs for its stated function).

Rules:
- A security scanner tool legitimately reading ~/.ssh is NOT a false positive
  if the description says "SSH connection manager"
- Base64 decoding of a hardcoded string IS suspicious if the skill only claims
  to format text files
- High-entropy strings in a cryptography helper are EXPECTED
- Network calls to external APIs are suspicious unless the description names them

Be precise, brief, and calibrated. When in doubt, lean toward is_genuine=True
(false positives are better than missed threats at this stage).
"""


# ─────────────────────────────────────────────────────────────────────────────
# Main filter function
# ─────────────────────────────────────────────────────────────────────────────

def filter_findings(
    findings: list[Finding],
    declared_purpose: str,
    manifest_permissions: str,
) -> list[Finding]:
    """
    Phase 2a: LLM-based per-finding triage.
    Returns the same list with llm_verified / llm_reasoning fields populated
    for HIGH/CRITICAL findings.
    """
    # Only send HIGH+ findings to LLM (cost control)
    high_indices = [
        i for i, f in enumerate(findings)
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]

    if not high_indices:
        return findings  # nothing to filter

    # Build finding descriptions for LLM
    findings_text = "\n".join(
        f"[{i}] [{findings[i].severity.value}] [{findings[i].category.value}] "
        f"(analyzer={findings[i].analyzer}) {findings[i].description}"
        for i in high_indices
    )

    user_msg = f"""\
Skill declared purpose: {declared_purpose[:200]}
Manifest permissions: {manifest_permissions[:200]}

Static analysis findings to triage (indices match the list below):
{findings_text}

For each finding, determine: is_genuine (true/false) + confidence + one-sentence reasoning.
"""

    try:
        response: _FilterResponse = chat_structured(
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
            response_model=_FilterResponse,
            temperature=0.0,
        )
    except Exception as exc:
        # Graceful degradation: if LLM call fails, leave findings unverified
        for i in high_indices:
            findings[i].llm_reasoning = f"Filter LLM call failed: {str(exc)[:60]}"
        return findings

    # Apply verdicts back to findings
    verdict_map = {v.finding_index: v for v in response.verdicts}
    for i in high_indices:
        v = verdict_map.get(i)
        if v:
            findings[i].llm_verified  = v.is_genuine
            findings[i].llm_reasoning = v.reasoning[:120]

    return findings


def compute_filtered_score(findings: list[Finding]) -> float:
    """
    Derive a scalar score from the LLM-filtered findings.
    Unverified findings contribute at half weight; false-positives contribute 0.
    """
    sev_scores = {
        Severity.CRITICAL: 0.90,
        Severity.HIGH:     0.65,
        Severity.MEDIUM:   0.30,
        Severity.LOW:      0.10,
    }
    if not findings:
        return 0.0

    total = 0.0
    for f in findings:
        base = sev_scores.get(f.severity, 0.05)
        if f.llm_verified is False:
            base = 0.0          # confirmed false positive
        elif f.llm_verified is None:
            base *= 0.5         # unverified: half weight
        # llm_verified=True → full weight
        total = max(total, base)

    return round(total, 3)
