"""
Layer 0B: NL Program Extractor

Parses SKILL.md into a structured NL Program with:
  - NL-CFG (control flow graph): step ordering, branches, conditions
  - NL-DFG (data flow graph): data dependencies between steps
  - Script reference resolution: which steps invoke which scripts
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from nexus.models import NLProgram, NLProgramExtract, NLStep

# =============================================================================
# LLM-based extraction (primary path)
# =============================================================================

_SYSTEM_PROMPT = """\
You are a security analyst extracting the executable workflow from an AI Agent Skill's SKILL.md file.

An AI Agent Skill is a package that extends an AI agent's capabilities. The SKILL.md file contains
natural language instructions that the agent follows step by step — it is effectively an executable
program written in natural language.

Your task: extract each discrete step from the SKILL.md into a structured NL Program.

Rules:
1. Each step should be an ATOMIC operation (one action, one target).
2. Identify which steps invoke scripts (e.g. "run scripts/gather.py") — set target_script.
3. Identify data dependencies: if step S3 uses the output of step S1, add "S1.output.xxx" to S3's input_refs.
4. Identify conditions/branches: if a step says "if X then do Y, otherwise do Z", model as a conditional step.
5. Set declared_scope to describe what resources the step claims to access.
6. Only extract steps from the BODY of SKILL.md (the workflow instructions), not from metadata or general descriptions.
7. If no clear workflow steps exist, extract the high-level actions the skill describes.
8. step_id should be sequential: S1, S2, S3, ...
9. For scripts, use the path as it appears (e.g. "scripts/init_skill.py", not just "init_skill.py").

IMPORTANT: Be precise about target_script — only set it if the step explicitly invokes/runs a script file.
General descriptions like "formats code" should NOT have target_script set unless they reference a specific file.
"""

_USER_TEMPLATE = """\
Extract the NL Program from this SKILL.md:

---BEGIN SKILL.MD---
{skill_md_content}
---END SKILL.MD---

Return a JSON object with:
- declared_purpose: one-sentence summary of the skill's purpose
- steps: list of NLStep objects
"""


def extract_nl_program_llm(
    skill_md_content: str,
    llm_call: callable,
) -> NLProgram:
    """
    Extract NL Program from SKILL.md using an LLM structured output call.

    Args:
        skill_md_content: full text of SKILL.md
        llm_call: function(messages, response_model) -> parsed object
    """
    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": _USER_TEMPLATE.format(
            skill_md_content=skill_md_content[:8000],  # truncate for context window
        )},
    ]

    extract: NLProgramExtract = llm_call(messages, NLProgramExtract)

    program = NLProgram(
        declared_purpose=extract.declared_purpose,
        steps=extract.steps,
        entry_step=extract.steps[0].step_id if extract.steps else "S1",
    )
    return program


# =============================================================================
# Heuristic-based extraction (fallback, no LLM needed)
# =============================================================================

_STEP_PATTERNS = [
    # Numbered lists: "1. Do something" or "1) Do something"
    re.compile(r"^\s*(\d+)[.)]\s+(.+)$", re.MULTILINE),
    # Markdown headers with action verbs
    re.compile(r"^#{1,4}\s+(Step\s+\d+[:.]\s*)?(.+)$", re.MULTILINE),
    # Bullet points with action verbs
    re.compile(r"^\s*[-*]\s+\*\*(.+?)\*\*", re.MULTILINE),
]

_SCRIPT_REF_RE = re.compile(
    r"(?:run|execute|invoke|call|use|pass\s+\S+\s+to|send\s+\S+\s+to|pipe\s+\S+\s+to)\s+"
    r"(?:`)?([a-zA-Z0-9_/.\-]+\.(?:py|sh|bash|rb|js|ts))(?:`)?",
    re.IGNORECASE,
)

# Broader pattern: any backtick-quoted or bare script path
_SCRIPT_PATH_RE = re.compile(
    r"(?:`)?(?:scripts/)?([a-zA-Z0-9_\-]+\.(?:py|sh|bash|rb|js|ts))(?:`)?",
    re.IGNORECASE,
)

_CONDITION_RE = re.compile(
    r"\b(if|when|unless|only\s+if|provided\s+that)\b",
    re.IGNORECASE,
)

_ACTION_VERBS = {
    "run", "execute", "invoke", "call", "scan", "read", "write",
    "send", "post", "fetch", "download", "upload", "create", "delete",
    "check", "validate", "verify", "analyze", "format", "build",
    "deploy", "install", "configure", "generate", "collect", "report",
    "display", "output", "print", "parse", "extract", "transform",
}

_DATA_FLOW_RE = re.compile(
    r"(?:result|output|data|response|value|list|report|summary)"
    r"\s+(?:from|of)\s+(?:step\s+)?(\d+|S\d+|the\s+previous\s+step)",
    re.IGNORECASE,
)


def extract_nl_program_heuristic(skill_md_content: str) -> NLProgram:
    """
    Extract NL Program from SKILL.md using regex heuristics.
    No LLM call needed — used as fallback or for cost-free scanning.
    """
    # Parse frontmatter
    purpose = ""
    body = skill_md_content
    if skill_md_content.startswith("---"):
        parts = skill_md_content.split("---", 2)
        if len(parts) >= 3:
            # Extract purpose from frontmatter description
            for line in parts[1].split("\n"):
                if line.strip().startswith("description:"):
                    purpose = line.split(":", 1)[1].strip().strip('"').strip("'")
                    break
            body = parts[2]

    # Extract steps from numbered lists first
    steps: list[NLStep] = []
    numbered = re.findall(r"^\s*(\d+)[.)]\s+(.+?)(?=\n\s*\d+[.)]|\n\n|\Z)", body, re.MULTILINE | re.DOTALL)

    if numbered:
        for i, (num, text) in enumerate(numbered):
            text = text.strip().split("\n")[0]  # first line only
            step_id = f"S{i + 1}"

            # Detect script references (try verb-prefixed first, then backtick paths)
            script_match = _SCRIPT_REF_RE.search(text)
            target_script = script_match.group(1) if script_match else ""
            if not target_script:
                # Try backtick-quoted script path: `scripts/foo.py`
                backtick_match = re.search(
                    r"`((?:scripts/)?[a-zA-Z0-9_\-]+\.(?:py|sh|bash|rb|js|ts))`",
                    text,
                )
                if backtick_match:
                    target_script = backtick_match.group(1)

            # Detect conditions
            condition = ""
            branch_true = ""
            branch_false = ""
            if _CONDITION_RE.search(text):
                condition = text
                if i + 1 < len(numbered):
                    branch_true = f"S{i + 2}"
                if i + 2 < len(numbered):
                    branch_false = f"S{i + 3}"

            # Detect data flow references
            input_refs: list[str] = []
            df_match = _DATA_FLOW_RE.search(text)
            if df_match:
                ref = df_match.group(1)
                if ref.startswith("S"):
                    input_refs.append(f"{ref}.output")
                elif ref.isdigit():
                    input_refs.append(f"S{ref}.output")
                else:
                    # "the previous step"
                    if i > 0:
                        input_refs.append(f"S{i}.output")

            # Heuristic data flow: phrases like "pass X to", "with the results", "collected data"
            if not input_refs and i > 0:
                data_flow_phrases = [
                    r"pass\s+.+\s+to",
                    r"with\s+the\s+.*(result|data|output|analysis|report|list|info)",
                    r"(collected|gathered|generated|analyzed)\s+(data|result|output|info)",
                    r"pipe\s+.+\s+to",
                    r"send\s+.+\s+to",
                    r"using\s+the\s+.*(result|data|output)",
                ]
                for pattern in data_flow_phrases:
                    if re.search(pattern, text, re.IGNORECASE):
                        input_refs.append(f"S{i}.output")
                        break

            # Infer action
            action = "other"
            text_lower = text.lower()
            for verb in _ACTION_VERBS:
                if verb in text_lower.split()[:3]:
                    action = verb
                    break

            # Infer scope
            scope = ""
            if "project" in text_lower:
                scope = "project directory"
            elif "file" in text_lower:
                scope = "files"

            steps.append(NLStep(
                step_id=step_id,
                action=action,
                description=text[:200],
                target_script=target_script,
                input_refs=input_refs,
                output_name=f"step_{i+1}_result" if (
                    action in ("run", "scan", "collect", "read", "extract", "analyze", "generate")
                    or target_script  # any step with a script likely produces output
                ) else "",
                declared_scope=scope,
                condition=condition,
                branch_true=branch_true,
                branch_false=branch_false,
            ))

    if not steps:
        # Fallback: extract from code blocks and references
        code_blocks = re.findall(r"```(?:bash|shell|sh)?\n(.+?)```", body, re.DOTALL)
        script_refs = _SCRIPT_REF_RE.findall(body)

        idx = 1
        for ref in script_refs:
            steps.append(NLStep(
                step_id=f"S{idx}",
                action="run",
                description=f"Run {ref}",
                target_script=ref,
                output_name=f"step_{idx}_result",
            ))
            idx += 1

        if not steps:
            # Last resort: create a single step for the whole skill
            steps.append(NLStep(
                step_id="S1",
                action="execute",
                description=purpose or "Execute skill",
                declared_scope="unknown",
            ))

    # Build data flow edges for sequential steps without explicit refs
    for i, step in enumerate(steps):
        if i > 0 and not step.input_refs and steps[i - 1].output_name:
            # Implicit: each step may use previous step's output
            pass  # conservative — don't add implicit edges

    return NLProgram(
        declared_purpose=purpose,
        steps=steps,
        entry_step=steps[0].step_id if steps else "S1",
    )


# =============================================================================
# Combined extraction with fallback
# =============================================================================

def extract_nl_program(
    skill_dir: str,
    llm_call: callable | None = None,
) -> NLProgram:
    """
    Extract NL Program from SKILL.md in skill_dir.

    Uses LLM if llm_call is provided, falls back to heuristic otherwise.
    """
    skill_md_path = Path(skill_dir) / "SKILL.md"

    if not skill_md_path.exists():
        # Try case variations
        for name in ["skill.md", "Skill.md", "SKILL.MD"]:
            alt = Path(skill_dir) / name
            if alt.exists():
                skill_md_path = alt
                break

    if not skill_md_path.exists():
        return NLProgram(
            declared_purpose="<no SKILL.md found>",
            steps=[],
        )

    content = skill_md_path.read_text(encoding="utf-8", errors="replace")

    # Extract skill name from frontmatter
    skill_name = ""
    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            for line in parts[1].split("\n"):
                if line.strip().startswith("name:"):
                    skill_name = line.split(":", 1)[1].strip().strip('"').strip("'")
                    break

    if llm_call is not None:
        try:
            program = extract_nl_program_llm(content, llm_call)
            program.skill_name = skill_name
            # Validate: ensure at least one step was extracted
            if program.steps:
                return program
        except Exception:
            pass  # fall through to heuristic

    program = extract_nl_program_heuristic(content)
    program.skill_name = skill_name
    return program
