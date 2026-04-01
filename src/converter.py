"""Convert skills from various formats to CL-GO format."""

from __future__ import annotations

import re
from dataclasses import dataclass

_YAML_FRONT_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


@dataclass
class ConvertedSkill:
    name: str
    content: str
    original_format: str
    changes_made: list[str]


def _extract_frontmatter(content: str) -> tuple[str, str]:
    match = _YAML_FRONT_RE.match(content)
    if match:
        return match.group(1), content[match.end():]
    return "", content


def _normalize_frontmatter(yaml_block: str, name: str) -> str:
    lines = yaml_block.strip().splitlines()
    fields: dict[str, str] = {}
    for line in lines:
        if ":" in line:
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()

    required = {
        "name": fields.get("name", name),
        "description": fields.get("description", fields.get("summary", "")),
    }

    result_lines = []
    for key, val in required.items():
        result_lines.append(f"{key}: {val}")

    for key, val in fields.items():
        if key not in required and key not in ("summary",):
            result_lines.append(f"{key}: {val}")

    return "\n".join(result_lines)


def convert_to_clgo(
    content: str, name: str, source_format: str = "auto"
) -> ConvertedSkill:
    """Convert a skill to CL-GO Claude Code format."""
    changes: list[str] = []
    original_fm, body = _extract_frontmatter(content)

    detected = "openclaw" if "SKILL.md" in content or "openclaw" in content.lower() else "claude-code"
    if source_format == "auto":
        source_format = detected

    if original_fm:
        new_fm = _normalize_frontmatter(original_fm, name)
        changes.append("Frontmatter normalise au format CL-GO")
    else:
        new_fm = f"name: {name}\ndescription: Skill importee depuis {source_format}"
        changes.append("Frontmatter genere (absent dans l'original)")

    body = body.strip()

    if not body:
        changes.append("ATTENTION : body vide")

    final = f"---\n{new_fm}\n---\n\n{body}\n"

    return ConvertedSkill(
        name=name,
        content=final,
        original_format=source_format,
        changes_made=changes,
    )
