"""CLI command for skill import."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .converter import convert_to_clgo
from .fetcher import fetch_skill
from .report import format_report
from .scanner import scan_content


def cmd_import(args: argparse.Namespace) -> int:
    """Scan, convert, and import a skill."""
    token = os.environ.get("CLAUDE_GITHUB_TOKEN")
    skill = fetch_skill(args.source, token=token)

    result = scan_content(skill.content, source=args.source)
    print(format_report(result.to_dict()))

    if result.verdict == "FAIL":
        print("Import BLOCKED — dangerous skill.", file=sys.stderr)
        return 1

    if result.verdict == "REVIEW":
        print("Warnings detected. Import pending review.",
              file=sys.stderr)
        report_path = Path(args.dest) / f".review-{skill.name}.json"
        report_path.write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"Report saved: {report_path}")
        return 2

    converted = convert_to_clgo(skill.content, skill.name)
    dest = Path(args.dest) / f"{converted.name}.md"
    dest.write_text(converted.content, encoding="utf-8")
    print(f"Skill imported: {dest}")
    for change in converted.changes_made:
        print(f"  - {change}")
    return 0
