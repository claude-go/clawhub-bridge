"""CLI entry point for clawhub-bridge."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .converter import convert_to_clgo
from .fetcher import fetch_skill
from .scanner import scan_content


def _print_report(result: dict) -> None:
    verdict = result["verdict"]
    icon = {"PASS": "+", "REVIEW": "?", "FAIL": "!"}[verdict]
    print(f"\n[{icon}] {verdict} — {result['summary']}")
    print(f"    Source : {result['source']}")

    if result["findings"]:
        print(f"    Findings : {result['total_findings']}")
        for f in result["findings"]:
            sev = f["severity"].upper()
            print(f"      [{sev}] L{f['line']} {f['description']}")
            print(f"             -> {f['matched']}")


def cmd_scan(source: str) -> int:
    """Scan a skill for security issues."""
    token = os.environ.get("CLAUDE_GITHUB_TOKEN")
    skill = fetch_skill(source, token=token)
    result = scan_content(skill.content, source=source)
    _print_report(result.to_dict())
    return 0 if result.verdict != "FAIL" else 1


def cmd_import(source: str, dest_dir: str) -> int:
    """Scan, convert, and import a skill."""
    token = os.environ.get("CLAUDE_GITHUB_TOKEN")
    skill = fetch_skill(source, token=token)

    result = scan_content(skill.content, source=source)
    _print_report(result.to_dict())

    if result.verdict == "FAIL":
        print("\nImport REFUSE — skill bloquee par le scanner.")
        return 1

    if result.verdict == "REVIEW":
        print("\nWarnings detectes. Import en attente de review.")
        report_path = Path(dest_dir) / f".review-{skill.name}.json"
        report_path.write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"Rapport sauvegarde : {report_path}")
        return 2

    converted = convert_to_clgo(skill.content, skill.name)
    dest = Path(dest_dir) / f"{converted.name}.md"
    dest.write_text(converted.content, encoding="utf-8")
    print(f"\nSkill importee : {dest}")
    for change in converted.changes_made:
        print(f"  - {change}")
    return 0


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python -m src.cli scan <source>")
        print("  python -m src.cli import <source> [dest_dir]")
        sys.exit(1)

    command = sys.argv[1]
    source = sys.argv[2]

    if command == "scan":
        sys.exit(cmd_scan(source))
    elif command == "import":
        dest = sys.argv[3] if len(sys.argv) > 3 else "."
        sys.exit(cmd_import(source, dest))
    else:
        print(f"Commande inconnue : {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
