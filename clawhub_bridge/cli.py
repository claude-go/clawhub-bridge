"""CLI entry point for clawhub-bridge."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .converter import convert_to_clgo
from .fetcher import fetch_skill
from .report import format_batch_summary, format_report
from .scanner import scan_content

VERSION = "4.1.0"


def _scan_single(source: str, as_json: bool) -> dict:
    token = os.environ.get("CLAUDE_GITHUB_TOKEN")
    skill = fetch_skill(source, token=token)
    result = scan_content(skill.content, source=source)
    data = result.to_dict()
    if as_json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print(format_report(data))
    return data


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan one or more files/directories for security issues."""
    sources = _expand_sources(args.source)
    if not sources:
        print("No scannable files found.", file=sys.stderr)
        return 1

    results = []
    for src in sources:
        data = _scan_single(src, args.json)
        results.append(data)

    if len(results) > 1 and not args.json:
        print(format_batch_summary(results))

    return 1 if any(r["verdict"] == "FAIL" for r in results) else 0


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


def _expand_sources(source: str) -> list[str]:
    """Expand a source path to a list of scannable files."""
    if source.startswith("https://"):
        return [source]
    path = Path(source)
    if path.is_file():
        return [str(path)]
    if path.is_dir():
        files = sorted(path.rglob("*.md"))
        return [str(f) for f in files if f.stat().st_size < 500_000]
    return []


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clawhub",
        description="Security scanner for AI agent skills (MCP, LangChain, CrewAI)",
    )
    parser.add_argument(
        "--version", action="version", version=f"clawhub-bridge {VERSION}"
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan skills for security issues")
    scan_p.add_argument("source", help="File, directory, or GitHub URL")
    scan_p.add_argument(
        "--json", action="store_true", help="Output as JSON"
    )

    imp_p = sub.add_parser("import", help="Scan + convert + import a skill")
    imp_p.add_argument("source", help="File or GitHub URL")
    imp_p.add_argument("dest", nargs="?", default=".", help="Destination dir")

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "import":
        sys.exit(cmd_import(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
