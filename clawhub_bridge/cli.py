"""CLI entry point for clawhub-bridge."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .approval_cli import cmd_approve, cmd_check
from .delta import compare
from .delta_report import format_delta
from .fetcher import fetch_skill
from .import_cli import cmd_import
from .policy import apply_policy
from .policy_cli import cmd_policy
from .policy_loader import load_policy
from .report import format_batch_summary, format_policy_verdict, format_report
from .scanner import scan_content

VERSION = "5.0.0"


def _scan_single(source: str) -> dict:
    token = os.environ.get("CLAUDE_GITHUB_TOKEN")
    skill = fetch_skill(source, token=token)
    result = scan_content(skill.content, source=source)
    return result.to_dict()


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan one or more files/directories for security issues."""
    sources = _expand_sources(args.source)
    if not sources:
        print("No scannable files found.", file=sys.stderr)
        return 1

    policy = load_policy(args.policy) if args.policy else None
    context_name = args.context if hasattr(args, "context") else None

    results = [_scan_single(src) for src in sources]

    if policy:
        for data in results:
            pv = apply_policy(data["findings"], policy, context_name)
            data["policy_verdict"] = pv.to_dict()
            data["verdict"] = pv.verdict

    if args.json:
        output = results[0] if len(results) == 1 else results
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        for data in results:
            print(format_report(data))
            if "policy_verdict" in data:
                print(format_policy_verdict(data["policy_verdict"]))
        if len(results) > 1:
            print(format_batch_summary(results))

    return 1 if any(r["verdict"] == "FAIL" for r in results) else 0


def cmd_delta(args: argparse.Namespace) -> int:
    """Compare two versions of a skill and report delta risk."""
    before_data = fetch_skill(args.before)
    after_data = fetch_skill(args.after)
    before_result = scan_content(before_data.content, source=args.before)
    after_result = scan_content(after_data.content, source=args.after)
    delta = compare(before_result, after_result)

    if args.json:
        print(json.dumps(delta.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(format_delta(delta.to_dict()))

    return 1 if delta.requires_review else 0


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
    scan_p.add_argument(
        "--policy", help="Path to policy JSON file"
    )
    scan_p.add_argument(
        "--context", help="Policy context (e.g. development, staging, production)"
    )

    imp_p = sub.add_parser("import", help="Scan + convert + import a skill")
    imp_p.add_argument("source", help="File or GitHub URL")
    imp_p.add_argument("dest", nargs="?", default=".", help="Destination dir")

    delta_p = sub.add_parser(
        "delta", help="Compare two skill versions for delta risk"
    )
    delta_p.add_argument("before", help="Before file (old version)")
    delta_p.add_argument("after", help="After file (new version)")
    delta_p.add_argument(
        "--json", action="store_true", help="Output as JSON"
    )

    approve_p = sub.add_parser(
        "approve", help="Create an approval envelope for a skill"
    )
    approve_p.add_argument("source", help="File to approve")
    approve_p.add_argument(
        "-o", "--output", help="Output path (default: <name>.approval.json)"
    )

    check_p = sub.add_parser(
        "check", help="Check a skill against an approval envelope"
    )
    check_p.add_argument("envelope", help="Approval envelope JSON file")
    check_p.add_argument("source", help="New version of the skill to check")
    check_p.add_argument(
        "--json", action="store_true", help="Output as JSON"
    )

    policy_p = sub.add_parser(
        "policy", help="Policy management (init, validate)"
    )
    policy_sub = policy_p.add_subparsers(dest="policy_command")

    policy_sub.add_parser(
        "init", help="Generate a default policy file"
    )

    validate_p = policy_sub.add_parser(
        "validate", help="Validate a policy file"
    )
    validate_p.add_argument("path", help="Path to policy JSON file")

    return parser


_COMMANDS = {
    "scan": cmd_scan,
    "import": cmd_import,
    "delta": cmd_delta,
    "approve": cmd_approve,
    "check": cmd_check,
    "policy": cmd_policy,
}


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    handler = _COMMANDS.get(args.command)
    if handler:
        sys.exit(handler(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
