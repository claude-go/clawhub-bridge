"""CLI command for MCP server scanning."""

from __future__ import annotations

import argparse
import json
import sys

from .mcp import analyze_mcp_server, parse_mcp_config

# ANSI colors for terminal output.
_RED = "\033[91m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_CYAN = "\033[96m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

_VERDICT_COLORS = {
    "FAIL": _RED,
    "REVIEW": _YELLOW,
    "PASS": _GREEN,
}


def cmd_mcp_scan(args: argparse.Namespace) -> int:
    """Scan MCP server config for security issues."""
    try:
        servers = parse_mcp_config(args.source)
    except (json.JSONDecodeError, FileNotFoundError) as exc:
        print(
            f"Error parsing config: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 1

    if not servers:
        print("No MCP servers found in config.", file=sys.stderr)
        return 1

    results = [analyze_mcp_server(srv) for srv in servers]

    if args.json:
        output = [r.to_dict() for r in results]
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        _print_results(results)

    return 1 if any(r.verdict == "FAIL" for r in results) else 0


def _print_results(results: list) -> None:
    """Print MCP scan results to terminal."""
    total = len(results)
    failed = sum(1 for r in results if r.verdict == "FAIL")
    review = sum(1 for r in results if r.verdict == "REVIEW")

    print(f"\n{_BOLD}MCP Server Security Scan{_RESET}")
    print(f"Servers scanned: {total}\n")

    for r in results:
        color = _VERDICT_COLORS.get(r.verdict, _RESET)
        pkg = r.config.package_name or r.config.url[:40]
        print(
            f"  {color}[{r.verdict}]{_RESET} "
            f"{_BOLD}{r.server_name}{_RESET} "
            f"({pkg})"
        )
        for f in r.findings:
            sev_color = (
                _RED if f.severity.value == "critical"
                else _YELLOW
            )
            print(
                f"    {sev_color}[{f.severity.value.upper()}]"
                f"{_RESET} {f.title}"
            )

    print()
    if failed:
        print(f"{_RED}{_BOLD}{failed} server(s) BLOCKED{_RESET}")
    if review:
        print(
            f"{_YELLOW}{review} server(s) need review{_RESET}"
        )
    if not failed and not review:
        print(f"{_GREEN}All servers passed{_RESET}")
    print()
