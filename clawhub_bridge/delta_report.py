"""Terminal formatting for delta risk reports."""

from __future__ import annotations

import sys


def _supports_color() -> bool:
    if not hasattr(sys.stdout, "isatty"):
        return False
    return sys.stdout.isatty()


_USE_COLOR = _supports_color()

_RESET = "\033[0m" if _USE_COLOR else ""
_BOLD = "\033[1m" if _USE_COLOR else ""
_DIM = "\033[2m" if _USE_COLOR else ""
_RED = "\033[31m" if _USE_COLOR else ""
_GREEN = "\033[32m" if _USE_COLOR else ""
_YELLOW = "\033[33m" if _USE_COLOR else ""
_CYAN = "\033[36m" if _USE_COLOR else ""

_DIR_STYLE = {
    "escalated": f"{_RED}{_BOLD}",
    "reduced": f"{_GREEN}{_BOLD}",
    "unchanged": _DIM,
    "mixed": f"{_YELLOW}{_BOLD}",
}

_DIR_ICON = {
    "escalated": "ESCALATED",
    "reduced": "REDUCED",
    "unchanged": "UNCHANGED",
    "mixed": "MIXED",
}


def format_delta(data: dict) -> str:
    """Format a DeltaResult dict into a human-readable terminal report."""
    lines: list[str] = []
    net = data["net_authority_change"]
    review = data["requires_review"]
    style = _DIR_STYLE.get(net, "")
    icon = _DIR_ICON.get(net, "?")

    lines.append("")
    review_tag = f" {_RED}[RE-REVIEW REQUIRED]{_RESET}" if review else ""
    lines.append(f"  {style}[{icon}]{_RESET} Net authority: {style}{net}{_RESET}{review_tag}")
    lines.append(
        f"  {_DIM}Before:{_RESET} {data['before_source']}"
        f"  {_DIM}After:{_RESET} {data['after_source']}"
    )

    cap_changes = data.get("capability_changes", [])
    if cap_changes:
        lines.append("")
        lines.append(f"  {_CYAN}{_BOLD}Capability changes:{_RESET}")
        for c in cap_changes:
            d = c["direction"]
            ds = _DIR_STYLE.get(d, "")
            arrow = "^" if d == "escalated" else "v"
            lines.append(
                f"    {c['resource']:<15} {c['before']} -> {ds}{c['after']}{_RESET} {ds}({arrow} {d}){_RESET}"
            )

    added = data.get("added_findings", [])
    if added:
        lines.append("")
        lines.append(f"  {_RED}{_BOLD}Added risks ({len(added)}):{_RESET}")
        for f in added:
            sev = f["severity"]
            lines.append(f"    {_RED}[+{sev.upper()}]{_RESET} L{f.get('line','?'):<4} {f['name']}")

    resolved = data.get("resolved_findings", [])
    if resolved:
        lines.append("")
        lines.append(f"  {_GREEN}{_BOLD}Resolved ({len(resolved)}):{_RESET}")
        for f in resolved:
            lines.append(f"    {_GREEN}[-]{_RESET} {f['name']} ({f['severity']})")

    if not cap_changes and not added and not resolved:
        lines.append("")
        lines.append(f"  {_GREEN}No changes detected between versions.{_RESET}")

    lines.append("")
    return "\n".join(lines)
