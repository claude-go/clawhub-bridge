"""Terminal report formatting with ANSI colors."""

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
_BLUE = "\033[34m" if _USE_COLOR else ""
_CYAN = "\033[36m" if _USE_COLOR else ""

_VERDICT_STYLE = {
    "PASS": f"{_GREEN}{_BOLD}",
    "REVIEW": f"{_YELLOW}{_BOLD}",
    "FAIL": f"{_RED}{_BOLD}",
}

_SEV_STYLE = {
    "critical": f"{_RED}{_BOLD}",
    "high": _RED,
    "medium": _YELLOW,
    "low": _BLUE,
}

_VERDICT_ICON = {"PASS": "PASS", "REVIEW": "WARN", "FAIL": "FAIL"}


def format_report(result: dict) -> str:
    """Format a scan result dict into a human-readable terminal report."""
    lines: list[str] = []
    verdict = result["verdict"]
    style = _VERDICT_STYLE.get(verdict, "")
    icon = _VERDICT_ICON.get(verdict, "?")

    lines.append("")
    lines.append(
        f"  {style}[{icon}]{_RESET} {style}{verdict}{_RESET}"
        f" {_DIM}—{_RESET} {result['summary']}"
    )
    lines.append(f"  {_DIM}Source:{_RESET} {result['source']}")

    caps = result.get("capabilities", {}).get("profile", {})
    if caps:
        lines.append("")
        lines.append(f"  {_CYAN}{_BOLD}Capabilities required:{_RESET}")
        for resource, level in sorted(caps.items()):
            level_style = _RED if level == "ADMIN" else (
                _YELLOW if level == "WRITE" else _GREEN
            )
            lines.append(
                f"    {resource:<15} {level_style}{level}{_RESET}"
            )

    findings = result.get("findings", [])
    if findings:
        by_sev = result.get("by_severity", {})
        sev_parts = []
        for sev in ("critical", "high", "medium", "low"):
            count = by_sev.get(sev, 0)
            if count:
                s = _SEV_STYLE.get(sev, "")
                sev_parts.append(f"{s}{count} {sev.upper()}{_RESET}")
        lines.append("")
        lines.append(
            f"  {_BOLD}Findings ({len(findings)}):{_RESET}"
            f" {', '.join(sev_parts)}"
        )
        lines.append("")
        for f in findings:
            sev = f["severity"]
            s = _SEV_STYLE.get(sev, "")
            lines.append(
                f"    {s}[{sev.upper():<8}]{_RESET}"
                f" L{f['line']:<4} {f['description']}"
            )
            lines.append(
                f"    {_DIM}           -> {f['matched']}{_RESET}"
            )
    else:
        lines.append("")
        lines.append(f"  {_GREEN}No security issues detected.{_RESET}")

    lines.append("")
    return "\n".join(lines)


def format_batch_summary(results: list[dict]) -> str:
    """Format a summary line for batch scans."""
    total = len(results)
    passed = sum(1 for r in results if r["verdict"] == "PASS")
    review = sum(1 for r in results if r["verdict"] == "REVIEW")
    failed = sum(1 for r in results if r["verdict"] == "FAIL")

    parts = [f"{_BOLD}{total} files scanned:{_RESET}"]
    if passed:
        parts.append(f"{_GREEN}{passed} PASS{_RESET}")
    if review:
        parts.append(f"{_YELLOW}{review} REVIEW{_RESET}")
    if failed:
        parts.append(f"{_RED}{failed} FAIL{_RESET}")

    return f"\n  {' | '.join(parts)}\n"
