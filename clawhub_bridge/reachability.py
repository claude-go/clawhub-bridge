"""Irreversible action reachability analyzer.

Performs a second pass over scan findings to determine whether
irreversible actions are guarded (require human confirmation)
or unguarded (execute automatically). Unguarded irreversible
actions are escalated in severity.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .patterns.types import Severity
from .scanner import Finding, ScanResult

GUARD_WINDOW = 5

GUARD_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\b(ask|confirm|prompt|approve|verify)\b.*\b(user|human|before|first)\b",
        r"\b(user|human)\b.*\b(confirm|approv|consent|authoriz)\b",
        r"\b(before|prior\s+to)\b.*\b(proceed|execut|runn|send|deploy|publish|delet)\w*\b",
        r"\bwait\s+(for\s+)?(confirm|approv|input|response)\b",
        r"\brequires?\s+(confirm|approv|consent|authoriz)\b",
        r"\b(y/n|yes/no|\[y\]|\[n\])\b",
        r"\binput\s*\(\s*[\"'].*\b(confirm|sure|proceed)\b",
        r"\b(are\s+you\s+sure|do\s+you\s+want)\b",
    ]
]

IRREVERSIBLE_PATTERN_NAMES = {
    "payment_api_call",
    "crypto_transfer",
    "subscription_create",
    "send_email",
    "social_media_post",
    "github_issue_pr_create",
    "messaging_send",
    "package_publish",
    "container_push",
    "deploy_production",
    "github_release_create",
    "database_drop",
    "database_truncate",
    "delete_without_where",
    "bucket_delete",
    "account_deletion",
    "credential_revoke",
    "password_change_external",
    "terminate_instance",
    "dns_record_change",
    "close_merge_pr",
}


@dataclass
class ReachabilityResult:
    finding: Finding
    guarded: bool
    guard_evidence: str


def _has_guard(lines: list[str], action_line: int) -> tuple[bool, str]:
    """Check if lines near the action contain a guard pattern."""
    start = max(0, action_line - GUARD_WINDOW)
    end = min(len(lines), action_line + GUARD_WINDOW)

    for idx in range(start, end):
        for pattern in GUARD_PATTERNS:
            match = pattern.search(lines[idx])
            if match:
                return True, f"L{idx + 1}: {match.group()[:60]}"

    return False, ""


def analyze_reachability(
    result: ScanResult, content: str
) -> list[ReachabilityResult]:
    """Analyze irreversible findings for guard presence."""
    lines = content.splitlines()
    reachability: list[ReachabilityResult] = []

    for finding in result.findings:
        if finding.pattern_name not in IRREVERSIBLE_PATTERN_NAMES:
            continue

        guarded, evidence = _has_guard(lines, finding.line_number - 1)
        reachability.append(
            ReachabilityResult(
                finding=finding,
                guarded=guarded,
                guard_evidence=evidence,
            )
        )

    return reachability


def escalate_unguarded(result: ScanResult, content: str) -> ScanResult:
    """Escalate severity of unguarded irreversible actions.

    MEDIUM -> HIGH, HIGH -> CRITICAL for unguarded actions.
    Adds '[UNGUARDED]' prefix to description.
    """
    reachability = analyze_reachability(result, content)

    for reach in reachability:
        if reach.guarded:
            continue

        finding = reach.finding
        if finding.severity == Severity.MEDIUM:
            finding.severity = Severity.HIGH
        elif finding.severity == Severity.HIGH:
            finding.severity = Severity.CRITICAL

        if not finding.description.startswith("[UNGUARDED]"):
            finding.description = (
                f"[UNGUARDED] {finding.description}"
            )

    _recalculate_verdict(result)
    return result


def _recalculate_verdict(result: ScanResult) -> None:
    """Recalculate verdict after severity changes."""
    result.verdict = "PASS"
    for finding in result.findings:
        if finding.severity == Severity.CRITICAL:
            result.verdict = "FAIL"
            return
        if finding.severity == Severity.HIGH:
            result.verdict = "REVIEW"
        elif result.verdict == "PASS":
            result.verdict = "REVIEW"
