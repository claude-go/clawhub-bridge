"""Policy encoding layer — context-aware verdict evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .patterns import Severity


@dataclass
class PolicyContext:
    """Defines verdict rules for a specific deployment context."""

    block: set[Severity] = field(default_factory=set)
    review: set[Severity] = field(default_factory=set)
    max_findings: int | None = None
    blocked_categories: set[str] = field(default_factory=set)
    allowed_patterns: set[str] = field(default_factory=set)


@dataclass
class Policy:
    """A set of named deployment contexts with shared defaults."""

    contexts: dict[str, PolicyContext] = field(default_factory=dict)
    default_context: str = "production"
    version: str = "1"

    def get_context(self, name: str | None = None) -> PolicyContext:
        key = name or self.default_context
        if key not in self.contexts:
            raise ValueError(f"Unknown policy context: {key!r}")
        return self.contexts[key]


@dataclass
class PolicyVerdict:
    """Result of applying a policy to scan findings."""

    verdict: str
    context_name: str
    total_findings: int
    blocked_findings: int
    reviewed_findings: int
    allowed_findings: int
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "context": self.context_name,
            "total_findings": self.total_findings,
            "blocked": self.blocked_findings,
            "reviewed": self.reviewed_findings,
            "allowed": self.allowed_findings,
            "reasons": self.reasons,
        }


def apply_policy(
    findings: list[dict],
    policy: Policy,
    context_name: str | None = None,
) -> PolicyVerdict:
    """Evaluate findings against a policy context.

    Args:
        findings: List of finding dicts from ScanResult.to_dict()
        policy: The loaded policy
        context_name: Which context to use (defaults to policy default)

    Returns:
        PolicyVerdict with the context-aware verdict.
    """
    ctx_name = context_name or policy.default_context
    ctx = policy.get_context(ctx_name)

    blocked = 0
    reviewed = 0
    allowed = 0
    reasons: list[str] = []

    for f in findings:
        name = f.get("name", "")
        severity_str = f.get("severity", "low")

        if name in ctx.allowed_patterns:
            allowed += 1
            continue

        category = _extract_category(name)
        if category in ctx.blocked_categories:
            blocked += 1
            reasons.append(f"Category blocked: {name} ({category})")
            continue

        try:
            sev = Severity(severity_str)
        except ValueError:
            reviewed += 1
            continue

        if sev in ctx.block:
            blocked += 1
            reasons.append(f"Severity blocked: {name} ({sev.value})")
        elif sev in ctx.review:
            reviewed += 1
        else:
            allowed += 1

    total = len(findings)

    if ctx.max_findings is not None and total > ctx.max_findings:
        blocked += 1
        reasons.append(
            f"Exceeds max findings: {total} > {ctx.max_findings}"
        )

    if blocked > 0:
        verdict = "FAIL"
    elif reviewed > 0:
        verdict = "REVIEW"
    else:
        verdict = "PASS"

    return PolicyVerdict(
        verdict=verdict,
        context_name=ctx_name,
        total_findings=total,
        blocked_findings=blocked,
        reviewed_findings=reviewed,
        allowed_findings=allowed,
        reasons=reasons,
    )


def _extract_category(pattern_name: str) -> str:
    """Extract category from pattern name.

    Pattern names follow the format 'category_specific_name'.
    """
    parts = pattern_name.lower().split("_")
    if len(parts) >= 2:
        return parts[0]
    return pattern_name.lower()
