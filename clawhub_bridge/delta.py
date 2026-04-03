"""Delta risk comparison between skill versions.

Compares two ScanResults and identifies what changed:
capability escalations, new findings, resolved findings,
and net authority movement.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .capabilities.types import AccessLevel, ResourceType
from .patterns import Severity
from .scanner import Finding, ScanResult


@dataclass
class CapabilityChange:
    """A change in access level for a single resource type."""

    resource: ResourceType
    before_level: AccessLevel
    after_level: AccessLevel
    direction: str  # "escalated", "reduced", "unchanged"

    def to_dict(self) -> dict:
        return {
            "resource": self.resource.value,
            "before": self.before_level.name,
            "after": self.after_level.name,
            "direction": self.direction,
        }


@dataclass
class DeltaResult:
    """Result of comparing two skill versions."""

    before_source: str
    after_source: str
    added_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)
    capability_changes: list[CapabilityChange] = field(default_factory=list)
    net_authority_change: str = "unchanged"
    requires_review: bool = False

    def to_dict(self) -> dict:
        return {
            "before_source": self.before_source,
            "after_source": self.after_source,
            "added_findings": [
                {
                    "name": f.pattern_name,
                    "severity": f.severity.value,
                    "line": f.line_number,
                    "matched": f.matched_text,
                }
                for f in self.added_findings
            ],
            "resolved_findings": [
                {
                    "name": f.pattern_name,
                    "severity": f.severity.value,
                }
                for f in self.resolved_findings
            ],
            "capability_changes": [c.to_dict() for c in self.capability_changes],
            "net_authority_change": self.net_authority_change,
            "requires_review": self.requires_review,
        }


def _diff_findings(
    before: list[Finding], after: list[Finding]
) -> tuple[list[Finding], list[Finding]]:
    """Return (added, resolved) findings based on pattern names."""
    before_counts: Counter[str] = Counter(f.pattern_name for f in before)
    after_counts: Counter[str] = Counter(f.pattern_name for f in after)

    added_names = after_counts - before_counts
    resolved_names = before_counts - after_counts

    after_by_name: dict[str, list[Finding]] = {}
    for f in after:
        after_by_name.setdefault(f.pattern_name, []).append(f)
    before_by_name: dict[str, list[Finding]] = {}
    for f in before:
        before_by_name.setdefault(f.pattern_name, []).append(f)

    added = []
    for name, count in added_names.items():
        added.extend(after_by_name[name][:count])

    resolved = []
    for name, count in resolved_names.items():
        resolved.extend(before_by_name[name][:count])

    return added, resolved


def _diff_capabilities(
    before: ScanResult, after: ScanResult
) -> list[CapabilityChange]:
    """Compare capability profiles across all resource types."""
    changes = []
    for rt in ResourceType:
        b_level = before.capabilities.max_level(rt)
        a_level = after.capabilities.max_level(rt)
        if b_level == a_level:
            continue
        direction = "escalated" if a_level > b_level else "reduced"
        changes.append(CapabilityChange(
            resource=rt,
            before_level=b_level,
            after_level=a_level,
            direction=direction,
        ))
    return changes


def compare(before: ScanResult, after: ScanResult) -> DeltaResult:
    """Compare two scan results and produce delta risk analysis."""
    added, resolved = _diff_findings(before.findings, after.findings)
    cap_changes = _diff_capabilities(before, after)

    has_escalation = any(c.direction == "escalated" for c in cap_changes)
    has_reduction = any(c.direction == "reduced" for c in cap_changes)
    has_new_critical = any(
        f.severity == Severity.CRITICAL for f in added
    )

    if has_escalation and has_reduction:
        net = "mixed"
    elif has_escalation:
        net = "escalated"
    elif has_reduction:
        net = "reduced"
    else:
        net = "unchanged"

    requires_review = has_escalation or has_new_critical

    return DeltaResult(
        before_source=before.source,
        after_source=after.source,
        added_findings=added,
        resolved_findings=resolved,
        capability_changes=cap_changes,
        net_authority_change=net,
        requires_review=requires_review,
    )
