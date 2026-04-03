"""Approval validity tracking for skill versions.

Creates approval envelopes that capture the security state at the
time of approval. When a new version is scanned, the envelope
determines whether the prior approval still holds.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .capabilities.types import AccessLevel, ResourceType
from .patterns import Severity
from .scanner import ScanResult


@dataclass
class ApprovalEnvelope:
    """Snapshot of the security state at the time a skill was approved."""

    approved_source: str
    approved_at: str
    max_accepted_severity: str
    capability_ceiling: dict[str, str]
    accepted_finding_names: list[str]
    total_findings: int
    verdict_at_approval: str

    def to_dict(self) -> dict:
        return {
            "approved_source": self.approved_source,
            "approved_at": self.approved_at,
            "max_accepted_severity": self.max_accepted_severity,
            "capability_ceiling": self.capability_ceiling,
            "accepted_finding_names": self.accepted_finding_names,
            "total_findings": self.total_findings,
            "verdict_at_approval": self.verdict_at_approval,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict) -> ApprovalEnvelope:
        return cls(
            approved_source=data["approved_source"],
            approved_at=data["approved_at"],
            max_accepted_severity=data["max_accepted_severity"],
            capability_ceiling=data["capability_ceiling"],
            accepted_finding_names=data["accepted_finding_names"],
            total_findings=data["total_findings"],
            verdict_at_approval=data["verdict_at_approval"],
        )

    @classmethod
    def from_json(cls, raw: str) -> ApprovalEnvelope:
        return cls.from_dict(json.loads(raw))


@dataclass
class ApprovalVerdict:
    """Result of checking a new scan against an approval envelope."""

    status: str  # "valid", "invalidated"
    reasons: list[str] = field(default_factory=list)
    envelope: ApprovalEnvelope | None = None

    def to_dict(self) -> dict:
        result: dict = {
            "status": self.status,
            "reasons": self.reasons,
        }
        if self.envelope:
            result["envelope"] = self.envelope.to_dict()
        return result


_SEVERITY_RANK = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


def create_envelope(scan_result: ScanResult) -> ApprovalEnvelope:
    """Capture the current scan state as an approval envelope."""
    now = datetime.now(timezone.utc).isoformat()
    ceiling = scan_result.capabilities.summary()

    finding_names = sorted({f.pattern_name for f in scan_result.findings})
    max_sev = "none"
    for f in scan_result.findings:
        sev = f.severity.value
        if _SEVERITY_RANK.get(sev, -1) > _SEVERITY_RANK.get(max_sev, -1):
            max_sev = sev

    return ApprovalEnvelope(
        approved_source=scan_result.source,
        approved_at=now,
        max_accepted_severity=max_sev,
        capability_ceiling=ceiling,
        accepted_finding_names=finding_names,
        total_findings=len(scan_result.findings),
        verdict_at_approval=scan_result.verdict,
    )


def check_approval(
    envelope: ApprovalEnvelope, new_result: ScanResult
) -> ApprovalVerdict:
    """Check whether a new scan stays within the approval envelope."""
    reasons: list[str] = []

    _check_new_critical_findings(envelope, new_result, reasons)
    _check_severity_escalation(envelope, new_result, reasons)
    _check_capability_escalation(envelope, new_result, reasons)

    status = "invalidated" if reasons else "valid"
    return ApprovalVerdict(status=status, reasons=reasons, envelope=envelope)


def _check_new_critical_findings(
    envelope: ApprovalEnvelope,
    new_result: ScanResult,
    reasons: list[str],
) -> None:
    """Flag any CRITICAL finding not present in the original approval."""
    accepted = set(envelope.accepted_finding_names)
    for f in new_result.findings:
        if f.severity == Severity.CRITICAL and f.pattern_name not in accepted:
            reasons.append(
                f"new CRITICAL finding: {f.pattern_name} (line {f.line_number})"
            )


def _check_severity_escalation(
    envelope: ApprovalEnvelope,
    new_result: ScanResult,
    reasons: list[str],
) -> None:
    """Flag if new findings exceed the max severity accepted at approval."""
    max_rank = _SEVERITY_RANK.get(envelope.max_accepted_severity, -1)
    for f in new_result.findings:
        sev_rank = _SEVERITY_RANK.get(f.severity.value, -1)
        if sev_rank > max_rank and f.pattern_name not in set(
            envelope.accepted_finding_names
        ):
            reasons.append(
                f"severity escalation: {f.pattern_name} is {f.severity.value}, "
                f"max accepted was {envelope.max_accepted_severity}"
            )


def _check_capability_escalation(
    envelope: ApprovalEnvelope,
    new_result: ScanResult,
    reasons: list[str],
) -> None:
    """Flag if any capability exceeds the ceiling from the approval."""
    ceiling = envelope.capability_ceiling
    for rt in ResourceType:
        new_level = new_result.capabilities.max_level(rt)
        approved_name = ceiling.get(rt.value)
        approved_level = (
            AccessLevel[approved_name] if approved_name else AccessLevel.NONE
        )
        if new_level > approved_level:
            reasons.append(
                f"capability escalation: {rt.value} "
                f"{approved_level.name} -> {new_level.name}"
            )
