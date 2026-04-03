"""Tests for delta risk comparison between skill versions."""

from clawhub_bridge.capabilities.types import (
    AccessLevel,
    Capability,
    CapabilityProfile,
    ResourceType,
)
from clawhub_bridge.delta import CapabilityChange, DeltaResult, compare
from clawhub_bridge.patterns import Severity
from clawhub_bridge.scanner import Finding, ScanResult


def _make_result(
    source: str = "test",
    findings: list[Finding] | None = None,
    caps: list[Capability] | None = None,
    verdict: str = "PASS",
) -> ScanResult:
    profile = CapabilityProfile()
    for c in (caps or []):
        profile.add(c)
    result = ScanResult(source=source, verdict=verdict)
    result.capabilities = profile
    for f in (findings or []):
        result.findings.append(f)
    return result


def _finding(name: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        pattern_name=name,
        severity=severity,
        description=f"Test {name}",
        line_number=1,
        matched_text=name,
        context="",
    )


def _cap(
    resource: ResourceType, level: AccessLevel, evidence: str = "test"
) -> Capability:
    return Capability(resource=resource, level=level, evidence=evidence, line_number=1)


class TestCompareFindings:
    def test_no_changes(self):
        f = _finding("exfil_webhook")
        before = _make_result(findings=[f])
        after = _make_result(findings=[f])
        delta = compare(before, after)
        assert delta.added_findings == []
        assert delta.resolved_findings == []

    def test_new_finding_detected(self):
        before = _make_result()
        after = _make_result(findings=[_finding("exfil_webhook")])
        delta = compare(before, after)
        assert len(delta.added_findings) == 1
        assert delta.added_findings[0].pattern_name == "exfil_webhook"

    def test_resolved_finding(self):
        before = _make_result(findings=[_finding("exfil_webhook")])
        after = _make_result()
        delta = compare(before, after)
        assert len(delta.resolved_findings) == 1
        assert delta.resolved_findings[0].pattern_name == "exfil_webhook"

    def test_mixed_changes(self):
        f1 = _finding("exfil_webhook")
        f2 = _finding("credential_harvest", Severity.CRITICAL)
        before = _make_result(findings=[f1])
        after = _make_result(findings=[f2])
        delta = compare(before, after)
        assert len(delta.added_findings) == 1
        assert len(delta.resolved_findings) == 1


class TestCompareCapabilities:
    def test_escalation_detected(self):
        before = _make_result(
            caps=[_cap(ResourceType.FILESYSTEM, AccessLevel.READ)]
        )
        after = _make_result(
            caps=[_cap(ResourceType.FILESYSTEM, AccessLevel.WRITE)]
        )
        delta = compare(before, after)
        changes = delta.capability_changes
        fs = [c for c in changes if c.resource == ResourceType.FILESYSTEM]
        assert len(fs) == 1
        assert fs[0].direction == "escalated"
        assert fs[0].before_level == AccessLevel.READ
        assert fs[0].after_level == AccessLevel.WRITE

    def test_reduction_detected(self):
        before = _make_result(
            caps=[_cap(ResourceType.NETWORK, AccessLevel.ADMIN)]
        )
        after = _make_result(
            caps=[_cap(ResourceType.NETWORK, AccessLevel.READ)]
        )
        delta = compare(before, after)
        changes = delta.capability_changes
        net = [c for c in changes if c.resource == ResourceType.NETWORK]
        assert len(net) == 1
        assert net[0].direction == "reduced"

    def test_new_resource_is_escalation(self):
        before = _make_result()
        after = _make_result(
            caps=[_cap(ResourceType.SHELL, AccessLevel.ADMIN)]
        )
        delta = compare(before, after)
        shell = [
            c
            for c in delta.capability_changes
            if c.resource == ResourceType.SHELL
        ]
        assert len(shell) == 1
        assert shell[0].direction == "escalated"
        assert shell[0].before_level == AccessLevel.NONE

    def test_removed_resource_is_reduction(self):
        before = _make_result(
            caps=[_cap(ResourceType.DATABASE, AccessLevel.WRITE)]
        )
        after = _make_result()
        delta = compare(before, after)
        db = [
            c
            for c in delta.capability_changes
            if c.resource == ResourceType.DATABASE
        ]
        assert len(db) == 1
        assert db[0].direction == "reduced"
        assert db[0].after_level == AccessLevel.NONE


class TestDeltaVerdict:
    def test_escalation_requires_review(self):
        before = _make_result(
            caps=[_cap(ResourceType.FILESYSTEM, AccessLevel.READ)]
        )
        after = _make_result(
            caps=[_cap(ResourceType.FILESYSTEM, AccessLevel.ADMIN)]
        )
        delta = compare(before, after)
        assert delta.requires_review is True
        assert delta.net_authority_change == "escalated"

    def test_reduction_no_review(self):
        before = _make_result(
            caps=[_cap(ResourceType.NETWORK, AccessLevel.ADMIN)]
        )
        after = _make_result(
            caps=[_cap(ResourceType.NETWORK, AccessLevel.READ)]
        )
        delta = compare(before, after)
        assert delta.requires_review is False
        assert delta.net_authority_change == "reduced"

    def test_no_change_no_review(self):
        cap = _cap(ResourceType.FILESYSTEM, AccessLevel.READ)
        before = _make_result(caps=[cap])
        after = _make_result(caps=[cap])
        delta = compare(before, after)
        assert delta.requires_review is False
        assert delta.net_authority_change == "unchanged"

    def test_new_critical_finding_requires_review(self):
        before = _make_result()
        after = _make_result(
            findings=[_finding("shell_injection", Severity.CRITICAL)]
        )
        delta = compare(before, after)
        assert delta.requires_review is True


class TestDeltaSerialization:
    def test_to_dict_structure(self):
        before = _make_result(source="v1.md")
        after = _make_result(
            source="v2.md",
            findings=[_finding("exfil_webhook")],
            caps=[_cap(ResourceType.NETWORK, AccessLevel.WRITE)],
        )
        delta = compare(before, after)
        d = delta.to_dict()
        assert d["before_source"] == "v1.md"
        assert d["after_source"] == "v2.md"
        assert "added_findings" in d
        assert "resolved_findings" in d
        assert "capability_changes" in d
        assert "net_authority_change" in d
        assert "requires_review" in d
