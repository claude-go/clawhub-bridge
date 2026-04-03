"""Tests for approval validity checking."""

from clawhub_bridge.approval import check_approval, create_envelope
from clawhub_bridge.capabilities.types import (
    AccessLevel,
    Capability,
    CapabilityProfile,
    ResourceType,
)
from clawhub_bridge.patterns import Severity
from clawhub_bridge.scanner import Finding, ScanResult


def _make_result(
    source: str = "test.md",
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
    return Capability(
        resource=resource, level=level, evidence=evidence, line_number=1
    )


class TestApprovalValid:
    def test_identical_version(self):
        result = _make_result(
            findings=[_finding("exfil_webhook")],
            caps=[_cap(ResourceType.NETWORK, AccessLevel.WRITE)],
        )
        env = create_envelope(result)
        verdict = check_approval(env, result)
        assert verdict.status == "valid"
        assert verdict.reasons == []

    def test_finding_resolved(self):
        before = _make_result(findings=[_finding("exfil_webhook")])
        env = create_envelope(before)
        after = _make_result()
        verdict = check_approval(env, after)
        assert verdict.status == "valid"

    def test_capability_reduced(self):
        before = _make_result(
            caps=[_cap(ResourceType.NETWORK, AccessLevel.ADMIN)]
        )
        env = create_envelope(before)
        after = _make_result(
            caps=[_cap(ResourceType.NETWORK, AccessLevel.READ)]
        )
        verdict = check_approval(env, after)
        assert verdict.status == "valid"

    def test_same_severity_different_finding(self):
        before = _make_result(
            findings=[_finding("exfil_webhook", Severity.HIGH)]
        )
        env = create_envelope(before)
        after = _make_result(
            findings=[_finding("other_pattern", Severity.HIGH)]
        )
        verdict = check_approval(env, after)
        assert verdict.status == "valid"

    def test_previously_accepted_critical_still_valid(self):
        before = _make_result(
            findings=[_finding("known_critical", Severity.CRITICAL)]
        )
        env = create_envelope(before)
        after = _make_result(
            findings=[_finding("known_critical", Severity.CRITICAL)]
        )
        verdict = check_approval(env, after)
        assert verdict.status == "valid"


class TestApprovalInvalidated:
    def test_new_critical_finding(self):
        before = _make_result()
        env = create_envelope(before)
        after = _make_result(
            findings=[_finding("shell_injection", Severity.CRITICAL)]
        )
        verdict = check_approval(env, after)
        assert verdict.status == "invalidated"
        assert any("CRITICAL" in r for r in verdict.reasons)

    def test_capability_escalation(self):
        before = _make_result(
            caps=[_cap(ResourceType.FILESYSTEM, AccessLevel.READ)]
        )
        env = create_envelope(before)
        after = _make_result(
            caps=[_cap(ResourceType.FILESYSTEM, AccessLevel.ADMIN)]
        )
        verdict = check_approval(env, after)
        assert verdict.status == "invalidated"
        assert any("capability escalation" in r for r in verdict.reasons)

    def test_new_resource_type(self):
        before = _make_result(
            caps=[_cap(ResourceType.FILESYSTEM, AccessLevel.READ)]
        )
        env = create_envelope(before)
        after = _make_result(
            caps=[
                _cap(ResourceType.FILESYSTEM, AccessLevel.READ),
                _cap(ResourceType.SHELL, AccessLevel.ADMIN),
            ],
        )
        verdict = check_approval(env, after)
        assert verdict.status == "invalidated"
        assert any("shell" in r for r in verdict.reasons)

    def test_severity_escalation(self):
        before = _make_result(
            findings=[_finding("minor_issue", Severity.LOW)]
        )
        env = create_envelope(before)
        after = _make_result(
            findings=[_finding("new_high_issue", Severity.HIGH)]
        )
        verdict = check_approval(env, after)
        assert verdict.status == "invalidated"
        assert any("severity escalation" in r for r in verdict.reasons)

    def test_multiple_invalidation_reasons(self):
        before = _make_result(
            caps=[_cap(ResourceType.FILESYSTEM, AccessLevel.READ)]
        )
        env = create_envelope(before)
        after = _make_result(
            findings=[_finding("shell_injection", Severity.CRITICAL)],
            caps=[_cap(ResourceType.FILESYSTEM, AccessLevel.ADMIN)],
        )
        verdict = check_approval(env, after)
        assert verdict.status == "invalidated"
        assert len(verdict.reasons) >= 2
