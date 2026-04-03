"""Tests for approval envelope creation and serialization."""

from clawhub_bridge.approval import (
    ApprovalEnvelope,
    ApprovalVerdict,
    create_envelope,
)
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


class TestCreateEnvelope:
    def test_clean_skill(self):
        result = _make_result()
        env = create_envelope(result)
        assert env.approved_source == "test.md"
        assert env.max_accepted_severity == "none"
        assert env.total_findings == 0
        assert env.accepted_finding_names == []
        assert env.capability_ceiling == {}
        assert env.verdict_at_approval == "PASS"

    def test_skill_with_findings(self):
        result = _make_result(
            findings=[
                _finding("exfil_webhook", Severity.HIGH),
                _finding("shell_access", Severity.MEDIUM),
            ],
        )
        env = create_envelope(result)
        assert env.max_accepted_severity == "high"
        assert env.total_findings == 2
        assert sorted(env.accepted_finding_names) == [
            "exfil_webhook",
            "shell_access",
        ]

    def test_skill_with_capabilities(self):
        result = _make_result(
            caps=[
                _cap(ResourceType.FILESYSTEM, AccessLevel.READ),
                _cap(ResourceType.NETWORK, AccessLevel.WRITE),
            ],
        )
        env = create_envelope(result)
        assert env.capability_ceiling == {
            "filesystem": "READ",
            "network": "WRITE",
        }


class TestEnvelopeSerialization:
    def test_roundtrip_json(self):
        result = _make_result(
            source="skill-v1.md",
            findings=[_finding("exfil_webhook", Severity.HIGH)],
            caps=[_cap(ResourceType.NETWORK, AccessLevel.WRITE)],
        )
        env = create_envelope(result)
        raw = env.to_json()
        restored = ApprovalEnvelope.from_json(raw)
        assert restored.approved_source == env.approved_source
        assert restored.max_accepted_severity == env.max_accepted_severity
        assert restored.capability_ceiling == env.capability_ceiling
        assert restored.accepted_finding_names == env.accepted_finding_names

    def test_to_dict_keys(self):
        env = create_envelope(_make_result())
        d = env.to_dict()
        expected = {
            "approved_source",
            "approved_at",
            "max_accepted_severity",
            "capability_ceiling",
            "accepted_finding_names",
            "total_findings",
            "verdict_at_approval",
        }
        assert set(d.keys()) == expected


class TestVerdictSerialization:
    def test_valid_to_dict(self):
        env = create_envelope(_make_result())
        v = ApprovalVerdict(status="valid", envelope=env)
        d = v.to_dict()
        assert d["status"] == "valid"
        assert d["reasons"] == []
        assert "envelope" in d

    def test_invalidated_to_dict(self):
        v = ApprovalVerdict(
            status="invalidated",
            reasons=["new CRITICAL: shell_injection"],
        )
        d = v.to_dict()
        assert d["status"] == "invalidated"
        assert len(d["reasons"]) == 1
