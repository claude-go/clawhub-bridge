"""Tests for policy types and apply logic."""

import pytest

from clawhub_bridge.patterns import Severity
from clawhub_bridge.policy import (
    Policy,
    PolicyContext,
    PolicyVerdict,
    apply_policy,
    _extract_category,
)


def _ctx_dev() -> PolicyContext:
    return PolicyContext(
        block={Severity.CRITICAL},
        review={Severity.HIGH},
    )


def _ctx_prod() -> PolicyContext:
    return PolicyContext(
        block={Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM},
        review={Severity.LOW},
        max_findings=0,
        blocked_categories={"steganography", "supply", "agent"},
    )


def _policy() -> Policy:
    return Policy(
        contexts={"development": _ctx_dev(), "production": _ctx_prod()},
        default_context="production",
    )


def _finding(name: str = "test_pattern", severity: str = "high") -> dict:
    return {"name": name, "severity": severity, "line": 1}


class TestPolicyContext:
    def test_default_context(self):
        policy = _policy()
        ctx = policy.get_context()
        assert Severity.CRITICAL in ctx.block
        assert Severity.HIGH in ctx.block

    def test_named_context(self):
        policy = _policy()
        ctx = policy.get_context("development")
        assert Severity.CRITICAL in ctx.block
        assert Severity.HIGH not in ctx.block
        assert Severity.HIGH in ctx.review

    def test_unknown_context_raises(self):
        policy = _policy()
        with pytest.raises(ValueError, match="Unknown policy context"):
            policy.get_context("nonexistent")


class TestApplyPolicy:
    def test_pass_no_findings(self):
        result = apply_policy([], _policy(), "development")
        assert result.verdict == "PASS"
        assert result.total_findings == 0

    def test_critical_blocked_in_dev(self):
        findings = [_finding(severity="critical")]
        result = apply_policy(findings, _policy(), "development")
        assert result.verdict == "FAIL"
        assert result.blocked_findings == 1

    def test_high_review_in_dev(self):
        findings = [_finding(severity="high")]
        result = apply_policy(findings, _policy(), "development")
        assert result.verdict == "REVIEW"
        assert result.reviewed_findings == 1

    def test_medium_allowed_in_dev(self):
        findings = [_finding(severity="medium")]
        result = apply_policy(findings, _policy(), "development")
        assert result.verdict == "PASS"
        assert result.allowed_findings == 1

    def test_high_blocked_in_prod(self):
        findings = [_finding(severity="high")]
        result = apply_policy(findings, _policy(), "production")
        assert result.verdict == "FAIL"
        assert result.blocked_findings >= 1

    def test_max_findings_exceeded(self):
        findings = [_finding(severity="low")]
        result = apply_policy(findings, _policy(), "production")
        assert result.verdict == "FAIL"
        assert "Exceeds max findings" in result.reasons[-1]

    def test_category_blocking(self):
        findings = [_finding(name="steganography_homoglyph", severity="low")]
        result = apply_policy(findings, _policy(), "production")
        assert result.verdict == "FAIL"
        assert any("Category blocked" in r for r in result.reasons)

    def test_allowed_pattern_bypasses(self):
        ctx = PolicyContext(
            block={Severity.CRITICAL, Severity.HIGH},
            allowed_patterns={"known_false_positive"},
        )
        policy = Policy(contexts={"test": ctx}, default_context="test")
        findings = [_finding(name="known_false_positive", severity="critical")]
        result = apply_policy(findings, policy, "test")
        assert result.verdict == "PASS"
        assert result.allowed_findings == 1

    def test_mixed_findings(self):
        findings = [
            _finding(severity="critical"),
            _finding(severity="low"),
            _finding(name="ok_pattern", severity="medium"),
        ]
        result = apply_policy(findings, _policy(), "development")
        assert result.verdict == "FAIL"
        assert result.blocked_findings == 1
        assert result.reviewed_findings == 0
        assert result.allowed_findings == 2

    def test_uses_default_context(self):
        findings = [_finding(severity="medium")]
        result = apply_policy(findings, _policy())
        assert result.context_name == "production"
        assert result.verdict == "FAIL"


class TestPolicyVerdict:
    def test_to_dict(self):
        v = PolicyVerdict(
            verdict="FAIL",
            context_name="production",
            total_findings=3,
            blocked_findings=1,
            reviewed_findings=1,
            allowed_findings=1,
            reasons=["test reason"],
        )
        d = v.to_dict()
        assert d["verdict"] == "FAIL"
        assert d["context"] == "production"
        assert d["reasons"] == ["test reason"]


class TestExtractCategory:
    def test_compound_name(self):
        assert _extract_category("steganography_homoglyph") == "steganography"

    def test_single_name(self):
        assert _extract_category("simple") == "simple"

    def test_multi_part(self):
        assert _extract_category("supply_chain_hijack") == "supply"
