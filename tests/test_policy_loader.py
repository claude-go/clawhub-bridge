"""Tests for policy loading, parsing, and default generation."""

import json
import tempfile
from pathlib import Path

import pytest

from clawhub_bridge.patterns import Severity
from clawhub_bridge.policy_loader import (
    DEFAULT_POLICY,
    generate_default_policy,
    load_policy,
    parse_policy,
)


class TestParsePolicy:
    def test_parse_minimal(self):
        data = {
            "contexts": {
                "dev": {"block": ["critical"], "review": ["high"]},
            },
            "default_context": "dev",
        }
        policy = parse_policy(data)
        assert "dev" in policy.contexts
        ctx = policy.get_context("dev")
        assert Severity.CRITICAL in ctx.block
        assert Severity.HIGH in ctx.review

    def test_parse_with_categories(self):
        data = {
            "contexts": {
                "prod": {
                    "block": ["critical", "high"],
                    "blocked_categories": ["steganography"],
                    "max_findings": 5,
                },
            },
            "default_context": "prod",
        }
        policy = parse_policy(data)
        ctx = policy.get_context("prod")
        assert "steganography" in ctx.blocked_categories
        assert ctx.max_findings == 5

    def test_parse_with_allowed_patterns(self):
        data = {
            "contexts": {
                "dev": {
                    "block": ["critical"],
                    "allowed_patterns": ["known_fp_1", "known_fp_2"],
                },
            },
            "default_context": "dev",
        }
        policy = parse_policy(data)
        ctx = policy.get_context("dev")
        assert "known_fp_1" in ctx.allowed_patterns
        assert "known_fp_2" in ctx.allowed_patterns

    def test_invalid_severity_ignored(self):
        data = {
            "contexts": {
                "dev": {"block": ["critical", "banana", "high"]},
            },
        }
        policy = parse_policy(data)
        ctx = policy.get_context("dev")
        assert Severity.CRITICAL in ctx.block
        assert Severity.HIGH in ctx.block
        assert len(ctx.block) == 2

    def test_empty_contexts(self):
        policy = parse_policy({"contexts": {}})
        assert len(policy.contexts) == 0

    def test_version_preserved(self):
        policy = parse_policy({"version": "2", "contexts": {}})
        assert policy.version == "2"


class TestLoadPolicy:
    def test_load_from_file(self):
        data = {
            "version": "1",
            "default_context": "dev",
            "contexts": {
                "dev": {"block": ["critical"]},
            },
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(data, f)
            f.flush()
            policy = load_policy(f.name)

        assert policy.default_context == "dev"
        assert "dev" in policy.contexts
        Path(f.name).unlink()

    def test_load_invalid_json_raises(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write("not json")
            f.flush()
            with pytest.raises(json.JSONDecodeError):
                load_policy(f.name)
        Path(f.name).unlink()


class TestDefaultPolicy:
    def test_default_has_three_contexts(self):
        policy = parse_policy(DEFAULT_POLICY)
        assert "development" in policy.contexts
        assert "staging" in policy.contexts
        assert "production" in policy.contexts

    def test_default_production_is_strictest(self):
        policy = parse_policy(DEFAULT_POLICY)
        prod = policy.get_context("production")
        assert Severity.CRITICAL in prod.block
        assert Severity.HIGH in prod.block
        assert Severity.MEDIUM in prod.block
        assert prod.max_findings == 0

    def test_default_dev_is_permissive(self):
        policy = parse_policy(DEFAULT_POLICY)
        dev = policy.get_context("development")
        assert Severity.CRITICAL in dev.block
        assert Severity.HIGH not in dev.block
        assert dev.max_findings is None

    def test_generate_returns_valid_json(self):
        raw = generate_default_policy()
        data = json.loads(raw)
        assert "contexts" in data
        policy = parse_policy(data)
        assert len(policy.contexts) == 3
