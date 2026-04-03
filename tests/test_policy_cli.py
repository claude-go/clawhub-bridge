"""Tests for policy CLI commands and scan --policy integration."""

from __future__ import annotations

import json

from clawhub_bridge.cli import cmd_scan
from clawhub_bridge.policy_cli import cmd_policy


class FakeArgs:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class TestPolicyInit:
    def test_init_outputs_valid_json(self, capsys):
        args = FakeArgs(policy_command="init")
        exit_code = cmd_policy(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "contexts" in data
        assert exit_code == 0


class TestPolicyValidate:
    def test_validate_valid_policy(self, tmp_path, capsys):
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(json.dumps({
            "version": "1",
            "default_context": "dev",
            "contexts": {"dev": {"block": ["critical"]}},
        }))
        args = FakeArgs(policy_command="validate", path=str(policy_file))
        exit_code = cmd_policy(args)
        captured = capsys.readouterr()
        assert "Valid policy" in captured.out
        assert exit_code == 0

    def test_validate_invalid_json(self, tmp_path, capsys):
        policy_file = tmp_path / "bad.json"
        policy_file.write_text("not json")
        args = FakeArgs(policy_command="validate", path=str(policy_file))
        exit_code = cmd_policy(args)
        assert exit_code == 1

    def test_validate_missing_default_warns(self, tmp_path, capsys):
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(json.dumps({
            "default_context": "missing",
            "contexts": {"dev": {"block": ["critical"]}},
        }))
        args = FakeArgs(policy_command="validate", path=str(policy_file))
        exit_code = cmd_policy(args)
        assert exit_code == 1


class TestScanWithPolicy:
    def test_scan_with_policy_overrides_verdict(self, tmp_path, capsys):
        skill = tmp_path / "skill.md"
        skill.write_text("Run: cat ~/.ssh/id_rsa")
        policy_file = tmp_path / "policy.json"
        policy_file.write_text(json.dumps({
            "default_context": "dev",
            "contexts": {
                "dev": {
                    "block": [],
                    "review": ["critical"],
                },
            },
        }))
        args = FakeArgs(
            source=str(skill),
            json=True,
            policy=str(policy_file),
            context="dev",
        )
        cmd_scan(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["verdict"] == "REVIEW"
        assert "policy_verdict" in data

    def test_scan_without_policy_uses_default(self, tmp_path, capsys):
        skill = tmp_path / "clean.md"
        skill.write_text("# Clean skill")
        args = FakeArgs(
            source=str(skill),
            json=True,
            policy=None,
            context=None,
        )
        cmd_scan(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["verdict"] == "PASS"
        assert "policy_verdict" not in data
