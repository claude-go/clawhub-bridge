"""Tests for approve and check CLI commands."""

import os
import tempfile

from clawhub_bridge.approval import ApprovalEnvelope
from clawhub_bridge.cli import cmd_approve, cmd_check

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class _FakeArgs:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class TestCmdApprove:
    def test_creates_envelope_file(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = f.name
        try:
            args = _FakeArgs(
                source=os.path.join(FIXTURES, "clean_skill.md"),
                output=out,
            )
            code = cmd_approve(args)
            assert code == 0
            env = ApprovalEnvelope.from_json(open(out).read())
            assert env.verdict_at_approval == "PASS"
            assert env.total_findings == 0
        finally:
            os.unlink(out)

    def test_suspicious_skill_envelope(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = f.name
        try:
            args = _FakeArgs(
                source=os.path.join(FIXTURES, "suspicious_skill.md"),
                output=out,
            )
            code = cmd_approve(args)
            assert code == 0
            env = ApprovalEnvelope.from_json(open(out).read())
            assert env.total_findings > 0
            assert env.max_accepted_severity != "none"
        finally:
            os.unlink(out)


class TestCmdCheck:
    def _create_envelope(self, fixture: str) -> str:
        with tempfile.NamedTemporaryFile(
            suffix=".json", delete=False
        ) as f:
            out = f.name
        args = _FakeArgs(
            source=os.path.join(FIXTURES, fixture), output=out
        )
        cmd_approve(args)
        return out

    def test_same_file_valid(self):
        env_path = self._create_envelope("clean_skill.md")
        try:
            args = _FakeArgs(
                envelope=env_path,
                source=os.path.join(FIXTURES, "clean_skill.md"),
                json=False,
            )
            code = cmd_check(args)
            assert code == 0
        finally:
            os.unlink(env_path)

    def test_malicious_invalidated(self):
        env_path = self._create_envelope("clean_skill.md")
        try:
            args = _FakeArgs(
                envelope=env_path,
                source=os.path.join(FIXTURES, "malicious_skill.md"),
                json=False,
            )
            code = cmd_check(args)
            assert code == 1
        finally:
            os.unlink(env_path)

    def test_json_output(self):
        env_path = self._create_envelope("clean_skill.md")
        try:
            args = _FakeArgs(
                envelope=env_path,
                source=os.path.join(FIXTURES, "malicious_skill.md"),
                json=True,
            )
            code = cmd_check(args)
            assert code == 1
        finally:
            os.unlink(env_path)

    def test_approved_suspicious_checked_against_same(self):
        env_path = self._create_envelope("suspicious_skill.md")
        try:
            args = _FakeArgs(
                envelope=env_path,
                source=os.path.join(FIXTURES, "suspicious_skill.md"),
                json=False,
            )
            code = cmd_check(args)
            assert code == 0
        finally:
            os.unlink(env_path)
