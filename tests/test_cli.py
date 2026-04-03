"""Tests for CLI batch JSON output and scan commands."""

from __future__ import annotations

import json

from clawhub_bridge.cli import cmd_scan, _expand_sources


class FakeArgs:
    def __init__(self, source: str, as_json: bool = False):
        self.source = source
        self.json = as_json
        self.policy = None
        self.context = None


class TestExpandSources:
    def test_single_file(self, tmp_path):
        p = tmp_path / "skill.md"
        p.write_text("# Clean skill")
        result = _expand_sources(str(p))
        assert result == [str(p)]

    def test_directory(self, tmp_path):
        (tmp_path / "a.md").write_text("# A")
        (tmp_path / "b.md").write_text("# B")
        (tmp_path / "c.txt").write_text("not markdown")
        result = _expand_sources(str(tmp_path))
        assert len(result) == 2
        assert all(r.endswith(".md") for r in result)

    def test_url(self):
        result = _expand_sources("https://github.com/user/repo")
        assert result == ["https://github.com/user/repo"]

    def test_missing_path(self):
        result = _expand_sources("/nonexistent/path/xyz")
        assert result == []


class TestBatchJsonOutput:
    def test_single_file_json_is_object(self, tmp_path, capsys):
        p = tmp_path / "clean.md"
        p.write_text("# A clean skill\nNo malicious content here.")
        args = FakeArgs(source=str(p), as_json=True)
        exit_code = cmd_scan(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, dict)
        assert data["verdict"] == "PASS"
        assert exit_code == 0

    def test_directory_json_is_array(self, tmp_path, capsys):
        (tmp_path / "a.md").write_text("# Clean skill A")
        (tmp_path / "b.md").write_text("# Clean skill B")
        args = FakeArgs(source=str(tmp_path), as_json=True)
        exit_code = cmd_scan(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) == 2
        assert all(r["verdict"] == "PASS" for r in data)
        assert exit_code == 0

    def test_fail_verdict_exit_code(self, tmp_path, capsys):
        p = tmp_path / "bad.md"
        p.write_text("Run this: cat ~/.ssh/id_rsa")
        args = FakeArgs(source=str(p), as_json=True)
        exit_code = cmd_scan(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["verdict"] == "FAIL"
        assert exit_code == 1

    def test_batch_with_mixed_verdicts(self, tmp_path, capsys):
        (tmp_path / "clean.md").write_text("# Safe skill")
        (tmp_path / "bad.md").write_text("cat ~/.ssh/id_rsa")
        args = FakeArgs(source=str(tmp_path), as_json=True)
        exit_code = cmd_scan(args)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        verdicts = {r["verdict"] for r in data}
        assert "FAIL" in verdicts
        assert exit_code == 1
