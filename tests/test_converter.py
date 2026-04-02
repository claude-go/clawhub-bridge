"""Tests for the skill converter."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from clawhub_bridge.converter import convert_to_clgo


def test_converts_with_frontmatter():
    content = "---\nname: test\nsummary: A test skill\n---\n\n# Test\nHello."
    result = convert_to_clgo(content, "test")
    assert "name: test" in result.content
    assert "description: A test skill" in result.content
    assert "# Test" in result.content


def test_generates_frontmatter_if_missing():
    content = "# Just a heading\n\nSome content here."
    result = convert_to_clgo(content, "my-skill")
    assert "name: my-skill" in result.content
    assert "Frontmatter genere" in result.changes_made[0]


def test_preserves_body():
    content = "---\nname: x\n---\n\n# Title\n\nBody text here."
    result = convert_to_clgo(content, "x")
    assert "Body text here." in result.content


def test_empty_body_warns():
    content = "---\nname: x\n---\n\n"
    result = convert_to_clgo(content, "x")
    assert any("vide" in c for c in result.changes_made)


def test_detects_openclaw_format():
    content = "---\nname: x\n---\n\nSKILL.md reference for openclaw"
    result = convert_to_clgo(content, "x")
    assert result.original_format == "openclaw"


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  PASS  {test.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {test.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
