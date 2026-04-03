"""Tests for the irreversible action reachability analyzer."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from clawhub_bridge.scanner import scan_content
from clawhub_bridge.reachability import analyze_reachability
from clawhub_bridge.patterns.types import Severity


def test_unguarded_payment_escalates_to_critical():
    content = 'stripe.charges.create(amount=5000, currency="usd")'
    result = scan_content(content, source="test")
    findings = [f for f in result.findings if f.pattern_name == "payment_api_call"]
    assert findings
    assert findings[0].description.startswith("[UNGUARDED]")


def test_guarded_payment_keeps_severity():
    content = """# Payment flow
Ask the user to confirm before proceeding
if user confirms:
    stripe.charges.create(amount=5000, currency="usd")
"""
    result = scan_content(content, source="test")
    reach = analyze_reachability(result, content)
    guarded = [r for r in reach if r.finding.pattern_name == "payment_api_call"]
    assert guarded
    assert guarded[0].guarded is True


def test_unguarded_email_escalated():
    content = "sendgrid.send(mail)"
    result = scan_content(content, source="test")
    findings = [f for f in result.findings if f.pattern_name == "send_email"]
    assert findings
    assert findings[0].severity == Severity.CRITICAL
    assert "[UNGUARDED]" in findings[0].description


def test_guarded_email_not_escalated():
    content = """Do you want to send this email? (y/n)
sendgrid.send(mail)
"""
    result = scan_content(content, source="test")
    findings = [f for f in result.findings if f.pattern_name == "send_email"]
    assert findings
    assert findings[0].severity == Severity.HIGH
    assert "[UNGUARDED]" not in findings[0].description


def test_unguarded_deploy_is_critical():
    content = "wrangler deploy --name worker"
    result = scan_content(content, source="test")
    findings = [f for f in result.findings if f.pattern_name == "deploy_production"]
    assert findings
    assert findings[0].description.startswith("[UNGUARDED]")


def test_guarded_deploy_with_confirm():
    content = """Are you sure you want to deploy? Confirm with yes/no
wrangler deploy --name worker
"""
    result = scan_content(content, source="test")
    reach = analyze_reachability(result, content)
    deploy = [r for r in reach if r.finding.pattern_name == "deploy_production"]
    assert deploy
    assert deploy[0].guarded is True


def test_medium_escalated_to_high_when_unguarded():
    content = "gh issue create --title 'Auto-created issue'"
    result = scan_content(content, source="test")
    findings = [f for f in result.findings if f.pattern_name == "github_issue_pr_create"]
    assert findings
    assert findings[0].severity == Severity.HIGH


def test_guard_within_window():
    content = """Step 1: prepare data
Step 2: validate format
Wait for user confirmation before proceeding
Step 3: process
npm publish --access public
"""
    result = scan_content(content, source="test")
    reach = analyze_reachability(result, content)
    pub = [r for r in reach if r.finding.pattern_name == "package_publish"]
    assert pub
    assert pub[0].guarded is True


def test_guard_outside_window():
    content = """Ask the user to confirm first
line 2
line 3
line 4
line 5
line 6
line 7
line 8
line 9
line 10
line 11
npm publish --access public
"""
    result = scan_content(content, source="test")
    reach = analyze_reachability(result, content)
    pub = [r for r in reach if r.finding.pattern_name == "package_publish"]
    assert pub
    assert pub[0].guarded is False


def test_multiple_irreversible_mixed_guards():
    content = """Confirm with user before sending
sendgrid.send(mail)
stripe.charges.create(amount=100)
line filler
line filler
line filler
line filler
line filler
line filler
line filler
DROP TABLE logs;
"""
    result = scan_content(content, source="test")
    reach = analyze_reachability(result, content)

    email = [r for r in reach if r.finding.pattern_name == "send_email"]
    assert email and email[0].guarded is True

    payment = [r for r in reach if r.finding.pattern_name == "payment_api_call"]
    assert payment and payment[0].guarded is True

    drop = [r for r in reach if r.finding.pattern_name == "database_drop"]
    assert drop and drop[0].guarded is False


def test_verdict_changes_with_escalation():
    content = "gh pr merge 42 --squash"
    result = scan_content(content, source="test")
    assert result.verdict in ("REVIEW", "FAIL")


def test_non_irreversible_not_affected():
    content = "cat ~/.ssh/id_rsa"
    result = scan_content(content, source="test")
    for f in result.findings:
        assert "[UNGUARDED]" not in f.description
