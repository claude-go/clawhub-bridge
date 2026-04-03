"""Tests for irreversible action patterns: data, access, service lifecycle."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from clawhub_bridge.scanner import scan_content


# --- Permanent Data Loss ---

def test_drop_table():
    content = "DROP TABLE users;"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "database_drop" in names


def test_drop_database():
    content = "DROP DATABASE production;"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "database_drop" in names


def test_truncate_table():
    content = "TRUNCATE TABLE logs;"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "database_truncate" in names


def test_delete_without_where():
    content = "DELETE FROM users;"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "delete_without_where" in names


def test_s3_recursive_delete():
    content = "aws s3 rm s3://bucket/data/ --recursive"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "bucket_delete" in names


# --- Access Control Changes ---

def test_account_deletion():
    content = "delete_account(user_id=123)"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "account_deletion" in names


def test_api_account_delete():
    content = "api.example.com/accounts/123 DELETE"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "account_deletion" in names


def test_revoke_token():
    content = "revoke_token(access_token)"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "credential_revoke" in names


def test_password_change_api():
    content = "change_password via api endpoint"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "password_change_external" in names


# --- Service Lifecycle ---

def test_terminate_ec2():
    content = "aws ec2 terminate-instances --instance-ids i-123"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "terminate_instance" in names


def test_kubectl_delete_namespace():
    content = "kubectl delete namespace production"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "terminate_instance" in names


def test_dns_record_delete():
    content = "cloudflare dns record delete zone123"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "dns_record_change" in names


def test_gh_pr_merge():
    content = "gh pr merge 42 --squash"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "close_merge_pr" in names


# --- Negative tests ---

def test_stripe_customer_list_no_match():
    content = 'stripe.customers.list(limit=10)'
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    irreversible = names & {
        "payment_api_call", "crypto_transfer",
        "subscription_create",
    }
    assert not irreversible


def test_select_query_no_match():
    content = "SELECT * FROM users WHERE id = 1;"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "database_drop" not in names
    assert "database_truncate" not in names
    assert "delete_without_where" not in names
