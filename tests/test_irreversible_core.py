"""Tests for irreversible action patterns: financial, communication, deployment."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from clawhub_bridge.scanner import scan_content


# --- Financial Transactions ---

def test_stripe_payment():
    content = 'stripe.charges.create(amount=5000, currency="usd")'
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "payment_api_call" in names


def test_paypal_payment():
    content = "paypal.com/v2/payments/capture"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "payment_api_call" in names


def test_crypto_transfer():
    content = "web3.eth.send_transaction({to: addr, value: amount})"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "crypto_transfer" in names


def test_wallet_send():
    content = "wallet.send(recipient, 0.5)"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "crypto_transfer" in names


def test_subscription_create():
    content = 'stripe.subscriptions.create(customer="cus_123")'
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "subscription_create" in names


# --- Public Communication ---

def test_sendmail():
    content = "smtp.send(to=recipient, body=message)"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "send_email" in names


def test_sendgrid_email():
    content = "sendgrid.send(mail)"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "send_email" in names


def test_ses_send_email():
    content = "ses.send_email(Destination=recipients)"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "send_email" in names


def test_social_media_post():
    content = "post to bluesky with the article content"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "social_media_post" in names


def test_bsky_create_record():
    content = "bsky.social/xrpc/createRecord"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "social_media_post" in names


def test_gh_issue_create():
    content = "gh issue create --title 'Bug' --body 'desc'"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "github_issue_pr_create" in names


def test_gh_pr_create():
    content = "gh pr create --title 'Feature' --body 'impl'"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "github_issue_pr_create" in names


def test_messaging_slack():
    content = "slack.chat.postMessage(channel='general', text='hello')"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "messaging_send" in names


def test_messaging_telegram():
    content = "telegram.send_message(chat_id=123, text='msg')"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "messaging_send" in names


# --- Deployment/Publishing ---

def test_npm_publish():
    content = "npm publish --access public"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "package_publish" in names


def test_uv_publish():
    content = "uv publish dist/*"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "package_publish" in names


def test_cargo_publish():
    content = "cargo publish --registry crates-io"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "package_publish" in names


def test_docker_push():
    content = "docker push myimage:latest"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "container_push" in names


def test_wrangler_deploy():
    content = "wrangler deploy --name my-worker"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "deploy_production" in names


def test_vercel_deploy():
    content = "vercel --prod"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "deploy_production" in names


def test_gh_release_create():
    content = "gh release create v1.0.0 --title 'Release'"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "github_release_create" in names
