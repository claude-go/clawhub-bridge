"""Tests for cloud credential harvesting detection patterns."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scanner import scan_content, scan_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_aws_credentials():
    content = "cat ~/.aws/credentials"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "aws_credentials" in names
    assert result.verdict == "FAIL"


def test_aws_secret_key_env():
    content = "export AWS_SECRET_ACCESS_KEY=wJalr..."
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "aws_credentials" in names


def test_gcp_credentials():
    content = "cat ~/.config/gcloud/application_default_credentials.json"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "gcp_credentials" in names


def test_gcp_application_credentials_env():
    content = "GOOGLE_APPLICATION_CREDENTIALS=/tmp/sa-key.json"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "gcp_credentials" in names


def test_azure_credentials():
    content = "cat ~/.azure/accessTokens.json"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "azure_credentials" in names


def test_kube_config():
    content = "cat ~/.kube/config"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "kube_config" in names


def test_kube_config_env():
    content = "KUBECONFIG= ~/.kube/config"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "kube_config" in names


def test_terraform_state():
    content = "terraform state pull > /tmp/state.json"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "terraform_state" in names


def test_terraform_state_file():
    content = "cp production.tfstate /tmp/backup"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "terraform_state" in names


def test_cloud_metadata_aws():
    content = "curl http://169.254.169.254/latest/meta-data/"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "cloud_metadata_endpoint" in names
    assert result.verdict == "FAIL"


def test_cloud_metadata_gcp():
    content = "curl http://metadata.google.internal/computeMetadata/v1/"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "cloud_metadata_endpoint" in names


def test_cloud_cred_fixture():
    result = scan_file(str(FIXTURES / "cloud_cred_skill.md"))
    assert result.verdict == "FAIL"
    names = {f.pattern_name for f in result.findings}
    assert "aws_credentials" in names
    assert "gcp_credentials" in names
    assert "kube_config" in names
    assert "cloud_metadata_endpoint" in names
    assert "terraform_state" in names


def test_clean_skill_no_cloud_findings():
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
