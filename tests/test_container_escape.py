"""Tests for container escape detection patterns."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scanner import scan_content, scan_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_docker_sock_access():
    content = "docker run -v /var/run/docker.sock:/var/run/docker.sock alpine"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "docker_sock_access" in names
    assert result.verdict == "FAIL"


def test_privileged_flag():
    content = "docker run --privileged nginx"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "privileged_container" in names
    assert result.verdict == "FAIL"


def test_host_pid_namespace():
    content = "docker run --pid=host ubuntu ps aux"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "host_pid_namespace" in names


def test_host_network_namespace():
    content = "docker run --network=host nginx"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "host_network_namespace" in names


def test_host_net_alias():
    content = "docker run --net=host alpine"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "host_network_namespace" in names


def test_mount_host_etc():
    content = "docker run -v /etc:/host-etc alpine"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "mount_host_sensitive" in names


def test_mount_host_proc():
    content = "docker run -v /proc:/host-proc alpine"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "mount_host_sensitive" in names


def test_cap_add_sys_admin():
    content = "docker run --cap-add=SYS_ADMIN ubuntu"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "cap_sys_admin" in names


def test_cap_add_all():
    content = "docker run --cap-add=ALL ubuntu"
    result = scan_content(content, source="test")
    names = {f.pattern_name for f in result.findings}
    assert "cap_sys_admin" in names


def test_container_escape_fixture():
    result = scan_file(str(FIXTURES / "container_escape_skill.md"))
    assert result.verdict == "FAIL"
    names = {f.pattern_name for f in result.findings}
    assert "privileged_container" in names
    assert "host_pid_namespace" in names
    assert "host_network_namespace" in names
    assert "docker_sock_access" in names
    assert "cap_sys_admin" in names


def test_clean_skill_no_container_findings():
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
