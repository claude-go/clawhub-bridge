"""Tests for MCP types."""

from clawhub_bridge.mcp.types import (
    McpFinding,
    McpScanResult,
    McpServerConfig,
    McpSeverity,
)


def test_server_config_package_name_npx():
    cfg = McpServerConfig(
        name="test", command="npx", args=["-y", "@scope/pkg"]
    )
    assert cfg.package_name == "@scope/pkg"


def test_server_config_package_name_uvx():
    cfg = McpServerConfig(
        name="test", command="uvx", args=["mcp-server-sqlite"]
    )
    assert cfg.package_name == "mcp-server-sqlite"


def test_server_config_package_name_fallback():
    cfg = McpServerConfig(name="test", command="custom-binary")
    assert cfg.package_name == "custom-binary"


def test_scan_result_pass_by_default():
    cfg = McpServerConfig(name="s", command="npx")
    result = McpScanResult(server_name="s", config=cfg)
    assert result.verdict == "PASS"


def test_scan_result_critical_sets_fail():
    cfg = McpServerConfig(name="s", command="npx")
    result = McpScanResult(server_name="s", config=cfg)
    result.add(McpFinding(
        category="test",
        severity=McpSeverity.CRITICAL,
        title="Critical finding",
        description="Test",
    ))
    assert result.verdict == "FAIL"


def test_scan_result_high_sets_review():
    cfg = McpServerConfig(name="s", command="npx")
    result = McpScanResult(server_name="s", config=cfg)
    result.add(McpFinding(
        category="test",
        severity=McpSeverity.HIGH,
        title="High finding",
        description="Test",
    ))
    assert result.verdict == "REVIEW"


def test_scan_result_to_dict():
    cfg = McpServerConfig(
        name="s", command="npx", args=["-y", "pkg"]
    )
    result = McpScanResult(server_name="s", config=cfg)
    d = result.to_dict()
    assert d["server_name"] == "s"
    assert d["verdict"] == "PASS"
    assert d["package"] == "pkg"


def test_finding_server_name_set_on_add():
    cfg = McpServerConfig(name="s", command="npx")
    result = McpScanResult(server_name="s", config=cfg)
    finding = McpFinding(
        category="test",
        severity=McpSeverity.LOW,
        title="Test",
        description="Test",
    )
    result.add(finding)
    assert finding.server_name == "s"
