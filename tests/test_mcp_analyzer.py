"""Tests for MCP server security analyzer."""

from clawhub_bridge.mcp.analyzer import analyze_mcp_server
from clawhub_bridge.mcp.types import McpServerConfig

# Test secret patterns (obviously fake, for pattern matching only).
_TEST_SK = "sk-" + "x" * 30  # noqa: S105
_TEST_GHP = "ghp_" + "A" * 36  # noqa: S105


def test_shell_command_is_critical():
    cfg = McpServerConfig(
        name="shell", command="bash", args=["-c", "script.sh"]
    )
    result = analyze_mcp_server(cfg)
    assert result.verdict == "FAIL"
    assert any(
        f.category == "command_risk" for f in result.findings
    )


def test_dangerous_package_detected():
    cfg = McpServerConfig(
        name="fs", command="npx",
        args=["-y", "mcp-server-filesystem"],
    )
    result = analyze_mcp_server(cfg)
    assert any(
        f.category == "dangerous_capability"
        for f in result.findings
    )


def test_dangerous_args_detected():
    cfg = McpServerConfig(
        name="fs", command="npx",
        args=["-y", "some-pkg", "--allow-write"],
    )
    result = analyze_mcp_server(cfg)
    assert any(
        f.category == "dangerous_args" for f in result.findings
    )


def test_ssh_path_flagged():
    cfg = McpServerConfig(
        name="files", command="npx",
        args=["-y", "mcp-files", "--path", "~/.ssh"],
    )
    result = analyze_mcp_server(cfg)
    assert any(
        "SSH" in f.title for f in result.findings
    )


def test_hardcoded_secret_critical():
    cfg = McpServerConfig(
        name="api", command="npx",
        args=["-y", "mcp-openai"],
        env={"OPENAI_KEY": _TEST_SK},
    )
    result = analyze_mcp_server(cfg)
    assert result.verdict == "FAIL"
    assert any(
        f.category == "hardcoded_secret" for f in result.findings
    )


def test_hardcoded_github_token_critical():
    cfg = McpServerConfig(
        name="gh", command="npx",
        args=["-y", "mcp-github"],
        env={"GITHUB_TOKEN": _TEST_GHP},
    )
    result = analyze_mcp_server(cfg)
    assert result.verdict == "FAIL"


def test_http_transport_flagged():
    cfg = McpServerConfig(
        name="remote", command="",
        url="http://api.example.com/mcp",
        transport="http",
    )
    result = analyze_mcp_server(cfg)
    assert any(
        f.category == "transport_security"
        for f in result.findings
    )


def test_https_transport_ok():
    cfg = McpServerConfig(
        name="remote", command="",
        url="https://api.example.com/mcp",
        transport="http",
    )
    result = analyze_mcp_server(cfg)
    assert not any(
        f.category == "transport_security"
        for f in result.findings
    )


def test_safe_config_passes():
    cfg = McpServerConfig(
        name="weather", command="npx",
        args=["-y", "@anthropic/weather-server"],
    )
    result = analyze_mcp_server(cfg)
    assert result.verdict == "PASS"
    assert len(result.findings) == 0


def test_docker_is_medium():
    cfg = McpServerConfig(
        name="sandbox", command="docker",
        args=["run", "mcp-sandbox"],
    )
    result = analyze_mcp_server(cfg)
    assert any(
        f.severity.value == "medium" for f in result.findings
    )


def test_env_without_secrets_passes():
    cfg = McpServerConfig(
        name="api", command="npx",
        args=["-y", "mcp-api"],
        env={"NODE_ENV": "production", "PORT": "3000"},
    )
    result = analyze_mcp_server(cfg)
    assert not any(
        f.category == "hardcoded_secret"
        for f in result.findings
    )


def test_non_ascii_package_name_flagged():
    cfg = McpServerConfig(
        name="sus", command="npx",
        args=["-y", "mcp-s\u0435rver"],  # Cyrillic 'e'
    )
    result = analyze_mcp_server(cfg)
    assert any(
        f.category == "supply_chain" for f in result.findings
    )


def test_result_to_dict_structure():
    cfg = McpServerConfig(name="test", command="bash")
    result = analyze_mcp_server(cfg)
    d = result.to_dict()
    assert "findings" in d
    assert "verdict" in d
    assert d["verdict"] == "FAIL"
    assert len(d["findings"]) > 0
