"""Tests for MCP config parser."""

import json
import os
import tempfile

from clawhub_bridge.mcp.config_parser import (
    parse_mcp_config,
    parse_mcp_json,
)


def test_parse_claude_desktop_format():
    config = json.dumps({
        "mcpServers": {
            "sqlite": {
                "command": "uvx",
                "args": ["mcp-server-sqlite", "--db", "/tmp/test.db"],
            }
        }
    })
    servers = parse_mcp_config(config)
    assert len(servers) == 1
    assert servers[0].name == "sqlite"
    assert servers[0].command == "uvx"
    assert servers[0].args[0] == "mcp-server-sqlite"


def test_parse_multiple_servers():
    config = json.dumps({
        "mcpServers": {
            "a": {"command": "npx", "args": ["-y", "pkg-a"]},
            "b": {"command": "uvx", "args": ["pkg-b"]},
        }
    })
    servers = parse_mcp_config(config)
    assert len(servers) == 2
    names = {s.name for s in servers}
    assert names == {"a", "b"}


def test_parse_with_env_vars():
    config = json.dumps({
        "mcpServers": {
            "api": {
                "command": "npx",
                "args": ["-y", "@scope/mcp-api"],
                "env": {"API_KEY": "test-key"},
            }
        }
    })
    servers = parse_mcp_config(config)
    assert servers[0].env == {"API_KEY": "test-key"}


def test_parse_url_based_transport():
    config = json.dumps({
        "mcpServers": {
            "remote": {"url": "http://localhost:3000/sse"}
        }
    })
    servers = parse_mcp_config(config)
    assert len(servers) == 1
    assert servers[0].transport == "sse"
    assert servers[0].url == "http://localhost:3000/sse"


def test_parse_http_transport():
    config = json.dumps({
        "mcpServers": {
            "remote": {"url": "http://example.com/api"}
        }
    })
    servers = parse_mcp_config(config)
    assert servers[0].transport == "http"


def test_parse_from_file():
    config = {
        "mcpServers": {
            "test": {"command": "node", "args": ["server.js"]}
        }
    }
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as f:
        json.dump(config, f)
        f.flush()
        path = f.name
    try:
        servers = parse_mcp_config(path)
        assert len(servers) == 1
        assert servers[0].name == "test"
    finally:
        os.unlink(path)


def test_parse_direct_server_map():
    config = json.dumps({
        "sqlite": {
            "command": "uvx",
            "args": ["mcp-server-sqlite"],
        }
    })
    servers = parse_mcp_config(config)
    assert len(servers) == 1
    assert servers[0].name == "sqlite"


def test_parse_json_dict():
    data = {
        "mcpServers": {
            "test": {"command": "npx", "args": ["-y", "pkg"]}
        }
    }
    servers = parse_mcp_json(data)
    assert len(servers) == 1


def test_parse_empty_config():
    servers = parse_mcp_config("{}")
    assert len(servers) == 0


def test_parse_skips_invalid_entries():
    config = json.dumps({
        "mcpServers": {
            "valid": {"command": "npx", "args": ["pkg"]},
            "invalid": "not-a-dict",
        }
    })
    servers = parse_mcp_config(config)
    assert len(servers) == 1
