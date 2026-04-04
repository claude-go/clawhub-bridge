"""Parse MCP server configuration files.

Handles Claude Desktop config (claude_desktop_config.json),
Claude Code settings (.claude/settings.json), and standalone
MCP config files."""

from __future__ import annotations

import json

from .types import McpServerConfig

# Max config file size to prevent DoS via huge files.
_MAX_CONFIG_SIZE = 1_048_576  # 1 MB


def parse_mcp_config(source: str) -> list[McpServerConfig]:
    """Parse an MCP config file and return server configs.

    Accepts JSON content or a file path.
    """
    content = _read_source(source)
    data = json.loads(content)
    return _extract_servers(data)


def parse_mcp_json(data: dict) -> list[McpServerConfig]:
    """Parse MCP servers from a pre-loaded dict."""
    return _extract_servers(data)


def _read_source(source: str) -> str:
    """Read config from string or file path."""
    stripped = source.strip()
    if stripped.startswith("{"):
        return stripped

    with open(source, encoding="utf-8") as f:
        content = f.read(_MAX_CONFIG_SIZE)
    return content


def _extract_servers(data: dict) -> list[McpServerConfig]:
    """Extract MCP server configs from various formats."""
    servers: list[McpServerConfig] = []

    # Format 1: {"mcpServers": {"name": {...}}}
    mcp_servers = data.get("mcpServers", {})

    # Format 2: Direct {"name": {"command": ...}}
    if not mcp_servers and _looks_like_server_map(data):
        mcp_servers = data

    for name, config in mcp_servers.items():
        if not isinstance(config, dict):
            continue
        server = _parse_single_server(name, config)
        if server:
            servers.append(server)

    return servers


def _looks_like_server_map(data: dict) -> bool:
    """Check if dict looks like a direct server map."""
    for val in data.values():
        if isinstance(val, dict) and "command" in val:
            return True
    return False


def _parse_single_server(
    name: str, config: dict
) -> McpServerConfig | None:
    """Parse a single server config entry."""
    command = config.get("command", "")
    if not command:
        # URL-based transport (SSE/HTTP).
        url = config.get("url", "")
        if url:
            transport = "sse" if "sse" in url.lower() else "http"
            return McpServerConfig(
                name=name,
                command="",
                url=url,
                transport=transport,
            )
        return None

    args = config.get("args", [])
    if not isinstance(args, list):
        args = [str(args)]

    env = config.get("env", {})
    if not isinstance(env, dict):
        env = {}

    return McpServerConfig(
        name=name,
        command=command,
        args=[str(a) for a in args],
        env={str(k): str(v) for k, v in env.items()},
        transport="stdio",
    )
