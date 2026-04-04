"""MCP server security analyzer.

Analyzes MCP server configs for:
- Supply chain risks (unknown packages, package managers)
- Dangerous command patterns (shell, admin, filesystem)
- Hardcoded secrets in env vars
- Transport security (HTTP vs stdio)
- Permission scope (based on server name and args)"""

from __future__ import annotations

import re

from .types import McpFinding, McpScanResult, McpServerConfig, McpSeverity

# Packages with known dangerous capabilities.
_DANGEROUS_PACKAGES = {
    "mcp-server-shell": "shell execution",
    "mcp-shell-server": "shell execution",
    "@anthropic/mcp-server-filesystem": "filesystem access",
    "mcp-server-filesystem": "filesystem access",
    "mcp-server-exec": "command execution",
    "mcp-server-terminal": "terminal access",
}

# Suspicious patterns in package names.
_SUSPICIOUS_PKG_PATTERNS = [
    (r"typosquat", "possible typosquatting"),
    (r"^@[^/]+/[^/]+-[^/]+-[^/]+-[^/]+", "excessively segmented name"),
    (r"[^\x00-\x7f]", "non-ASCII characters in package name"),
]

# Dangerous argument patterns.
_DANGEROUS_ARG_PATTERNS = [
    (r"--allow-write", "write access enabled"),
    (r"--allow-delete", "delete access enabled"),
    (r"--no-sandbox", "sandboxing disabled"),
    (r"--unsafe", "unsafe mode enabled"),
    (r"--privileged", "privileged mode"),
    (r"/etc/", "system config path access"),
    (r"~/?\.ssh", "SSH key access"),
    (r"~/?\.aws", "AWS credential access"),
    (r"~/?\.env", "env file access"),
]

# Secret patterns in env values.
_SECRET_PATTERNS = [
    r"sk-[a-zA-Z0-9]{20,}",  # OpenAI-style keys.
    r"ghp_[a-zA-Z0-9]{36}",  # GitHub PATs.
    r"AKIA[A-Z0-9]{16}",  # AWS access keys.
    r"xox[bprs]-[a-zA-Z0-9-]+",  # Slack tokens.
]


def analyze_mcp_server(config: McpServerConfig) -> McpScanResult:
    """Analyze an MCP server config for security issues."""
    result = McpScanResult(
        server_name=config.name, config=config
    )
    _check_command(config, result)
    _check_package(config, result)
    _check_args(config, result)
    _check_env(config, result)
    _check_transport(config, result)
    return result


def _check_command(
    config: McpServerConfig, result: McpScanResult
) -> None:
    """Check the command binary for risks."""
    cmd = config.command.lower()
    if cmd in ("sh", "bash", "zsh", "cmd", "powershell"):
        result.add(McpFinding(
            category="command_risk",
            severity=McpSeverity.CRITICAL,
            title="MCP server runs directly in shell",
            description=(
                f"Server '{config.name}' uses {cmd} as "
                "command — arbitrary shell execution"
            ),
            evidence=config.command,
        ))
    elif cmd in ("docker", "podman"):
        result.add(McpFinding(
            category="command_risk",
            severity=McpSeverity.MEDIUM,
            title="MCP server runs in container runtime",
            description=(
                f"Server '{config.name}' uses {cmd} — "
                "check container privileges"
            ),
            evidence=config.command,
        ))


def _check_package(
    config: McpServerConfig, result: McpScanResult
) -> None:
    """Check the package name for supply chain risks."""
    pkg = config.package_name
    if not pkg:
        return
    if pkg in _DANGEROUS_PACKAGES:
        cap = _DANGEROUS_PACKAGES[pkg]
        result.add(McpFinding(
            category="dangerous_capability",
            severity=McpSeverity.HIGH,
            title=f"Package with {cap} capability",
            description=(
                f"'{pkg}' provides {cap}. "
                "Ensure this is intentional."
            ),
            evidence=pkg,
        ))
    for pattern, desc in _SUSPICIOUS_PKG_PATTERNS:
        if re.search(pattern, pkg, re.IGNORECASE):
            result.add(McpFinding(
                category="supply_chain",
                severity=McpSeverity.HIGH,
                title=f"Suspicious package name: {desc}",
                description=(
                    f"Package '{pkg}' matches suspicious "
                    f"pattern: {desc}"
                ),
                evidence=pkg,
            ))


def _check_args(
    config: McpServerConfig, result: McpScanResult
) -> None:
    """Check command arguments for dangerous patterns."""
    args_str = " ".join(config.args)
    for pattern, desc in _DANGEROUS_ARG_PATTERNS:
        if re.search(pattern, args_str, re.IGNORECASE):
            result.add(McpFinding(
                category="dangerous_args",
                severity=McpSeverity.HIGH,
                title=f"Dangerous argument: {desc}",
                description=(
                    f"Server '{config.name}' uses argument "
                    f"that enables {desc}"
                ),
                evidence=re.search(
                    pattern, args_str, re.IGNORECASE
                ).group()[:50],
            ))


def _check_env(
    config: McpServerConfig, result: McpScanResult
) -> None:
    """Check env vars for hardcoded secrets."""
    for key, value in config.env.items():
        for secret_pat in _SECRET_PATTERNS:
            if re.search(secret_pat, value):
                result.add(McpFinding(
                    category="hardcoded_secret",
                    severity=McpSeverity.CRITICAL,
                    title=(
                        f"Hardcoded secret in env var {key}"
                    ),
                    description=(
                        "Secret value found in MCP server "
                        "config. Use env var references "
                        "or keychain instead."
                    ),
                    evidence=f"{key}=***REDACTED***",
                ))
                break


def _check_transport(
    config: McpServerConfig, result: McpScanResult
) -> None:
    """Check transport security."""
    if config.transport in ("http", "sse"):
        if config.url.startswith("http://"):
            result.add(McpFinding(
                category="transport_security",
                severity=McpSeverity.HIGH,
                title="MCP server uses unencrypted HTTP",
                description=(
                    f"Server '{config.name}' communicates "
                    "over plain HTTP. Use HTTPS or stdio."
                ),
                evidence=config.url[:50],
            ))
