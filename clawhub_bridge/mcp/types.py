"""Data types for MCP server scanning."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class McpSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class McpServerConfig:
    """Parsed MCP server configuration."""

    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    transport: str = "stdio"
    url: str = ""

    @property
    def package_name(self) -> str:
        """Extract the likely package name from command+args."""
        if self.command in ("npx", "bunx"):
            for arg in self.args:
                if not arg.startswith("-"):
                    return arg
        if self.command in ("uvx", "pipx"):
            for arg in self.args:
                if not arg.startswith("-"):
                    return arg
        if self.command in ("node", "python", "python3"):
            for arg in self.args:
                if not arg.startswith("-"):
                    return arg
        return self.command


@dataclass
class McpFinding:
    """A security finding from MCP server analysis."""

    category: str
    severity: McpSeverity
    title: str
    description: str
    server_name: str = ""
    evidence: str = ""


@dataclass
class McpScanResult:
    """Result of scanning MCP server configuration."""

    server_name: str
    config: McpServerConfig
    findings: list[McpFinding] = field(default_factory=list)
    verdict: str = "PASS"

    def add(self, finding: McpFinding) -> None:
        finding.server_name = self.server_name
        self.findings.append(finding)
        if finding.severity == McpSeverity.CRITICAL:
            self.verdict = "FAIL"
        elif finding.severity == McpSeverity.HIGH:
            if self.verdict != "FAIL":
                self.verdict = "REVIEW"
        elif self.verdict == "PASS":
            self.verdict = "REVIEW"

    def to_dict(self) -> dict:
        return {
            "server_name": self.server_name,
            "verdict": self.verdict,
            "command": self.config.command,
            "package": self.config.package_name,
            "transport": self.config.transport,
            "total_findings": len(self.findings),
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
        }
