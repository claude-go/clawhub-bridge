"""Types for the capability lattice.

Based on SkillFortify (arxiv 2603.00195):
- 4 access levels: NONE < READ < WRITE < ADMIN
- 8 resource types: filesystem, network, env, shell, skill_invoke,
  clipboard, browser, database
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, Enum


class AccessLevel(IntEnum):
    """Ordered lattice: NONE < READ < WRITE < ADMIN."""

    NONE = 0
    READ = 1
    WRITE = 2
    ADMIN = 3


class ResourceType(Enum):
    FILESYSTEM = "filesystem"
    NETWORK = "network"
    ENV = "env"
    SHELL = "shell"
    SKILL_INVOKE = "skill_invoke"
    CLIPBOARD = "clipboard"
    BROWSER = "browser"
    DATABASE = "database"


@dataclass(frozen=True)
class Capability:
    """A single inferred capability requirement."""

    resource: ResourceType
    level: AccessLevel
    evidence: str
    line_number: int


@dataclass
class CapabilityProfile:
    """Aggregated capability requirements for a skill."""

    capabilities: list[Capability] = field(default_factory=list)

    def add(self, cap: Capability) -> None:
        self.capabilities.append(cap)

    def max_level(self, resource: ResourceType) -> AccessLevel:
        """Return the highest access level for a resource type."""
        levels = [
            c.level for c in self.capabilities if c.resource == resource
        ]
        return max(levels) if levels else AccessLevel.NONE

    def summary(self) -> dict[str, str]:
        """Return {resource: max_access_level} for all touched resources."""
        result: dict[str, str] = {}
        for rt in ResourceType:
            level = self.max_level(rt)
            if level > AccessLevel.NONE:
                result[rt.value] = level.name
        return result

    def to_dict(self) -> dict:
        return {
            "profile": self.summary(),
            "details": [
                {
                    "resource": c.resource.value,
                    "level": c.level.name,
                    "evidence": c.evidence,
                    "line": c.line_number,
                }
                for c in self.capabilities
            ],
        }
