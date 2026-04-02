"""Detection patterns for malicious skill content."""

from .types import Pattern, Severity
from .core import CORE_PATTERNS
from .extended import EXTENDED_PATTERNS
from .infra import INFRA_PATTERNS
from .supply_chain import SUPPLY_CHAIN_PATTERNS
from .persistence import PERSISTENCE_PATTERNS
from .agent_attacks import AGENT_ATTACK_PATTERNS

ALL_PATTERNS: list[Pattern] = (
    CORE_PATTERNS
    + EXTENDED_PATTERNS
    + INFRA_PATTERNS
    + SUPPLY_CHAIN_PATTERNS
    + PERSISTENCE_PATTERNS
    + AGENT_ATTACK_PATTERNS
)

__all__ = ["Pattern", "Severity", "ALL_PATTERNS"]
