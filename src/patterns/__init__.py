"""Detection patterns for malicious skill content."""

from .types import Pattern, Severity
from .core import CORE_PATTERNS
from .extended import EXTENDED_PATTERNS
from .infra import INFRA_PATTERNS

ALL_PATTERNS: list[Pattern] = CORE_PATTERNS + EXTENDED_PATTERNS + INFRA_PATTERNS

__all__ = ["Pattern", "Severity", "ALL_PATTERNS"]
