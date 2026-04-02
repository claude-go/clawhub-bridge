"""Types for detection patterns."""

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: str
    severity: Severity
    description: str
