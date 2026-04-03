"""clawhub-bridge — Security scanner for AI agent skills."""

from .scanner import scan_content, scan_file, ScanResult, Finding
from .patterns import ALL_PATTERNS, Severity
from .capabilities import (
    AccessLevel,
    ResourceType,
    CapabilityProfile,
    analyze_capabilities,
)
from .delta import compare, DeltaResult, CapabilityChange
from .approval import (
    ApprovalEnvelope,
    ApprovalVerdict,
    create_envelope,
    check_approval,
)
from .policy import (
    Policy,
    PolicyContext,
    PolicyVerdict,
    apply_policy,
)
from .policy_loader import load_policy, parse_policy
from .reachability import analyze_reachability, ReachabilityResult

__version__ = "5.0.0"

__all__ = [
    "scan_content",
    "scan_file",
    "ScanResult",
    "Finding",
    "ALL_PATTERNS",
    "Severity",
    "AccessLevel",
    "ResourceType",
    "CapabilityProfile",
    "analyze_capabilities",
    "compare",
    "DeltaResult",
    "CapabilityChange",
    "analyze_reachability",
    "ReachabilityResult",
    "ApprovalEnvelope",
    "ApprovalVerdict",
    "create_envelope",
    "check_approval",
    "Policy",
    "PolicyContext",
    "PolicyVerdict",
    "apply_policy",
    "load_policy",
    "parse_policy",
]
