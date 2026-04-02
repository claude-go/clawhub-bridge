"""Capability lattice — infers required permissions for agent skills."""

from .types import AccessLevel, ResourceType, Capability, CapabilityProfile
from .analyzer import analyze_capabilities

__all__ = [
    "AccessLevel",
    "ResourceType",
    "Capability",
    "CapabilityProfile",
    "analyze_capabilities",
]
