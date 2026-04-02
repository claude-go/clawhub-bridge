"""Capability analyzer — infers required permissions from skill content."""

from __future__ import annotations

import re

from .rules import ALL_RULES
from .types import Capability, CapabilityProfile


def analyze_capabilities(content: str) -> CapabilityProfile:
    """Analyze skill content and return inferred capability profile."""
    profile = CapabilityProfile()
    lines = content.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        for rule in ALL_RULES:
            if re.search(rule.regex, line, re.IGNORECASE):
                cap = Capability(
                    resource=rule.resource,
                    level=rule.level,
                    evidence=rule.label,
                    line_number=line_idx,
                )
                profile.add(cap)

    return profile
