"""Policy loading, parsing, and default template generation."""

from __future__ import annotations

import json
from pathlib import Path

from .patterns import Severity
from .policy import Policy, PolicyContext


def load_policy(path: str | Path) -> Policy:
    """Load a policy from a JSON file."""
    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    return parse_policy(data)


def parse_policy(data: dict) -> Policy:
    """Parse a policy from a dict."""
    version = str(data.get("version", "1"))
    default_ctx = data.get("default_context", "production")
    contexts: dict[str, PolicyContext] = {}

    for name, ctx_data in data.get("contexts", {}).items():
        contexts[name] = _parse_context(ctx_data)

    return Policy(
        contexts=contexts,
        default_context=default_ctx,
        version=version,
    )


def _parse_context(data: dict) -> PolicyContext:
    """Parse a single context definition."""
    return PolicyContext(
        block=_parse_severities(data.get("block", [])),
        review=_parse_severities(data.get("review", [])),
        max_findings=data.get("max_findings"),
        blocked_categories=set(data.get("blocked_categories", [])),
        allowed_patterns=set(data.get("allowed_patterns", [])),
    )


def _parse_severities(raw: list[str]) -> set[Severity]:
    """Convert severity strings to enum values."""
    result: set[Severity] = set()
    for s in raw:
        try:
            result.add(Severity(s.lower()))
        except ValueError:
            pass
    return result


DEFAULT_POLICY: dict = {
    "version": "1",
    "default_context": "production",
    "contexts": {
        "development": {
            "block": ["critical"],
            "review": ["high"],
            "max_findings": None,
            "blocked_categories": [],
            "allowed_patterns": [],
        },
        "staging": {
            "block": ["critical", "high"],
            "review": ["medium"],
            "max_findings": 20,
            "blocked_categories": ["steganography"],
            "allowed_patterns": [],
        },
        "production": {
            "block": ["critical", "high", "medium"],
            "review": ["low"],
            "max_findings": 0,
            "blocked_categories": [
                "steganography",
                "supply",
                "agent",
            ],
            "allowed_patterns": [],
        },
    },
}


def generate_default_policy() -> str:
    """Return the default policy as formatted JSON."""
    return json.dumps(DEFAULT_POLICY, indent=2, ensure_ascii=False)
