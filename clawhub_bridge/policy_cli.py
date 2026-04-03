"""CLI commands for policy management."""

from __future__ import annotations

import argparse
import json
import sys

from .policy_loader import generate_default_policy, load_policy


def cmd_policy(args: argparse.Namespace) -> int:
    """Policy management: init or validate."""
    if args.policy_command == "init":
        print(generate_default_policy())
        return 0
    elif args.policy_command == "validate":
        return _validate_policy(args.path)
    else:
        print("Usage: clawhub policy {init|validate}", file=sys.stderr)
        return 1


def _validate_policy(path: str) -> int:
    """Validate a policy file and report its contents."""
    try:
        policy = load_policy(path)
        ctx_names = list(policy.contexts.keys())
        default = policy.default_context
        print(f"Valid policy v{policy.version}")
        print(f"  Contexts: {', '.join(ctx_names)}")
        print(f"  Default: {default}")
        if default not in policy.contexts:
            print(
                f"  WARNING: default context '{default}' not defined",
                file=sys.stderr,
            )
            return 1
        return 0
    except (json.JSONDecodeError, KeyError) as exc:
        print(f"Invalid policy: {exc}", file=sys.stderr)
        return 1
