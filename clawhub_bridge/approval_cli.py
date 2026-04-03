"""CLI commands for approval validity tracking."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .approval import ApprovalEnvelope, check_approval, create_envelope
from .fetcher import fetch_skill
from .scanner import scan_content


def cmd_approve(args: argparse.Namespace) -> int:
    """Create an approval envelope for the current version of a skill."""
    skill = fetch_skill(args.source)
    result = scan_content(skill.content, source=args.source)
    envelope = create_envelope(result)

    out_path = args.output or f"{Path(args.source).stem}.approval.json"
    Path(out_path).write_text(envelope.to_json(), encoding="utf-8")
    print(f"Approval envelope created: {out_path}")
    print(f"  Verdict at approval: {envelope.verdict_at_approval}")
    print(f"  Findings accepted: {envelope.total_findings}")
    print(f"  Max severity: {envelope.max_accepted_severity}")
    if envelope.capability_ceiling:
        print(f"  Capability ceiling: {envelope.capability_ceiling}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Check a new skill version against an approval envelope."""
    raw = Path(args.envelope).read_text(encoding="utf-8")
    envelope = ApprovalEnvelope.from_json(raw)

    skill = fetch_skill(args.source)
    result = scan_content(skill.content, source=args.source)
    verdict = check_approval(envelope, result)

    if args.json:
        print(json.dumps(verdict.to_dict(), indent=2, ensure_ascii=False))
    else:
        symbol = "\u2705" if verdict.status == "valid" else "\u274c"
        print(f"{symbol} Approval: {verdict.status.upper()}")
        print(f"  Envelope from: {envelope.approved_source}")
        print(f"  Checked against: {args.source}")
        if verdict.reasons:
            print("  Invalidation reasons:")
            for r in verdict.reasons:
                print(f"    - {r}")

    return 1 if verdict.status == "invalidated" else 0
