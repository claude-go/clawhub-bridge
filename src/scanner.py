"""Security scanner for agent skills."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .patterns import ALL_PATTERNS, Severity


@dataclass
class Finding:
    pattern_name: str
    severity: Severity
    description: str
    line_number: int
    matched_text: str
    context: str


@dataclass
class ScanResult:
    source: str
    findings: list[Finding] = field(default_factory=list)
    verdict: str = "PASS"
    summary: str = ""

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        if finding.severity == Severity.CRITICAL:
            self.verdict = "FAIL"
        elif finding.severity == Severity.HIGH and self.verdict != "FAIL":
            self.verdict = "REVIEW"
        elif self.verdict == "PASS":
            self.verdict = "REVIEW"

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "verdict": self.verdict,
            "summary": self.summary,
            "total_findings": len(self.findings),
            "by_severity": self._count_by_severity(),
            "findings": [
                {
                    "name": f.pattern_name,
                    "severity": f.severity.value,
                    "description": f.description,
                    "line": f.line_number,
                    "matched": f.matched_text,
                    "context": f.context,
                }
                for f in self.findings
            ],
        }

    def _count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            key = f.severity.value
            counts[key] = counts.get(key, 0) + 1
        return counts


def _get_context(lines: list[str], line_idx: int) -> str:
    start = max(0, line_idx - 1)
    end = min(len(lines), line_idx + 2)
    return "\n".join(lines[start:end])


def scan_content(content: str, source: str = "unknown") -> ScanResult:
    """Scan skill content for malicious patterns."""
    result = ScanResult(source=source)
    lines = content.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        for pattern in ALL_PATTERNS:
            compiled = re.compile(pattern.regex, re.IGNORECASE)
            match = compiled.search(line)
            if match:
                finding = Finding(
                    pattern_name=pattern.name,
                    severity=pattern.severity,
                    description=pattern.description,
                    line_number=line_idx,
                    matched_text=match.group()[:100],
                    context=_get_context(lines, line_idx - 1),
                )
                result.add(finding)

    result.summary = _build_summary(result)
    return result


def scan_file(filepath: str) -> ScanResult:
    """Scan a skill file for malicious patterns."""
    with open(filepath, encoding="utf-8") as f:
        content = f.read()
    return scan_content(content, source=filepath)


def _build_summary(result: ScanResult) -> str:
    if not result.findings:
        return "Aucun pattern malveillant detecte."

    counts = result._count_by_severity()
    parts = []
    for sev in ["critical", "high", "medium", "low"]:
        if sev in counts:
            parts.append(f"{counts[sev]} {sev.upper()}")

    detail = ", ".join(parts)
    if result.verdict == "FAIL":
        return f"BLOQUE — {detail}. Skill dangereuse, import refuse."
    return f"A VERIFIER — {detail}. Relecture manuelle recommandee."
