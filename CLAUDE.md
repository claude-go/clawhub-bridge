# ClawHub Bridge

Security scanner and capability analyzer for AI agent skills. pip-installable.

## Architecture

```
clawhub_bridge/
  patterns/
    types.py         — Pattern, Severity (dataclasses)
    core.py          — 5 categories (credential, exfiltration, injection, destructif, obfuscation)
    extended.py      — 5 categories (privilege escalation, network recon, reverse shell, webhook, unicode)
    infra.py         — 2 categories (container escape, cloud credential harvesting)
    supply_chain.py  — 1 categorie (dependency hijack, curl|bash, custom indexes)
    persistence.py   — 2 categories (system services, shell init persistence)
    agent_attacks.py    — 4 categories (memory poisoning, config hijack, recursive spawn, instruction smuggling)
    a2a_delegation.py   — 4 categories (permission bypass, identity violation, chain obfuscation, cross-agent leakage)
    __init__.py         — Agregation ALL_PATTERNS
  capabilities/
    types.py         — AccessLevel (NONE<READ<WRITE<ADMIN), ResourceType (8 types), CapabilityProfile
    rules.py         — Regles d'inference capabilities par type de ressource
    analyzer.py      — Moteur d'inference, produit CapabilityProfile
    __init__.py      — Exports
  scanner.py         — Moteur de scan, produit ScanResult avec verdict + capabilities
  fetcher.py         — Fetch depuis GitHub URL ou fichier local
  converter.py       — Conversion au format CL-GO (frontmatter normalise)
  report.py          — Terminal output formatting with ANSI colors
  cli.py             — CLI entry point (argparse)
  __init__.py        — Public API exports
pyproject.toml       — hatchling build, CLI entry point "clawhub"
```

## Usage

```bash
# Install
pip install git+https://github.com/claude-go/clawhub-bridge.git

# CLI
clawhub scan path/to/skill.md
clawhub scan ./skills/              # scan directory
clawhub scan ./skills/ --json       # JSON output for CI
clawhub import "https://github.com/..." dest/

# Python API
from clawhub_bridge import scan_content
result = scan_content(code, source="skill.md")
```

## Verdicts

- **PASS** : No malicious patterns. Import authorized.
- **REVIEW** : HIGH/MEDIUM findings. Manual review required.
- **FAIL** : CRITICAL pattern detected. Import blocked.

## Stack

- Python 3.10+, zero external dependencies
- 23 detection categories, 87 patterns
- Capability lattice: 4 levels (NONE<READ<WRITE<ADMIN) x 8 resources
- 146 tests
- GitHub Action (composite, action.yml at root)
- PyPI-ready (hatchling build)
