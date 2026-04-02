"""Capability inference rules.

Each rule maps a regex pattern to a (ResourceType, AccessLevel) pair.
The analyzer applies all rules line-by-line to build a CapabilityProfile.
"""

from __future__ import annotations

from dataclasses import dataclass

from .types import AccessLevel, ResourceType

A = AccessLevel
R = ResourceType


@dataclass(frozen=True)
class CapRule:
    regex: str
    resource: ResourceType
    level: AccessLevel
    label: str


FILESYSTEM_RULES = [
    CapRule(r"\bcat\s+|less\s+|head\s+|tail\s+|more\s+", R.FILESYSTEM, A.READ, "file read"),
    CapRule(r"\bls\s+|find\s+|stat\s+|file\s+", R.FILESYSTEM, A.READ, "file listing"),
    CapRule(r"~\/\.ssh|\.ssh/|id_rsa|id_ed25519", R.FILESYSTEM, A.READ, "ssh key access"),
    CapRule(r"\.env|\.env\.\w+", R.FILESYSTEM, A.READ, "env file access"),
    CapRule(r"\bcp\s+|\bmv\s+|\btouch\s+", R.FILESYSTEM, A.WRITE, "file write/move"),
    CapRule(r"\bmkdir\s+", R.FILESYSTEM, A.WRITE, "directory creation"),
    CapRule(r">\s*\S|>>|tee\s+", R.FILESYSTEM, A.WRITE, "file output redirect"),
    CapRule(r"\brm\s+|\bunlink\s+|\brmdir\s+", R.FILESYSTEM, A.ADMIN, "file deletion"),
    CapRule(r"\bchmod\s+|\bchown\s+|\bchgrp\s+", R.FILESYSTEM, A.ADMIN, "permission change"),
    CapRule(r"\bdd\s+if=|\bmkfs\.\b|\bshred\s+", R.FILESYSTEM, A.ADMIN, "disk operation"),
]

NETWORK_RULES = [
    CapRule(r"\bcurl\s+.*https?://|\bwget\s+.*https?://", R.NETWORK, A.READ, "http fetch"),
    CapRule(r"\bcurl\s+.*-X\s+(POST|PUT|PATCH|DELETE)", R.NETWORK, A.WRITE, "http write"),
    CapRule(r"\bcurl\s+.*--(data|upload-file)", R.NETWORK, A.WRITE, "http upload"),
    CapRule(r"\bwget\s+--post-(data|file)", R.NETWORK, A.WRITE, "wget upload"),
    CapRule(r"\bnc\s+|\bnetcat\s+|\bncat\s+", R.NETWORK, A.WRITE, "netcat connection"),
    CapRule(r"\bnmap\s+|\bmasscan\s+|\bzmap\s+", R.NETWORK, A.READ, "port scan"),
    CapRule(r"\btcpdump\s+|\btshark\s+", R.NETWORK, A.ADMIN, "packet capture"),
    CapRule(r"\bssh\s+|\bscp\s+|\bsftp\s+", R.NETWORK, A.WRITE, "ssh connection"),
    CapRule(r"\.ngrok\.(io|app)|ngrok\s+(http|tcp)", R.NETWORK, A.ADMIN, "tunnel exposure"),
    CapRule(r"api\.telegram\.org|hooks\.slack\.com|discord\.com/api/webhooks", R.NETWORK, A.WRITE, "webhook call"),
]

ENV_RULES = [
    CapRule(r"\$\w+|\$\{\w+\}", R.ENV, A.READ, "env var read"),
    CapRule(r"\bexport\s+\w+=", R.ENV, A.WRITE, "env var set"),
    CapRule(r"\bunset\s+\w+", R.ENV, A.WRITE, "env var unset"),
    CapRule(r"\.aws/credentials|AWS_SECRET|AWS_SESSION_TOKEN", R.ENV, A.READ, "aws creds"),
    CapRule(r"\.config/gcloud|GOOGLE_APPLICATION_CREDENTIALS", R.ENV, A.READ, "gcp creds"),
    CapRule(r"\.azure/|AZURE_CLIENT_SECRET", R.ENV, A.READ, "azure creds"),
    CapRule(r"\.kube/config|KUBECONFIG", R.ENV, A.READ, "k8s config"),
]

SHELL_RULES = [
    CapRule(r"\beval\s*\(|\bexec\s*\(|\bFunction\s*\(", R.SHELL, A.ADMIN, "dynamic exec"),
    CapRule(r"\bbase64\s+-d.*\|\s*(bash|sh)", R.SHELL, A.ADMIN, "decode+exec"),
    CapRule(r"\bsudo\s+|\bdoas\s+|\bpkexec\s+", R.SHELL, A.ADMIN, "privilege escalation"),
    CapRule(r"\bcrontab\s+|\bcron\.d\b", R.SHELL, A.ADMIN, "cron manipulation"),
    CapRule(r"\bsystemctl\s+|\bservice\s+", R.SHELL, A.ADMIN, "service control"),
    CapRule(r"/dev/(tcp|udp)/", R.SHELL, A.ADMIN, "reverse shell"),
    CapRule(r"\bgit\s+push\s+(-f|--force)", R.SHELL, A.ADMIN, "force push"),
    CapRule(r"\bgit\s+reset\s+--hard", R.SHELL, A.ADMIN, "hard reset"),
    CapRule(r"\bgit\s+clone\s+|\bgit\s+pull\s+", R.SHELL, A.WRITE, "git write"),
    CapRule(r"\bgit\s+(status|log|diff|show)\b", R.SHELL, A.READ, "git read"),
]

SKILL_INVOKE_RULES = [
    CapRule(r"\bimport\s+\w+|\brequire\s*\(", R.SKILL_INVOKE, A.READ, "module import"),
    CapRule(r"\bpip\s+install\s+|\bnpm\s+install\s+", R.SKILL_INVOKE, A.WRITE, "package install"),
    CapRule(r"--index-url\s+|--extra-index-url\s+", R.SKILL_INVOKE, A.ADMIN, "custom package index"),
]

CLIPBOARD_RULES = [
    CapRule(r"\bpbcopy\b|\bpbpaste\b|\bxclip\b|\bxsel\b", R.CLIPBOARD, A.WRITE, "clipboard access"),
    CapRule(r"wl-copy|wl-paste", R.CLIPBOARD, A.WRITE, "wayland clipboard"),
]

BROWSER_RULES = [
    CapRule(r"\.config/(chromium|google-chrome)|Login\s*Data|Cookies", R.BROWSER, A.READ, "browser data read"),
    CapRule(r"\bplaywright\b|\bpuppeteer\b|\bselenium\b", R.BROWSER, A.WRITE, "browser automation"),
    CapRule(r"\.mozilla/firefox|\.config/BraveSoftware", R.BROWSER, A.READ, "browser profile"),
]

DATABASE_RULES = [
    CapRule(r"\bSELECT\s+.*\bFROM\b", R.DATABASE, A.READ, "sql select"),
    CapRule(r"\b(INSERT|UPDATE|MERGE)\s+", R.DATABASE, A.WRITE, "sql write"),
    CapRule(r"\b(DROP|TRUNCATE|DELETE\s+FROM)\s+", R.DATABASE, A.ADMIN, "sql destructive"),
    CapRule(r"\bsqlite3?\s+|\bpsql\s+|\bmysql\s+", R.DATABASE, A.READ, "db client"),
    CapRule(r"\.db\b|\.sqlite\b", R.DATABASE, A.READ, "db file access"),
]

ALL_RULES: list[CapRule] = (
    FILESYSTEM_RULES
    + NETWORK_RULES
    + ENV_RULES
    + SHELL_RULES
    + SKILL_INVOKE_RULES
    + CLIPBOARD_RULES
    + BROWSER_RULES
    + DATABASE_RULES
)
