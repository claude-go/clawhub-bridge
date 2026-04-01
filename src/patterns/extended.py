"""Extended detection patterns — privilege escalation, network recon, reverse shell, webhook, unicode."""

from .types import Pattern, Severity

PRIVILEGE_ESCALATION = [
    Pattern(
        "sudo_doas",
        r"\b(sudo|doas|pkexec)\s+",
        Severity.HIGH,
        "Escalade de privileges detectee (sudo/doas/pkexec)",
    ),
    Pattern(
        "setuid_chmod",
        r"chmod\s+[ugo]*\+s|chmod\s+[0-7]*[4-7][0-7]{2}\s",
        Severity.CRITICAL,
        "Modification setuid/setgid detectee",
    ),
    Pattern(
        "crontab_persist",
        r"crontab\s+-[elr]|\bcron\.d\b|/etc/crontab",
        Severity.HIGH,
        "Manipulation crontab (persistance potentielle)",
    ),
]

NETWORK_RECON = [
    Pattern(
        "port_scan",
        r"\b(nmap|masscan|zmap)\s+",
        Severity.HIGH,
        "Scan de ports detecte",
    ),
    Pattern(
        "network_enum",
        r"\b(netstat|ss)\s+.*-[a-z]*[tul]|ifconfig\s+.*promisc",
        Severity.MEDIUM,
        "Enumeration reseau detectee",
    ),
    Pattern(
        "packet_capture",
        r"\b(tcpdump|tshark|wireshark)\s+",
        Severity.HIGH,
        "Capture de paquets detectee",
    ),
]

REVERSE_SHELL = [
    Pattern(
        "bash_reverse_shell",
        r"bash\s+-i\s+>&\s*/dev/(tcp|udp)/",
        Severity.CRITICAL,
        "Reverse shell bash detecte",
    ),
    Pattern(
        "nc_reverse_shell",
        r"\b(nc|ncat|netcat)\s+.*-e\s+/(bin/)?(sh|bash)",
        Severity.CRITICAL,
        "Reverse shell netcat detecte",
    ),
    Pattern(
        "python_reverse_shell",
        r"socket\.connect\s*\(.*\)\s*.*subprocess|import\s+pty.*spawn",
        Severity.CRITICAL,
        "Reverse shell Python detecte",
    ),
    Pattern(
        "perl_ruby_reverse_shell",
        r"perl\s+-e\s+.*socket.*exec|ruby\s+-r\s*socket\s+-e",
        Severity.CRITICAL,
        "Reverse shell Perl/Ruby detecte",
    ),
]

WEBHOOK_EXFIL = [
    Pattern(
        "discord_webhook",
        r"discord(app)?\.com/api/webhooks/\d+",
        Severity.CRITICAL,
        "URL webhook Discord hardcodee (exfiltration potentielle)",
    ),
    Pattern(
        "slack_webhook",
        r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+",
        Severity.CRITICAL,
        "URL webhook Slack hardcodee (exfiltration potentielle)",
    ),
    Pattern(
        "telegram_bot_api",
        r"api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]+",
        Severity.CRITICAL,
        "Token bot Telegram hardcode (exfiltration potentielle)",
    ),
    Pattern(
        "ngrok_tunnel",
        r"\bngrok\s+(http|tcp|tls)|[a-z0-9]+\.ngrok\.(io|app)",
        Severity.HIGH,
        "Tunnel ngrok detecte (exposition reseau)",
    ),
]

UNICODE_OBFUSCATION = [
    Pattern(
        "bidi_override",
        r"[\u202a-\u202e\u2066-\u2069\u200f\u200e]",
        Severity.CRITICAL,
        "Caractere Unicode bidi override (masquage de code)",
    ),
    Pattern(
        "zero_width_chars",
        r"[\u200b\u200c\u200d\ufeff]{2,}",
        Severity.HIGH,
        "Sequence de caracteres zero-width (payload cache)",
    ),
]

EXTENDED_PATTERNS = (
    PRIVILEGE_ESCALATION
    + NETWORK_RECON
    + REVERSE_SHELL
    + WEBHOOK_EXFIL
    + UNICODE_OBFUSCATION
)
