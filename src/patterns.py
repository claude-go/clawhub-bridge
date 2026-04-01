"""Detection patterns for malicious skill content."""

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: str
    severity: Severity
    description: str


CREDENTIAL_HARVEST = [
    Pattern(
        "ssh_key_access",
        r"~\/\.ssh|id_rsa|id_ed25519|authorized_keys",
        Severity.CRITICAL,
        "Acces aux cles SSH detecte",
    ),
    Pattern(
        "browser_creds",
        r"\.config\/(chromium|google-chrome)|Login\s*Data|Cookies\.sqlite",
        Severity.CRITICAL,
        "Acces aux identifiants navigateur detecte",
    ),
    Pattern(
        "crypto_wallet",
        r"\.bitcoin|\.ethereum|wallet\.dat|\.gnupg\/private|seed\s*phrase",
        Severity.CRITICAL,
        "Acces aux wallets crypto detecte",
    ),
    Pattern(
        "env_file_read",
        r"cat\s+\.env|\.env\.local|\.env\.production",
        Severity.HIGH,
        "Lecture de fichiers .env detectee",
    ),
    Pattern(
        "keychain_access",
        r"security\s+find-(generic|internet)-password|keychain",
        Severity.CRITICAL,
        "Acces au keychain OS detecte",
    ),
]

EXFILTRATION = [
    Pattern(
        "curl_post_external",
        r"curl\s+.*(-X\s+POST|--data|--upload-file).*https?://",
        Severity.CRITICAL,
        "Envoi de donnees vers URL externe via curl",
    ),
    Pattern(
        "wget_upload",
        r"wget\s+--post-(data|file)",
        Severity.CRITICAL,
        "Upload via wget detecte",
    ),
    Pattern(
        "base64_encode_pipe",
        r"base64.*\|.*curl|base64.*\|\s*(nc|ncat|netcat)",
        Severity.CRITICAL,
        "Encodage base64 pipe vers reseau",
    ),
    Pattern(
        "dns_exfil",
        r"dig\s+.*\$|nslookup\s+.*\$|host\s+.*\$",
        Severity.HIGH,
        "Exfiltration DNS potentielle",
    ),
]

PROMPT_INJECTION = [
    Pattern(
        "ignore_instructions",
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|constraints)",
        Severity.CRITICAL,
        "Injection de prompt : ignorer les instructions",
    ),
    Pattern(
        "role_override",
        r"you\s+are\s+now\s+|from\s+now\s+on\s+you\s+are|act\s+as\s+if",
        Severity.HIGH,
        "Override de role detecte",
    ),
    Pattern(
        "system_prompt_leak",
        r"(print|show|display|reveal|output)\s+(your\s+)?(system\s+prompt|instructions)",
        Severity.HIGH,
        "Tentative de fuite du system prompt",
    ),
    Pattern(
        "hidden_instruction",
        r"<!--.*?(execute|run|curl|wget|rm\s|eval).*?-->",
        Severity.CRITICAL,
        "Instruction cachee dans commentaire HTML",
    ),
]

DESTRUCTIVE = [
    Pattern(
        "rm_recursive",
        r"rm\s+-(r|rf|fr)\s",
        Severity.CRITICAL,
        "Suppression recursive detectee",
    ),
    Pattern(
        "force_push",
        r"git\s+push\s+(-f|--force)",
        Severity.HIGH,
        "Force push detecte",
    ),
    Pattern(
        "reset_hard",
        r"git\s+reset\s+--hard",
        Severity.HIGH,
        "Reset hard detecte",
    ),
    Pattern(
        "disk_wipe",
        r"dd\s+if=|mkfs\.|fdisk|shred\s",
        Severity.CRITICAL,
        "Operation destructrice sur disque",
    ),
]

OBFUSCATION = [
    Pattern(
        "base64_decode_exec",
        r"base64\s+-d|base64\s+--decode.*\|\s*(bash|sh|eval|python)",
        Severity.CRITICAL,
        "Decodage base64 suivi d'execution",
    ),
    Pattern(
        "eval_dynamic",
        r"\beval\s*\(|exec\s*\(|Function\s*\(",
        Severity.HIGH,
        "Execution dynamique de code",
    ),
    Pattern(
        "hex_escape_sequence",
        r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}",
        Severity.HIGH,
        "Sequence hex longue (potentiel payload obfusque)",
    ),
]

ALL_PATTERNS: list[Pattern] = (
    CREDENTIAL_HARVEST
    + EXFILTRATION
    + PROMPT_INJECTION
    + DESTRUCTIVE
    + OBFUSCATION
)
