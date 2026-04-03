"""A2A (agent-to-agent) delegation attack patterns.

Detects dangerous delegation patterns where one agent hands off
to another with escalated permissions, bypassed controls, or
obfuscated intent.
"""

from .types import Pattern, Severity

PERMISSION_BYPASS = [
    Pattern(
        "delegation_bypass_permissions",
        r"mode[\"'\s:=]+bypassPermissions|bypassPermissions[\"'\s:=]+true",
        Severity.CRITICAL,
        "Agent delegue avec bypass des permissions — aucun consentement utilisateur",
    ),
    Pattern(
        "delegation_dontask_mode",
        r"mode[\"'\s:=]+dontAsk|dontAsk[\"'\s:=]+true",
        Severity.HIGH,
        "Agent delegue en mode silencieux — actions sans approbation",
    ),
    Pattern(
        "delegation_sandbox_disable",
        r"dangerouslyDisableSandbox[\"'\s:=]+true",
        Severity.CRITICAL,
        "Sandbox desactive pour agent delegue — acces systeme complet",
    ),
    Pattern(
        "delegation_wildcard_tools",
        r"(?:allowedTools|allowed.tools)[\"'\s:=]+\[?\s*[\"']\*[\"']",
        Severity.CRITICAL,
        "Tous les outils accordes a l'agent delegue — aucune restriction",
    ),
]

IDENTITY_VIOLATION = [
    Pattern(
        "delegation_identity_spoof",
        r"(?:pretend|pose|impersonate|act)\s+(?:as|like)\s+(?:the\s+)?(?:user|human|admin|system|root)",
        Severity.CRITICAL,
        "Agent delegue usurpe l'identite utilisateur/admin/systeme",
    ),
    Pattern(
        "delegation_override_system",
        r"(?:ignore|override|replace|overwrite)\s+(?:all\s+)?(?:previous\s+)?(?:system|instructions|rules|constraints)",
        Severity.CRITICAL,
        "Agent delegue avec instruction d'ignorer les contraintes systeme",
    ),
]

CHAIN_OBFUSCATION = [
    Pattern(
        "delegation_deep_chain",
        r"(?:Agent|spawn|delegate|TeamCreate).*(?:Agent|spawn|delegate|TeamCreate).*(?:Agent|spawn|delegate|TeamCreate)",
        Severity.HIGH,
        "Chaine de delegation multi-niveaux — tracabilite perdue",
    ),
    Pattern(
        "delegation_background_write",
        r"run_in_background.*(?:Write|Edit|Bash|execute|rm\s|delete)|(?:Write|Edit|Bash|execute|rm\s|delete).*run_in_background",
        Severity.HIGH,
        "Agent arriere-plan avec operations d'ecriture/suppression",
    ),
    Pattern(
        "delegation_external_endpoint",
        r"(?:delegate|forward|send|proxy)\s+(?:to|via)\s+(?:https?://|external|remote|third.party)",
        Severity.HIGH,
        "Delegation vers endpoint externe — donnees hors perimetre",
    ),
]

CROSS_AGENT_LEAKAGE = [
    Pattern(
        "delegation_credential_forward",
        r"(?:pass|forward|send|include|share)\s+(?:the\s+)?(?:api.?key|token|password|secret|credential)s?\s+(?:to|with)\s+(?:the\s+)?(?:agent|subagent|teammate)",
        Severity.HIGH,
        "Transfert de credentials vers agent delegue — fuite de secrets",
    ),
    Pattern(
        "delegation_grant_full_access",
        r"(?:grant|give|allow|enable)\s+(?:full|unrestricted|complete|total|all)\s+(?:access|permission|control)",
        Severity.HIGH,
        "Acces complet accorde a l'agent delegue — sans limites",
    ),
]

A2A_DELEGATION_PATTERNS = (
    PERMISSION_BYPASS
    + IDENTITY_VIOLATION
    + CHAIN_OBFUSCATION
    + CROSS_AGENT_LEAKAGE
)
