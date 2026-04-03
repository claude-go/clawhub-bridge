"""Indirect exfiltration path patterns.

Detects non-obvious data exfiltration channels that bypass
direct network monitoring: rendered output, clipboard, git
staging, error messages, logging endpoints, and agent memory.
"""

from .types import Pattern, Severity

RENDERED_OUTPUT_EXFIL = [
    Pattern(
        "markdown_image_exfil",
        r"!\[.*?\]\(https?://.*?\$\{?[\w.]+\}?",
        Severity.CRITICAL,
        "Image markdown avec donnees dynamiques dans l'URL — exfil via rendu",
    ),
    Pattern(
        "html_img_exfil",
        r"<img\s+[^>]*src=[\"']https?://[^\"']*\$\{?[\w.]+\}?",
        Severity.CRITICAL,
        "Balise img HTML avec donnees dynamiques — exfil via rendu",
    ),
    Pattern(
        "dynamic_url_construction",
        r"(?:url|endpoint|href|src)\s*[=:]\s*[`\"']https?://.*?\+\s*(?:secret|token|key|password|api|cred|auth)",
        Severity.CRITICAL,
        "Construction d'URL avec concatenation de secret",
    ),
    Pattern(
        "iframe_data_injection",
        r"<iframe\s+[^>]*src=[\"']https?://[^\"']*(?:data|query|context|payload|param)=",
        Severity.HIGH,
        "Iframe avec parametres de donnees — canal d'exfil potentiel",
    ),
    Pattern(
        "link_with_encoded_data",
        r"\[.*?\]\(https?://.*?(?:base64|encode|data)=",
        Severity.HIGH,
        "Lien markdown avec donnees encodees dans l'URL",
    ),
]

CLIPBOARD_EXFIL = [
    Pattern(
        "clipboard_write",
        r"pbcopy|xclip|xsel\s+-[bi]|clip\.exe|Set-Clipboard|clipboard\.write",
        Severity.HIGH,
        "Ecriture dans le presse-papiers — staging pour exfil manuelle",
    ),
    Pattern(
        "clipboard_pipe_secret",
        r"(?:cat|echo|print)\s+.*(?:secret|token|key|password|cred).*\|\s*(?:pbcopy|xclip|xsel|clip)",
        Severity.CRITICAL,
        "Secret envoye dans le presse-papiers",
    ),
]

GIT_STAGING_EXFIL = [
    Pattern(
        "git_remote_add_exfil",
        r"git\s+remote\s+add\s+\w+\s+https?://(?!github\.com/(claude-go|Kevin-hDev))",
        Severity.HIGH,
        "Ajout de remote git non autorise — exfil potentielle via push",
    ),
    Pattern(
        "git_push_foreign_remote",
        r"git\s+push\s+(?!origin\b)(?!claude-go\b)\w+",
        Severity.HIGH,
        "Push vers remote non-standard — donnees envoyees hors perimetre",
    ),
    Pattern(
        "git_notes_exfil",
        r"git\s+notes\s+add\s+.*(?:secret|token|key|password|env|cred)",
        Severity.HIGH,
        "Secret stocke dans git notes — visible apres push",
    ),
]

ERROR_TRIGGERED_EXFIL = [
    Pattern(
        "error_with_secret_data",
        r"(?:throw|raise|Error|Exception)\s*\(?.*(?:secret|token|key|password|api_key|credentials)",
        Severity.HIGH,
        "Secret dans message d'erreur — fuite via error tracking",
    ),
    Pattern(
        "sentry_breadcrumb_secret",
        r"(?:Sentry|sentry|SENTRY).*(?:set_tag|set_extra|capture_message).*(?:secret|token|key|password|cred)",
        Severity.HIGH,
        "Secret envoye a Sentry comme tag/extra — exfil via monitoring",
    ),
]

LOGGING_ENDPOINT_EXFIL = [
    Pattern(
        "external_log_with_data",
        r"(?:datadog|newrelic|splunk|logstash|fluentd|elastic).*(?:secret|token|key|password|user_data|context)",
        Severity.HIGH,
        "Donnees sensibles envoyees a un service de logging externe",
    ),
    Pattern(
        "webhook_disguised_as_log",
        r"(?:log|notify|report|alert)\s*\(?\s*[\"']https?://",
        Severity.HIGH,
        "Appel HTTP deguise en log/notification — exfil dissimule",
    ),
]

AGENT_MEMORY_EXFIL = [
    Pattern(
        "write_secret_to_shared_memory",
        r"(?:write|save|store|persist|append)\s+(?:the\s+)?(?:secret|token|key|password|credential|api.?key)\s+(?:to|in|into)\s+(?:memory|file|shared|public|output)",
        Severity.CRITICAL,
        "Secret ecrit dans memoire/fichier partage — accessible par autres agents",
    ),
    Pattern(
        "exfil_via_tool_output",
        r"(?:include|embed|insert|add)\s+(?:the\s+)?(?:secret|token|key|password|credential)s?\s+(?:in|into|to)\s+(?:the\s+)?(?:output|response|report|result|summary)",
        Severity.HIGH,
        "Secret inclus dans sortie visible — exfil via canal de reponse",
    ),
    Pattern(
        "stage_data_for_retrieval",
        r"(?:save|write|store)\s+.*(?:for\s+later|temporary|tmp|temp)\s+(?:retrieval|access|collection|pickup)",
        Severity.MEDIUM,
        "Donnees stagees pour recuperation ulterieure — possible dead drop",
    ),
]

INDIRECT_EXFIL_PATTERNS = (
    RENDERED_OUTPUT_EXFIL
    + CLIPBOARD_EXFIL
    + GIT_STAGING_EXFIL
    + ERROR_TRIGGERED_EXFIL
    + LOGGING_ENDPOINT_EXFIL
    + AGENT_MEMORY_EXFIL
)
