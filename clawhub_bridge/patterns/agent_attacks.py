"""Agent-specific attack patterns — memory poisoning, config hijack, recursive spawn."""

from .types import Pattern, Severity

MEMORY_POISONING = [
    Pattern(
        "claude_md_overwrite",
        r"(>>?|write|echo\s+.*>)\s*.*CLAUDE\.md|Write\s*\(.*CLAUDE\.md",
        Severity.CRITICAL,
        "Tentative d'ecriture dans CLAUDE.md (empoisonnement memoire agent)",
    ),
    Pattern(
        "agent_memory_inject",
        r"(>>?|write|echo\s+.*>)\s*.*(memory|memories|knowledge)/.*\.(md|json|yaml)",
        Severity.CRITICAL,
        "Injection dans les fichiers memoire agent",
    ),
    Pattern(
        "rules_directory_inject",
        r"(>>?|write|echo\s+.*>)\s*.*\.claude/(rules|settings)",
        Severity.CRITICAL,
        "Injection dans les regles ou config Claude Code",
    ),
]

CONFIG_HIJACK = [
    Pattern(
        "settings_json_modify",
        r"(>>?|write|echo\s+.*>)\s*.*\.claude/settings\.json|\"allowedTools\"|\"permissions\"",
        Severity.CRITICAL,
        "Modification des permissions/settings de l'agent",
    ),
    Pattern(
        "mcp_config_inject",
        r"(>>?|write|echo\s+.*>)\s*.*(mcp|servers).*\.(json|yaml)|mcpServers|\"command\":\s*\"",
        Severity.HIGH,
        "Injection dans la config MCP (ajout de serveur malveillant)",
    ),
    Pattern(
        "hook_hijack",
        r"\"hooks\"|PreToolUse|PostToolUse|UserPromptSubmit|\"command\":\s*\[",
        Severity.HIGH,
        "Manipulation des hooks agent (execution automatique)",
    ),
]

RECURSIVE_SPAWN = [
    Pattern(
        "infinite_agent_loop",
        r"Agent\s*\(.*Agent\s*\(|spawn.*agent.*spawn|recursive.*agent",
        Severity.HIGH,
        "Boucle recursive d'agents potentielle (DoS)",
    ),
    Pattern(
        "mass_agent_spawn",
        r"for\s+.*in\s+.*:\s*.*Agent\s*\(|while.*Agent\s*\(",
        Severity.HIGH,
        "Creation d'agents en masse (DoS potentiel)",
    ),
]

INSTRUCTION_SMUGGLING = [
    Pattern(
        "data_instruction_inject",
        r"<system>|<system-reminder>|<IMPORTANT>|<instruction>",
        Severity.CRITICAL,
        "Injection d'instructions deguisees en balises systeme",
    ),
    Pattern(
        "invisible_text_css",
        r"font-size:\s*0|color:\s*(white|#fff|transparent)|opacity:\s*0[^.]|display:\s*none",
        Severity.HIGH,
        "Texte invisible via CSS (instructions cachees)",
    ),
    Pattern(
        "markdown_comment_inject",
        r"\[//\]:\s*#\s*\(.*?(execute|run|curl|sudo|rm\s)",
        Severity.CRITICAL,
        "Injection dans un commentaire Markdown",
    ),
]

AGENT_ATTACK_PATTERNS = (
    MEMORY_POISONING + CONFIG_HIJACK + RECURSIVE_SPAWN + INSTRUCTION_SMUGGLING
)
