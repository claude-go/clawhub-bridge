"""Persistence mechanism detection — system services, shell init, scheduled tasks."""

from .types import Pattern, Severity

SYSTEM_SERVICE_PERSIST = [
    Pattern(
        "systemd_service_create",
        r"(/etc/systemd|~/.config/systemd)/.*\.service|systemctl\s+(enable|daemon-reload)",
        Severity.CRITICAL,
        "Creation ou activation de service systemd (persistance)",
    ),
    Pattern(
        "launchagent_create",
        r"~/Library/LaunchAgents/.*\.plist|/Library/Launch(Agents|Daemons)/.*\.plist|launchctl\s+(load|bootstrap)",
        Severity.CRITICAL,
        "Creation ou chargement de LaunchAgent/LaunchDaemon macOS (persistance)",
    ),
    Pattern(
        "initd_script",
        r"/etc/init\.d/|update-rc\.d\s+|chkconfig\s+",
        Severity.CRITICAL,
        "Manipulation de script init.d (persistance legacy)",
    ),
    Pattern(
        "windows_autorun",
        r"HKLM\\.*\\Run|HKCU\\.*\\Run|reg\s+add\s+.*\\Run",
        Severity.CRITICAL,
        "Modification registre Windows autorun (persistance)",
    ),
]

SHELL_INIT_PERSIST = [
    Pattern(
        "shell_rc_modify",
        r">>?\s*~/?\.(bashrc|zshrc|bash_profile|zprofile|profile|zshenv)",
        Severity.HIGH,
        "Modification de fichier d'init shell (persistance)",
    ),
    Pattern(
        "ssh_authorized_keys_inject",
        r">>?\s*~?/\.ssh/authorized_keys|echo\s+.*>>?\s*.*authorized_keys",
        Severity.CRITICAL,
        "Injection dans SSH authorized_keys (acces persistant)",
    ),
    Pattern(
        "at_batch_schedule",
        r"\bat\s+(now|midnight|noon|\d+:\d+)|batch\s*<<",
        Severity.HIGH,
        "Planification via at/batch (execution differee)",
    ),
    Pattern(
        "xdg_autostart",
        r"~/.config/autostart/.*\.desktop|/etc/xdg/autostart/",
        Severity.HIGH,
        "Creation d'entree XDG autostart (persistance session)",
    ),
]

PERSISTENCE_PATTERNS = SYSTEM_SERVICE_PERSIST + SHELL_INIT_PERSIST
