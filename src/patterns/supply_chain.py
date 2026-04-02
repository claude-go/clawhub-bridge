"""Supply chain patterns — dependency hijack, custom indexes, typosquatting."""

from .types import Pattern, Severity

DEPENDENCY_HIJACK = [
    Pattern(
        "pip_custom_index",
        r"--index-url\s+(?!https://(pypi\.org|files\.pythonhosted\.org))\S+",
        Severity.CRITICAL,
        "Index pip personnalise (dependency hijack potentiel)",
    ),
    Pattern(
        "pip_extra_index",
        r"--extra-index-url\s+\S+",
        Severity.HIGH,
        "Extra index pip (confusion de dependances possible)",
    ),
    Pattern(
        "npm_custom_registry",
        r"registry\s*=\s*(?!https://registry\.npmjs\.org)\S+|--registry\s+(?!https://registry\.npmjs\.org)\S+",
        Severity.CRITICAL,
        "Registry npm personnalise (dependency hijack potentiel)",
    ),
    Pattern(
        "pip_install_url",
        r"pip\s+install\s+https?://(?!files\.pythonhosted\.org)\S+",
        Severity.HIGH,
        "Installation pip depuis URL directe",
    ),
    Pattern(
        "pip_install_git",
        r"pip\s+install\s+git\+",
        Severity.HIGH,
        "Installation pip depuis depot git",
    ),
    Pattern(
        "npm_install_url",
        r"npm\s+install\s+https?://\S+",
        Severity.HIGH,
        "Installation npm depuis URL directe",
    ),
    Pattern(
        "npm_install_git",
        r"npm\s+install\s+git(\+ssh|\+https)://",
        Severity.HIGH,
        "Installation npm depuis depot git",
    ),
    Pattern(
        "curl_pipe_install",
        r"curl\s+.*\|\s*(sudo\s+)?(bash|sh|python|pip)",
        Severity.CRITICAL,
        "Telecharge et execute directement (curl | bash)",
    ),
    Pattern(
        "wget_pipe_install",
        r"wget\s+.*-O\s*-\s*\|\s*(sudo\s+)?(bash|sh|python)",
        Severity.CRITICAL,
        "Telecharge et execute directement (wget | bash)",
    ),
]

SUPPLY_CHAIN_PATTERNS = DEPENDENCY_HIJACK
