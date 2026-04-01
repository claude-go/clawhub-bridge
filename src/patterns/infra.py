"""Infrastructure patterns — container escape, cloud credential harvesting."""

from .types import Pattern, Severity

CONTAINER_ESCAPE = [
    Pattern(
        "docker_sock_access",
        r"/var/run/docker\.sock|docker\.sock",
        Severity.CRITICAL,
        "Acces au socket Docker (escape conteneur possible)",
    ),
    Pattern(
        "privileged_container",
        r"--privileged",
        Severity.CRITICAL,
        "Conteneur en mode privileged (acces complet a l'hote)",
    ),
    Pattern(
        "host_pid_namespace",
        r"--pid\s*=\s*host",
        Severity.CRITICAL,
        "Namespace PID hote (visibilite processus hote)",
    ),
    Pattern(
        "host_network_namespace",
        r"--(network|net)\s*=\s*host",
        Severity.HIGH,
        "Namespace reseau hote (acces reseau complet)",
    ),
    Pattern(
        "mount_host_sensitive",
        r"-v\s+/(?:etc|proc|sys|root|var/log)[:/]|--mount\s+.*source\s*=\s*/(?:etc|proc|sys|root)",
        Severity.CRITICAL,
        "Montage de repertoire sensible de l'hote dans conteneur",
    ),
    Pattern(
        "cap_sys_admin",
        r"--cap-add\s*=?\s*(SYS_ADMIN|ALL)",
        Severity.CRITICAL,
        "Ajout de capability SYS_ADMIN ou ALL (escape conteneur)",
    ),
]

CLOUD_CREDENTIAL_HARVEST = [
    Pattern(
        "aws_credentials",
        r"~/\.aws/credentials|\.aws/credentials|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN",
        Severity.CRITICAL,
        "Acces aux credentials AWS detecte",
    ),
    Pattern(
        "gcp_credentials",
        r"~/\.config/gcloud|\.config/gcloud|GOOGLE_APPLICATION_CREDENTIALS|gcloud\s+auth\s+print",
        Severity.CRITICAL,
        "Acces aux credentials GCP detecte",
    ),
    Pattern(
        "azure_credentials",
        r"~/\.azure|\.azure/accessTokens|AZURE_CLIENT_SECRET|AZURE_TENANT_ID.*AZURE_CLIENT",
        Severity.CRITICAL,
        "Acces aux credentials Azure detecte",
    ),
    Pattern(
        "kube_config",
        r"~/\.kube/config|\.kube/config|KUBECONFIG\s*=",
        Severity.CRITICAL,
        "Acces a la config Kubernetes detecte",
    ),
    Pattern(
        "terraform_state",
        r"\.tfstate|terraform\s+state\s+(pull|show)",
        Severity.HIGH,
        "Acces au state Terraform (peut contenir des secrets)",
    ),
    Pattern(
        "cloud_metadata_endpoint",
        r"169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com",
        Severity.CRITICAL,
        "Acces au endpoint metadata cloud (vol de credentials instance)",
    ),
]

INFRA_PATTERNS = CONTAINER_ESCAPE + CLOUD_CREDENTIAL_HARVEST
