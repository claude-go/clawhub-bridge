"""Irreversible action patterns.

Detects actions that cannot be undone once executed: financial
transactions, public communications, deployments, permanent
data deletion, access control changes, and service lifecycle.
"""

from .types import Pattern, Severity

FINANCIAL_TRANSACTIONS = [
    Pattern(
        "payment_api_call",
        r"stripe\.(charges?|payment.?intents?|invoices?)\.create"
        r"|paypal.*\/v[12]\/(payments|orders)"
        r"|braintree.*transaction\.sale",
        Severity.CRITICAL,
        "Appel API de paiement detecte — transaction financiere irreversible",
    ),
    Pattern(
        "crypto_transfer",
        r"(send|transfer).*\b(eth|btc|sol|usdt|usdc)\b"
        r"|web3\.(eth\.)?send_?transaction"
        r"|wallet\.send\b",
        Severity.CRITICAL,
        "Transfert crypto detecte — irreversible sur blockchain",
    ),
    Pattern(
        "subscription_create",
        r"stripe\.subscriptions?\.create"
        r"|create.?subscription"
        r"|recurring.?payment",
        Severity.HIGH,
        "Creation d'abonnement payant — engagement financier",
    ),
]

PUBLIC_COMMUNICATION = [
    Pattern(
        "send_email",
        r"\bsend_?mail\b|\bsmtp\.send\b"
        r"|sendgrid.*send\b|ses\.send.?email"
        r"|mailgun.*messages",
        Severity.HIGH,
        "Envoi d'email detecte — message irreversible une fois livre",
    ),
    Pattern(
        "social_media_post",
        r"(post|publish|tweet|toot|create_status)"
        r".*\b(twitter|x\.com|bluesky|mastodon|facebook|linkedin)\b"
        r"|api\.twitter\.com/.*statuses"
        r"|bsky\.social.*createRecord",
        Severity.HIGH,
        "Publication sur reseau social — visible publiquement",
    ),
    Pattern(
        "github_issue_pr_create",
        r"gh\s+(issue|pr)\s+create"
        r"|api\.github\.com.*\/(issues|pulls)\b.*POST",
        Severity.MEDIUM,
        "Creation d'issue/PR GitHub — visible publiquement",
    ),
    Pattern(
        "messaging_send",
        r"(slack|discord|teams).*\.(post_?message|send|chat\.post)"
        r"|telegram.*send_?message"
        r"|whatsapp.*messages",
        Severity.MEDIUM,
        "Envoi de message sur plateforme de communication",
    ),
]

DEPLOYMENT_PUBLISHING = [
    Pattern(
        "package_publish",
        r"\bnpm\s+publish\b|\bpip\s+upload\b|\bcargo\s+publish\b"
        r"|\btwine\s+upload\b|\buv\s+publish\b"
        r"|\bgem\s+push\b",
        Severity.CRITICAL,
        "Publication de package — irreversible sur registre public",
    ),
    Pattern(
        "container_push",
        r"\bdocker\s+push\b|\bpodman\s+push\b"
        r"|crane\s+push|skopeo\s+copy",
        Severity.CRITICAL,
        "Push d'image container — visible sur registre",
    ),
    Pattern(
        "deploy_production",
        r"\bwrangler\s+deploy\b|\bwrangler\s+pages\s+deploy\b"
        r"|\bvercel\s+(--prod|deploy)\b"
        r"|\bnetlify\s+deploy\s+--prod\b"
        r"|\bheroku\s+.*deploy\b"
        r"|\bgcloud\s+.*deploy\b"
        r"|\baws\s+.*deploy\b",
        Severity.CRITICAL,
        "Deploiement production detecte — service expose publiquement",
    ),
    Pattern(
        "github_release_create",
        r"gh\s+release\s+create"
        r"|api\.github\.com.*\/releases.*POST",
        Severity.HIGH,
        "Creation de release GitHub — visible publiquement",
    ),
]

PERMANENT_DATA_LOSS = [
    Pattern(
        "database_drop",
        r"\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\b",
        Severity.CRITICAL,
        "Suppression de structure de base de donnees — perte permanente",
    ),
    Pattern(
        "database_truncate",
        r"\bTRUNCATE\s+TABLE\b",
        Severity.CRITICAL,
        "Truncate de table — suppression totale des donnees",
    ),
    Pattern(
        "delete_without_where",
        r"\bDELETE\s+FROM\s+\w+\s*;",
        Severity.CRITICAL,
        "DELETE sans clause WHERE — suppression totale des donnees",
    ),
    Pattern(
        "bucket_delete",
        r"(aws\s+s3|gsutil|az\s+storage)\s+.*\b(rm|delete|rb)\b.*--recursive"
        r"|r2\s+.*delete",
        Severity.CRITICAL,
        "Suppression recursive de bucket/storage — perte de donnees",
    ),
]

ACCESS_CONTROL_CHANGES = [
    Pattern(
        "account_deletion",
        r"(delete|remove|destroy).?(account|user|profile)\b"
        r"|api.*\/accounts?\/.*DELETE",
        Severity.CRITICAL,
        "Suppression de compte — irreversible sans backup",
    ),
    Pattern(
        "credential_revoke",
        r"(revoke|invalidate|rotate).?(token|key|credential|permission)\b"
        r"|ssh-keygen\s+-R",
        Severity.HIGH,
        "Revocation de credentials — acces coupe immediatement",
    ),
    Pattern(
        "password_change_external",
        r"(change|reset|update).?password\b.*api"
        r"|\/auth\/.*password.*PUT",
        Severity.HIGH,
        "Changement de mot de passe via API externe",
    ),
]

SERVICE_LIFECYCLE = [
    Pattern(
        "terminate_instance",
        r"(aws\s+ec2|gcloud\s+compute).*terminate"
        r"|kubectl\s+delete\s+(pod|deployment|namespace)"
        r"|docker\s+(rm|kill)\s+",
        Severity.HIGH,
        "Terminaison d'instance/container — service arrete",
    ),
    Pattern(
        "dns_record_change",
        r"(route53|cloudflare|gcloud\s+dns).*\b(delete|update|change)\b"
        r"|dns.*record.*(delete|update)",
        Severity.HIGH,
        "Modification de record DNS — impact sur routage",
    ),
    Pattern(
        "close_merge_pr",
        r"gh\s+pr\s+(merge|close)"
        r"|api\.github\.com.*\/pulls\/\d+\/(merge|update)",
        Severity.MEDIUM,
        "Merge/fermeture de PR — historique git modifie",
    ),
]

IRREVERSIBLE_PATTERNS = (
    FINANCIAL_TRANSACTIONS
    + PUBLIC_COMMUNICATION
    + DEPLOYMENT_PUBLISHING
    + PERMANENT_DATA_LOSS
    + ACCESS_CONTROL_CHANGES
    + SERVICE_LIFECYCLE
)
