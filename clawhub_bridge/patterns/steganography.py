"""Steganographic payload detection — hidden instructions in skill content.

Detects: homoglyph substitution, invisible characters, encoded payloads,
tag smuggling, whitespace encoding, punycode domains, mixed-script strings.

Extends beyond the basic bidi/zero-width patterns in extended.py.
"""

from .types import Pattern, Severity

HOMOGLYPH_SUBSTITUTION = [
    Pattern(
        "cyrillic_homoglyph",
        r"[\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u0458"
        r"\u04bb\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420"
        r"\u0421\u0422\u0425]",
        Severity.HIGH,
        "Caractere cyrillique homoglyphe detecte (substitution visuelle)",
    ),
    Pattern(
        "greek_homoglyph",
        r"[\u0391\u0392\u0395\u0396\u0397\u0399\u039a\u039c\u039d"
        r"\u039f\u03a1\u03a4\u03a5\u03a7\u03bf\u03b1\u03b5]",
        Severity.HIGH,
        "Caractere grec homoglyphe detecte (substitution visuelle)",
    ),
    Pattern(
        "fullwidth_latin",
        r"[\uff21-\uff3a\uff41-\uff5a]{2,}",
        Severity.MEDIUM,
        "Caracteres latin pleine largeur detectes (obfuscation)",
    ),
]

INVISIBLE_CHARACTERS = [
    Pattern(
        "single_zero_width",
        r"[\u200b\u200c\u200d\ufeff]",
        Severity.MEDIUM,
        "Caractere zero-width isole detecte (marqueur stego potentiel)",
    ),
    Pattern(
        "soft_hyphen_sequence",
        r"\u00ad{2,}|(?:\w\u00ad){3,}",
        Severity.HIGH,
        "Sequence de soft hyphens detectee (encodage stego)",
    ),
    Pattern(
        "word_joiner_abuse",
        r"\u2060{2,}|[\u2060\u200b]{3,}",
        Severity.HIGH,
        "Abus de word joiner detecte (canal cache)",
    ),
    Pattern(
        "interlinear_annotation",
        r"[\ufff9\ufffa\ufffb]",
        Severity.CRITICAL,
        "Annotation interlineaire Unicode (injection invisible)",
    ),
    Pattern(
        "tag_characters",
        r"[\U000e0001-\U000e007f]",
        Severity.CRITICAL,
        "Tag characters Unicode (payload invisible dans Plan 14)",
    ),
]

ENCODED_PAYLOADS = [
    Pattern(
        "base64_blob_long",
        r"(?:[A-Za-z0-9+/]{4}){16,}={0,2}",
        Severity.MEDIUM,
        "Blob base64 long detecte (payload encode potentiel)",
    ),
    Pattern(
        "hex_blob_long",
        r"(?:0x)?[0-9a-fA-F]{64,}",
        Severity.MEDIUM,
        "Blob hexadecimal long detecte (payload encode potentiel)",
    ),
    Pattern(
        "percent_encoded_sequence",
        r"(?:%[0-9a-fA-F]{2}){8,}",
        Severity.MEDIUM,
        "Sequence URL-encodee longue (payload obfusque)",
    ),
    Pattern(
        "unicode_escape_chain",
        r"(?:\\u[0-9a-fA-F]{4}){4,}",
        Severity.HIGH,
        "Chaine d'escapes Unicode (instructions cachees)",
    ),
]

TAG_SMUGGLING = [
    Pattern(
        "html_comment_instruction",
        r"<!--\s*(?:ignore|override|system|execute|inject|run"
        r"|fetch|send|forward|export)\b",
        Severity.CRITICAL,
        "Instruction cachee dans commentaire HTML",
    ),
    Pattern(
        "invisible_span",
        r"<span\s+[^>]*style\s*=\s*[\"'][^\"']*"
        r"(?:display\s*:\s*none|visibility\s*:\s*hidden|"
        r"font-size\s*:\s*0|opacity\s*:\s*0)[^\"']*[\"']",
        Severity.CRITICAL,
        "Span HTML invisible avec contenu cache",
    ),
    Pattern(
        "data_attribute_payload",
        r"data-(?:payload|cmd|exec|instruction|prompt)\s*=",
        Severity.HIGH,
        "Attribut data- suspect (payload dans metadata HTML)",
    ),
    Pattern(
        "markdown_html_injection",
        r"<(?:script|iframe|object|embed|applet|form|input)\b",
        Severity.CRITICAL,
        "Tag HTML dangereux dans contenu markdown",
    ),
]

WHITESPACE_ENCODING = [
    Pattern(
        "tab_space_alternation",
        r"(?:[ ]\t|\t[ ]){8,}",
        Severity.HIGH,
        "Alternance tab/espace suspecte (whitespace stego)",
    ),
    Pattern(
        "trailing_whitespace_pattern",
        r"[ \t]{20,}$",
        Severity.MEDIUM,
        "Whitespace trailing excessif (encodage potentiel)",
    ),
]

PUNYCODE_DOMAINS = [
    Pattern(
        "punycode_domain",
        r"\bxn--[a-z0-9]+-?[a-z0-9]*\.[a-z]{2,}",
        Severity.HIGH,
        "Domaine punycode detecte (homographe IDN potentiel)",
    ),
]

MIXED_SCRIPT = [
    Pattern(
        "confusable_url",
        r"https?://[^\s]*[\u0400-\u04ff][^\s]*\.[a-z]{2,}",
        Severity.CRITICAL,
        "URL avec melange scripts Latin/Cyrillique (homographe)",
    ),
]

STEGANOGRAPHY_PATTERNS = (
    HOMOGLYPH_SUBSTITUTION
    + INVISIBLE_CHARACTERS
    + ENCODED_PAYLOADS
    + TAG_SMUGGLING
    + WHITESPACE_ENCODING
    + PUNYCODE_DOMAINS
    + MIXED_SCRIPT
)
