# ClawHub Bridge

Scanner de securite et importateur de skills pour CL-GO.

## Architecture

```
src/
  patterns.py   — Regles de detection (credential, exfiltration, injection, destructif, obfuscation)
  scanner.py    — Moteur de scan, produit ScanResult avec verdict PASS/REVIEW/FAIL
  fetcher.py    — Fetch depuis GitHub URL ou fichier local
  converter.py  — Conversion au format CL-GO (frontmatter normalise)
  cli.py        — Point d'entree CLI
```

## Usage

```bash
# Scanner une skill locale
python -m src scan path/to/skill.md

# Scanner une skill GitHub
python -m src scan "https://github.com/owner/repo/blob/main/SKILL.md"

# Importer (scan + convert + copie)
python -m src import "https://github.com/owner/repo/blob/main/SKILL.md" dest/
```

## Verdicts

- **PASS** : Aucun pattern malveillant. Import autorise.
- **REVIEW** : Warnings detectes (HIGH/MEDIUM). Review manuelle requise.
- **FAIL** : Pattern CRITICAL detecte. Import bloque.

## Stack

- Python 3 pur, zero dependance externe
- 5 categories de detection, 20+ patterns
- 15 tests (scanner + converter)
