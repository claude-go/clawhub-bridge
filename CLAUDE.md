# ClawHub Bridge

Scanner de securite et importateur de skills pour CL-GO.

## Architecture

```
src/
  patterns/
    types.py         — Pattern, Severity (dataclasses)
    core.py          — 5 categories (credential, exfiltration, injection, destructif, obfuscation)
    extended.py      — 5 categories (privilege escalation, network recon, reverse shell, webhook, unicode)
    infra.py         — 2 categories (container escape, cloud credential harvesting)
    supply_chain.py  — 1 categorie (dependency hijack, curl|bash, custom indexes)
    __init__.py      — Agregation ALL_PATTERNS
  capabilities/
    types.py         — AccessLevel (NONE<READ<WRITE<ADMIN), ResourceType (8 types), CapabilityProfile
    rules.py         — Regles d'inference capabilities par type de ressource
    analyzer.py      — Moteur d'inference, produit CapabilityProfile
    __init__.py      — Exports
  scanner.py         — Moteur de scan, produit ScanResult avec verdict + capabilities
  fetcher.py         — Fetch depuis GitHub URL ou fichier local
  converter.py       — Conversion au format CL-GO (frontmatter normalise)
  cli.py             — Point d'entree CLI
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

## Capability Lattice

Basé sur SkillFortify (arxiv 2603.00195). Chaque skill scannee produit un profil de capabilities :

- **4 niveaux** : NONE < READ < WRITE < ADMIN
- **8 ressources** : filesystem, network, env, shell, skill_invoke, clipboard, browser, database
- Inference automatique par analyse statique du contenu

## Stack

- Python 3 pur, zero dependance externe
- 13 categories de detection, 56+ patterns
- 91 tests (scanner + extended + container + cloud + supply chain + capabilities + converter)
