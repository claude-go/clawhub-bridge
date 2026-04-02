"""Fetch skills from GitHub URLs or local paths."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class FetchedSkill:
    name: str
    content: str
    source_url: str
    source_type: str  # "github", "local", "raw_url"
    metadata: dict


_GITHUB_RAW_RE = re.compile(
    r"github\.com/([^/]+)/([^/]+)/(?:blob/|tree/)?([^/]+)/(.*)"
)


def _validate_url(url: str) -> bool:
    return url.startswith("https://") and len(url) < 2048


def fetch_from_github(url: str, token: str | None = None) -> FetchedSkill:
    """Fetch a skill file from a GitHub repository URL."""
    if not _validate_url(url):
        raise ValueError("URL invalide ou non-HTTPS")

    match = _GITHUB_RAW_RE.match(url.replace("https://", ""))
    if not match:
        raise ValueError(f"URL GitHub non reconnue : {url}")

    owner, repo, branch, path = match.groups()
    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"

    headers = ["Accept: text/plain"]
    if token:
        headers.append(f"Authorization: token {token}")

    cmd = ["curl", "-sS", "-f", "--max-time", "15"]
    for h in headers:
        cmd.extend(["-H", h])
    cmd.append(raw_url)

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=20
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Echec du telechargement (code {result.returncode})"
        )

    content = result.stdout
    if not content.strip():
        raise RuntimeError("Fichier vide recupere")

    return FetchedSkill(
        name=Path(path).stem,
        content=content,
        source_url=url,
        source_type="github",
        metadata={"owner": owner, "repo": repo, "branch": branch, "path": path},
    )


def fetch_from_local(filepath: str) -> FetchedSkill:
    """Load a skill from a local file path."""
    path = Path(filepath).resolve()

    if ".." in path.parts:
        raise ValueError("Traversee de chemin interdite")

    if not path.is_file():
        raise FileNotFoundError(f"Fichier introuvable : {filepath}")

    if path.stat().st_size > 500_000:
        raise ValueError("Fichier trop volumineux (max 500 Ko)")

    content = path.read_text(encoding="utf-8")
    return FetchedSkill(
        name=path.stem,
        content=content,
        source_url=str(path),
        source_type="local",
        metadata={"path": str(path)},
    )


def fetch_skill(source: str, token: str | None = None) -> FetchedSkill:
    """Auto-detect source type and fetch the skill."""
    if source.startswith("https://github.com"):
        return fetch_from_github(source, token)
    return fetch_from_local(source)
