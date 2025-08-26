from __future__ import annotations

import logging
from pathlib import Path

import requests


DEFAULT_REPO = "ton-blockchain/ton"


def github_raw_url(repo: str, revision: str, file_path: str) -> str:
    """
    Construct a raw.githubusercontent.com URL for a file in a GitHub repo.

    Args:
        repo: "owner/repo" (defaults to DEFAULT_REPO where used)
        revision: commit hash, tag, or branch name
        file_path: path within the repository (e.g. "crypto/vm/cellops.cpp")
    """
    return f"https://raw.githubusercontent.com/{repo}/{revision}/{file_path}"


def download_github_file(revision: str, file_path: str, repo: str = DEFAULT_REPO) -> tuple[str, str]:
    """
    Download a text file from GitHub raw by (repo, revision, file_path).

    Returns (response_text, url) and logs progress.
    """
    url = github_raw_url(repo, revision, file_path)
    logging.info("↳ fetching %s", url)
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    logging.info("  ✓ %s (%d bytes)", Path(file_path).name, len(r.text))
    return r.text, url 