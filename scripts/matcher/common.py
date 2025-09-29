from __future__ import annotations

import logging
import os

from pathlib import Path

import requests


DEFAULT_REPO = "ton-blockchain/ton"
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')


def _github_raw_url(repo: str, revision: str, file_path: str) -> str:
    """
    Construct a raw.githubusercontent.com URL for a file in a GitHub repo.

    Args:
        repo: "owner/repo" (defaults to DEFAULT_REPO where used)
        revision: commit hash, tag, or branch name
        file_path: path within the repository (e.g. "crypto/vm/cellops.cpp")
    """
    return f"https://raw.githubusercontent.com/{repo}/{revision}/{file_path}"


def _latest_commit_sha_for_path(repo: str, revision: str, file_path: str) -> str:
    """
    Ask GitHub which is the latest commit (reachable from 'revision')
    that touched 'file_path'. If not found or API fails, fall back to 'revision'.
    """
    api_url = f"https://api.github.com/repos/{repo}/commits"
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN is not None:
        headers['Authorization'] = f"Bearer {GITHUB_TOKEN}"
    params = {
        "sha": revision,
        "path": file_path,
        "per_page": 1,
    }
    try:
        resp = requests.get(api_url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        commits = resp.json()
        if isinstance(commits, list) and commits:
            sha = commits[0].get("sha")
            if isinstance(sha, str) and sha:
                return sha
        logging.warning("GitHub commits API returned no commits for %s@%s:%s; using provided revision",
                        repo, revision, file_path)
    except Exception as exc:  # noqa: BLE001 - we want to fallback broadly here
        logging.warning("Failed to query GitHub commits API (%s); using provided revision", exc)
    return revision


def download_github_file(revision: str, file_path: str, repo: str = DEFAULT_REPO) -> tuple[str, str]:
    """
    Download a text file from GitHub raw by (repo, revision, file_path).

    Returns (response_text, url) and logs progress.
    """
    effective_sha = _latest_commit_sha_for_path(repo, revision, file_path)
    url = _github_raw_url(repo, effective_sha, file_path)
    logging.info("↳ fetching %s", url)
    headers = {}
    if GITHUB_TOKEN is not None:
        headers['Authorization'] = f"Bearer {GITHUB_TOKEN}"
    r = requests.get(url, timeout=30, headers=headers)
    r.raise_for_status()
    logging.info("  ✓ %s (%d bytes)", Path(file_path).name, len(r.text))
    return r.text, url 