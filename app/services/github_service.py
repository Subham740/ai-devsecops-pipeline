from __future__ import annotations

import os
from typing import Any


def _github_client(token: str | None = None):
    from github import Github

    api_token = token or os.getenv("GITHUB_TOKEN")
    if not api_token:
        raise RuntimeError("GITHUB_TOKEN is not configured.")
    return Github(api_token)


def list_repositories(token: str | None = None, limit: int = 30) -> list[dict[str, Any]]:
    github = _github_client(token)
    repos = []
    for repo in github.get_user().get_repos()[:limit]:
        repos.append(
            {
                "full_name": repo.full_name,
                "default_branch": repo.default_branch,
                "private": repo.private,
                "html_url": repo.html_url,
                "last_scan_status": "ready",
            }
        )
    return repos


def repository_snapshot(full_name: str, token: str | None = None) -> dict[str, Any]:
    if "/" not in full_name:
        raise ValueError("Repository must be in owner/name format.")
    repo = _github_client(token).get_repo(full_name)
    pulls = repo.get_pulls(state="open")
    commits = repo.get_commits()
    return {
        "full_name": repo.full_name,
        "default_branch": repo.default_branch,
        "private": repo.private,
        "html_url": repo.html_url,
        "open_pull_requests": pulls.totalCount,
        "latest_commit_sha": commits[0].sha if commits.totalCount else None,
        "latest_commit_message": commits[0].commit.message if commits.totalCount else None,
        "last_scan_status": "queued",
    }
