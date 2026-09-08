from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from ..utils.version_bump_resolver import VersionBump, get_version_bumps


def filter_security_dependency_pull_requests(
    owner: str,
    repo: str,
    pull_requests: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Compatibility helper used by older tests and callers.

    Keeps the bot-only filtering behavior and normalizes the fields needed by
    downstream security tooling.
    """
    results: list[dict[str, Any]] = []

    for pull_request in pull_requests:
        user = pull_request.get("user") or {}
        login = user.get("login", "")
        if "[bot]" not in login.lower():
            continue

        pr_number = pull_request.get("number")
        if not pr_number:
            continue

        title = pull_request.get("title", "")
        version_bumps = get_version_bumps(title, pull_request.get("body", ""))

        results.append(
            {
                "pr_number": pr_number,
                "pr_title": title,
                "pr_branch": (pull_request.get("head") or {}).get("ref", ""),
                "pull_url": pull_request.get("html_url", ""),
                "version_bumps": [bump.model_dump() for bump in version_bumps],
                "severity": "",
                "author": login,
            }
        )

    return results


@dataclass
class PullRequestMetadata:
    pr_number: int | None = None
    pr_title: str = ""
    pr_branch: str = ""
    pull_url: str = ""
    version_bumps: list[VersionBump] = field(default_factory=list)
    mergeable_state: str = ""
    author: str = ""

    def __getitem__(self, key: str) -> Any:
        return self.model_dump()[key]

    def model_dump(self) -> dict[str, Any]:
        return {
            "pr_number": self.pr_number,
            "pr_title": self.pr_title,
            "pr_branch": self.pr_branch,
            "pull_url": self.pull_url,
            "version_bumps": [
                bump.model_dump() if hasattr(bump, "model_dump") else bump
                for bump in self.version_bumps
            ],
            "severity": "",
            "author": self.author,
        }

    @classmethod
    def from_pull_request(
        cls,
        pull_request: dict[str, Any],
        version_bumps: list[VersionBump],
    ) -> "PullRequestMetadata":
        return cls(
            pr_number=pull_request.get("number"),
            pr_title=pull_request.get("title", ""),
            pr_branch=(pull_request.get("head") or {}).get("ref", ""),
            pull_url=pull_request.get("html_url", ""),
            version_bumps=version_bumps,
            mergeable_state=pull_request.get("mergeable_state", ""),
            author=(pull_request.get("user") or {}).get("login", ""),
        )


def is_bot_owner(user: str) -> bool:
    return "[bot]" in user.lower()


def build_pull_request_metadata(
    owner: str,
    repo: str,
    pull_request:dict[str, Any],
) -> PullRequestMetadata:
    """
    Convert GitHub pull requests into normalized PullRequestMetadata objects.
    """

    user = pull_request.get("user") or {}

    if not is_bot_owner(user.get("login", "")):
        return None

    if not pull_request.get("number"):
        return None

    return PullRequestMetadata.from_pull_request(
        pull_request=pull_request,
        version_bumps=get_version_bumps(
            pull_request.get("title", ""),
            pull_request.get("body", ""),
        ),
        
    )