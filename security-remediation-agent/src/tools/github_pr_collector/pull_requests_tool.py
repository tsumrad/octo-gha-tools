import os
from typing import Any

import httpx
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from ..github_vulnerability_collector.dependabot_alerts_tool import (
    GITHUB_API_VERSION,
    PER_PAGE,
    get_next_link,
)
from .model.pull_request_metadata import filter_security_dependency_pull_requests
from ..github_vulnerability_collector.model.vulnerability_alert import  VulnerabilityAlert

GitHubObject = dict[str, Any]


class SecurityDependencyPullRequestInput(BaseModel):
    """
    Input schema for collecting pull requests related to dependency security fixes.
    """

    owner: str = Field(description="Repository owner or organization.")
    repo: str = Field(description="Repository name.")

    alerts: list[GitHubObject] = Field(
        default_factory=list,
        description=(
            "Open Dependabot alerts used to match dependency PRs "
            "to security fixes."
        ),
    )

    severities: list[str] | None = Field(
        default=None,
        description=(
            "Optional alert severities to include: "
            "critical, high, medium, or low."
        ),
    )


def get_github_headers() -> dict[str, str]:
    """
    Build authenticated GitHub API headers.
    """
    token = os.environ.get("GITHUB_TOKEN")

    if not token:
        raise RuntimeError("GITHUB_TOKEN environment variable is required")

    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }


async def get_open_pull_requests(owner: str, repo: str) -> list[GitHubObject]:
    """
    Fetch all open pull requests from a GitHub repository.
    """

    url = f"https://api.github.com/repos/{owner}/{repo}/pulls"

    params: dict[str, Any] | None = {
        "state": "open",
        "per_page": PER_PAGE,
    }

    pull_requests: list[GitHubObject] = []

    timeout = httpx.Timeout(
        connect=10.0,
        read=30.0,
        write=10.0,
        pool=10.0,
    )

    async with httpx.AsyncClient(
        headers=get_github_headers(),
        timeout=timeout,
    ) as client:

        while True:
            response = await client.get(url, params=params)

            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise RuntimeError(
                    "GitHub API request failed: "
                    f"{response.status_code} {response.text}"
                ) from exc

            data: list[GitHubObject] = response.json()
            pull_requests.extend(data)

            next_url = get_next_link(response.headers.get("Link", ""))

            if not next_url:
                break

            url = next_url
            params = None  # pagination already includes params

    return pull_requests


@tool(
    "collect_security_dependency_pull_requests",
    args_schema=SecurityDependencyPullRequestInput,
)
async def pull_requests_tool(
    owner: str,
    repo: str,
    alerts: list[VulnerabilityAlert] | None = None,
    severities: list[str] | None = None,
) -> list[GitHubObject]:
    """
    Collect open pull requests that remediate dependency security alerts.
    """

    pull_requests = await get_open_pull_requests(owner=owner, repo=repo)

    return filter_security_dependency_pull_requests(
        owner=owner,
        repo=repo,
        pull_requests=pull_requests,
        alerts=alerts or [],
        severities=severities,
    )


security_dependency_pull_requests_tool = pull_requests_tool