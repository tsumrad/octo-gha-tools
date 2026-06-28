import re
from collections.abc import Iterable
from dataclasses import asdict, is_dataclass
from typing import Any

from pydantic import BaseModel

from ..utils.version_bump_resolver import get_version_bumps

from ...github_vulnerability_collector.dependabot_alerts_tool import DEFAULT_SEVERITIES
from ...github_vulnerability_collector.model.vulnerability_alert import build_alerts_by_package, VulnerabilityAlert


class VersionBump(BaseModel):
    package: str
    from_version: str
    to_version: str


class PullRequestMetadata(BaseModel):
    pr_number: int | None = None
    pr_title: str = ""
    pr_branch: str = ""
    pull_url: str = ""

    version_bumps: list[VersionBump]

    severity: str = ""
    author: str = ""
    ecosystem: str = ""


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
            author=(pull_request.get("user") or {}).get("login", ""),
        )


# -----------------------------------------------------
# Version bump abstraction
# -----------------------------------------------------

def parse_version_bumps(title: str, body: str) -> list[VersionBump]:
    version_updates = get_version_bumps(title, body)

    version_bumps = []
    if version_updates and len(version_updates) > 0:
        for update in version_updates:
            update_data = to_mapping(update)
            version_bumps.append(
                VersionBump(
                    package=update_data.get("package", ""),
                    from_version=update_data.get("from_version") or "",
                    to_version=update_data.get("to_version", ""),
                )
            )
    return version_bumps


def to_mapping(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return value
    raise TypeError(f"Unsupported version bump type: {type(value).__name__}")


def is_bot_owner(user: str) -> bool:
    return "[bot]" in user.lower()


# -----------------------------------------------------
# Main filter
# -----------------------------------------------------

def filter_security_dependency_pull_requests(
    owner: str,
    repo: str,
    pull_requests: Iterable[dict[str, Any]],
    alerts: list[VulnerabilityAlert],
    severities: Iterable[str] | None = None,
) -> list[dict[str, Any]]:

    candidates: list[dict[str, Any]] = []
    alerts_by_package = build_alerts_by_package(alerts)
    severity_filter = set(severities or DEFAULT_SEVERITIES)

    for pull_request in pull_requests:
        user = pull_request.get("user") or {}

        if not is_bot_owner(user.get("login", "")):
            continue

        pr_number = pull_request.get("number")
        if not pr_number:
            continue

        version_bumps = parse_version_bumps(pull_request.get("title"), pull_request.get("body"))
        # matched_version_bumps = [
        #     version_bump
        #     for version_bump in version_bumps
        #     if find_alerts_for_package(version_bump.package, alerts_by_package)
        # ]
        # if not matched_version_bumps:
        #     continue

        # matched_alerts = [
        #     alert
        #     for version_bump in matched_version_bumps
        #     for alert in find_alerts_for_package(version_bump.package, alerts_by_package)
        # ]
        # if not any(alert.get("severity") in severity_filter for alert in matched_alerts):
        #     continue

        candidates.append(
            PullRequestMetadata.from_pull_request(
                pull_request=pull_request,
                version_bumps=version_bumps,
            ).model_dump()
        )

    return candidates