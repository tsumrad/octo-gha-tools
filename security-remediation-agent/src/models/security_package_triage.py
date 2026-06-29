from dataclasses import dataclass, field
from typing import Any

from ..tools.github_pr_collector.model.pull_request_metadata import PullRequestMetadata
from ..tools.github_vulnerability_collector.model.vulnerability_alert import VulnerabilityAlert


@dataclass
class SecurityPackageTriage:
    package: str
    current_version_range: str
    remediated_version: str

    vulnerabilities: list[VulnerabilityAlert] = field(default_factory=list)
    scanning_alerts: list[Any] = field(default_factory=list)

    isupgradable: bool = False
    upgrade_version: str = ""

    istransitive: bool = False
    transitive_source_package: list[str] = field(default_factory=list)

    is_pull_available: bool = False
    pull_metadata: list[PullRequestMetadata] = field(default_factory=list)

    is_issue_created: bool = False
    issue_metadata: dict[str, Any] = field(default_factory=dict)

    isbreakable: bool = False
    upgrade_pull_metadata: list[PullRequestMetadata] = field(default_factory=list)
    pull_patch: Any = None
    breaking_upgrade_version: str = ""
    non_breaking_upgrade_version: str = ""
    breaking_pull_available: bool = False
    breaking_pull_metadata: PullRequestMetadata | None = None
    non_breaking_pull_available: bool = False
    non_breaking_pull_metadata: PullRequestMetadata | None = None

    ecosystem: str = ""
    severity: str = ""
