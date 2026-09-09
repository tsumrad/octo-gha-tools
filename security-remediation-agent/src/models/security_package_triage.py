from dataclasses import dataclass, field
from typing import Any
from dataclasses import field

from  ..models.remediation_plan import SummaryContext

from src.tools.model.pull_request_metadata import PullRequestMetadata
from src.tools.model.vulnerability_alert import VulnerabilityAlert


@dataclass
class SecurityPackageTriage:
    #Source: Vulnerability alert
    package: str
    vulnerable_version_range: str
    remediated_version: str
    ecosystem: str = ""
    severity: str = ""
    istransitive: bool = False

    #Source: Vulnerability alert and code scanning
    vulnerabilities: list[VulnerabilityAlert] = field(default_factory=list)
    scanning_alerts: list[Any] = field(default_factory=list)

    # component relationship    
    transitive_source_package: list[str] = field(default_factory=list)
    dependency_occurrences: list[dict[str, Any]] = field(default_factory=list)
    introducer_pull_requests: list[dict[str, Any]] = field(default_factory=list)
    current_version: str = ""
    fixed_minimum_version: str = ""
    fixed_maximum_version: str = ""

    #pulls - remediation & update consolidation
    is_pull_available: bool = False

    # Determined values
    #Computed; get the least applicable patch. if its breaking version. populate breaking; else non-breaking.
    # for scenarios where both breaking and non-breaking present; both are populated.
    isbreakable: bool = False

    #pulls - by bot
    pull_request_metadata: list[PullRequestMetadata] = field(default_factory=list)

    #issue
    is_issue_created: bool = False
    issue_metadata: dict[str, Any] = field(default_factory=dict)

    # Target upgrade version for the package
    upgrade_to_version: str = ""
    

@dataclass
class SecurityRemediationTriage:
    summary: SummaryContext = None
    package_triages: list[SecurityPackageTriage] = field(default_factory=list)
