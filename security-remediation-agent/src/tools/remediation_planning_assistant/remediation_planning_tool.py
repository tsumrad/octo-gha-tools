from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime
from venv import logger

from langchain_core.tools import tool
from pydantic import BaseModel, Field
from packaging.version import Version, InvalidVersion
from uuid_utils import uuid4

from ...models.remediation_plan import (
    ActionType,
    EcosystemContext,
    IssueContext,
    PackageContext,
    RemediationPlan,
    SummaryContext,
)
from ...models.security_package_triage import SecurityPackageTriage
from ...tools.github_pr_collector.model.pull_request_metadata import PullRequestMetadata



@tool("build_remediation_plan")
def build_remediation_plan(
    triage_result: list[SecurityPackageTriage],
) -> RemediationPlan:
    """Build a remediation plan from a package vulnerability triage result."""
    if not triage_result:
        return RemediationPlan(
            plan_id=f"plan_{date.today():%Y%m%d}_{uuid4().hex[:8]}",
            created_at=datetime.utcnow(),
            remediation_plans=[],
            summary=SummaryContext(
                ecosystem_summary=[],
            ),
        )

    return RemediationPlan(
        plan_id=f"plan_{date.today():%Y%m%d}_{uuid4().hex[:8]}",
        created_at=datetime.utcnow(),
        remediation_plans=create_issue_context(triage_result),
        summary=build_summary(triage_result),
    )

def build_summary(
    triage_result: list[SecurityPackageTriage],
) -> SummaryContext:
    """
    Group vulnerable packages by ecosystem.

    A package can be:
    - direct OR transitive
    - breaking OR non-breaking

    Multiple packages belonging to the same ecosystem are consolidated
    into a single EcosystemContext.
    """

    grouped: dict[str, EcosystemContext] = {}

    for pkg in triage_result:
        ecosystem = grouped.setdefault(
            pkg.ecosystem,
            EcosystemContext(
                name=pkg.ecosystem,
            ),
        )

        # Direct / transitive classification
        if pkg.istransitive:
            if pkg.package not in ecosystem.transitive_vulnerabile_packages:
                ecosystem.transitive_vulnerabile_packages.append(pkg.package)
        else:
            if pkg.package not in ecosystem.direct_vulnerabile_packages:
                ecosystem.direct_vulnerabile_packages.append(pkg.package)

    return SummaryContext(
        ecosystem_summary=list(grouped.values()),
    )

def create_package_context(pkg: SecurityPackageTriage) -> PackageContext:
    return PackageContext(
        name=pkg.package,
        ecosystem=pkg.ecosystem,
        current_version=pkg.current_version,
        relationship="transitive" if pkg.istransitive else "direct",
        vulnerabilities=pkg.vulnerabilities,
        pull_requests=pkg.pull_request_metadata,
        fixed_minimum_version=pkg.fixed_minimum_version or "",
        fixed_maximum_version=pkg.fixed_maximum_version or "",
        isbreakable=pkg.isbreakable,
        upgrade_to_version=pkg.upgrade_to_version,
        action_type=None,

    )

def create_issue_context(triage_result: list[SecurityPackageTriage]) -> list[IssueContext]:
    #Create by ecosystem
    grouped: dict[str, list[SecurityPackageTriage]] = defaultdict(list)

    for pkg in triage_result:
        grouped[pkg.ecosystem].append(pkg)

    issue_contexts = []

    for ecosystem, packages in grouped.items():
        issue_contexts.append(
            IssueContext(
                ecosystem=ecosystem,
                packages=[
                    create_package_context(pkg)
                    for pkg in packages
                ],
                coding_agent=None,
                severity=None,
            )
        )

    return issue_contexts