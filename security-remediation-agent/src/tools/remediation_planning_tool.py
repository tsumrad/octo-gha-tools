from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime

from langchain_core.tools import tool
from uuid_utils import uuid4

from ..engines.remediation_grouping_engine import RemediationGroupingEngine
from ..models.triage_result import (
    IssueContext,
    PackageContext,
    TriageResult,
)
from ..models.security_package_triage import SecurityPackageTriage

RenovateGroupingService = RemediationGroupingEngine



@tool("build_remediation_plan")
def build_remediation_plan(
    triage_result: TriageResult,
) -> TriageResult:
    """Build a remediation plan from a package vulnerability triage result."""
    if not triage_result:
        return TriageResult(
            plan_id=f"plan_{date.today():%Y%m%d}_{uuid4().hex[:8]}",
            created_at=datetime.utcnow(),
            remediation_plans=[],
        )

    return TriageResult(
        plan_id=f"plan_{date.today():%Y%m%d}_{uuid4().hex[:8]}",
        created_at=datetime.utcnow(),
        remediation_plans=create_issue_context(triage_result),
    )


def create_package_context(pkg: SecurityPackageTriage) -> PackageContext:
    return PackageContext(
        name=pkg.package,
        transitive_dependency_occurrences=pkg.transitive_dependency_occurrences,
        package_upgrade_recommendations=pkg.package_upgrade_recommendations,
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

def create_issue_context(triage_result: TriageResult) -> list[IssueContext]:
    #Create by ecosystem
    grouped: dict[str, list[SecurityPackageTriage]] = defaultdict(list)   

    for plan in triage_result.remediation_plans:
        for pkg in plan.packages:
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
                severity=None,
            )
        )

    return issue_contexts
