from src.agents.remediation_planner_agent import RemediationPlannerAgent
from src.models.gh.pull_request_metadata import PullRequestMetadata
from src.models.remediation_plan import RemediationPlan
from src.models.remediation_plan import RemeditionPackage
from src.models.security_package_triage import (
    PackageUpgradeRecommendation,
    SecurityPackageTriage,
)
from src.models.security_remediation_context import SecurityRemediationContext


async def test_plans_direct_triage_item_into_remediation_bundle():
    pull_request = PullRequestMetadata(pr_number=42)
    triage = SecurityPackageTriage(
        package="requests",
        ecosystem="pip",
        current_version="2.31.0",
        vulnerablility_version_range="<2.32.0",
        vulnerablility_fixed_version="2.32.0",
        pull_request_metadata=[pull_request],
    )
    context = SecurityRemediationContext(total_vulnerabilities=1)

    result = await RemediationPlannerAgent().plan([triage], context)

    assert isinstance(result, RemediationPlan)
    assert result.summary is context
    assert len(result.remediation_plan_bundles) == 1
    package = result.remediation_plan_bundles[0].packages[0]
    assert package.remediation_package == "requests"
    assert package.current_version == "2.31.0"
    assert package.remediation_version == "2.32.0"
    assert package.minimum_upgradable_version == "2.32.0"
    assert package.packages == [triage]
    assert package.remediation_prs == [pull_request]


async def test_plans_transitive_triage_item_using_parent_recommendation():
    triage = SecurityPackageTriage(
        package="starlette",
        ecosystem="pip",
        current_version="0.49.0",
        vulnerablility_version_range="<0.50.0",
        vulnerablility_fixed_version="0.50.0",
        istransitive=True,
        package_upgrade_recommendations=[
            PackageUpgradeRecommendation(
                package="fastapi",
                from_version="0.124.0",
                to_version="0.125.0",
                minimum_upgradable_version="0.124.1",
                source="pypi_verified",
            )
        ],
    )

    result = await RemediationPlannerAgent().plan(
        [triage],
        SecurityRemediationContext(total_vulnerabilities=1),
    )

    package = result.remediation_plan_bundles[0].packages[0]
    assert package.remediation_package == "fastapi"
    assert package.current_version == "0.124.0"
    assert package.remediation_version == "0.125.0"
    assert package.minimum_upgradable_version == "0.124.1"
    assert package.packages == [triage]


def test_deduplicates_remediation_package_with_multiple_triage_items():
    first = SecurityPackageTriage(
        package="starlette",
        ecosystem="pip",
        vulnerablility_version_range="<0.50.0",
        vulnerablility_fixed_version="0.50.0",
    )
    second = SecurityPackageTriage(
        package="pydantic",
        ecosystem="pip",
        vulnerablility_version_range="<2.0.0",
        vulnerablility_fixed_version="2.0.0",
    )
    packages = [
        RemeditionPackage(
            ecosystem="pip",
            remediation_package="fastapi",
            packages=[first],
        ),
        RemeditionPackage(
            ecosystem="pip",
            remediation_package="fastapi",
            packages=[second],
        ),
    ]

    deduplicated = RemediationPlannerAgent._dedupe_bundle_packages(packages)

    assert len(deduplicated) == 1
    assert deduplicated[0].packages == [first, second]
