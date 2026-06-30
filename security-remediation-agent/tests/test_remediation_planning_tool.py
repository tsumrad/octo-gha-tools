from src.models.remediation_plan import ActionType, FixClass
from src.models.security_package_triage import SecurityPackageTriage
from src.tools.github_vulnerability_collector.model.vulnerability_alert import VulnerabilityAlert
from src.tools.remediation_planning_assistant.remediation_planning_tool import (
    build_direct_plan,
    derive_action_type,
    derive_fix_class,
)


def test_fix_direction_without_existing_pr_creates_placeholder_plan() -> None:
    pkg = SecurityPackageTriage(
        package="demo",
        ecosystem="pip",
        current_version_range="<2.0.0",
        remediated_version="2.0.0",
        vulnerabilities=[
            VulnerabilityAlert(
                package="demo",
                ecosystem="pip",
                severity="high",
                ghsa_id="GHSA-demo",
                first_patched="2.0.0",
                vulnerable_range="<2.0.0",
            )
        ],
    )

    fix_class = derive_fix_class(pkg)

    assert fix_class == FixClass.NON_BREAKING_BUMP
    assert derive_action_type(pkg, fix_class) == ActionType.PLACEHOLDER_PR

    plan = build_direct_plan(pkg)
    assert plan.action.action_type == ActionType.PLACEHOLDER_PR
    assert "**Target version:** 2.0.0" in plan.action.placeholder_markdown
