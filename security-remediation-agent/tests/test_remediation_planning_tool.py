from src.models.remediation_plan import ActionType, FixClass
from src.models.security_package_triage import SecurityPackageTriage
from src.tools.github_vulnerability_collector.model.vulnerability_alert import VulnerabilityAlert
from src.tools.remediation_planning_assistant.remediation_planning_tool import (
    build_direct_plan,
    build_transitive_plan,
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


def test_critical_transitive_fix_direction_without_pr_creates_placeholder_plan() -> None:
    pkg = SecurityPackageTriage(
        package="form-data",
        ecosystem="npm",
        current_version_range=">= 4.0.0, < 4.0.6",
        remediated_version="4.0.6",
        istransitive=True,
        transitive_source_package=["axios@0.28.1"],
        vulnerabilities=[
            VulnerabilityAlert(
                package="form-data",
                ecosystem="npm",
                severity="critical",
                ghsa_id="GHSA-form-data",
                first_patched="4.0.6",
                vulnerable_range=">= 4.0.0, < 4.0.6",
                relationship="indirect",
            )
        ],
    )

    plan = build_transitive_plan(pkg)

    assert plan.package.effective_severity == "critical"
    assert plan.action.action_type == ActionType.PLACEHOLDER_PR
    assert plan.action.target_package == "axios"
    assert "`axios >= 4.0.6`" in plan.action.placeholder_markdown
    assert "### Issue details" in plan.action.placeholder_markdown
    assert "| Patched vulnerable package version | `4.0.6` |" in plan.action.placeholder_markdown
    assert "### Source details" in plan.action.placeholder_markdown
    assert "| Source package to update | `axios` |" in plan.action.placeholder_markdown
    assert "| Source candidates from dependency graph | axios@0.28.1 |" in plan.action.placeholder_markdown
