from __future__ import annotations

from datetime import date, datetime

from langchain_core.tools import tool
from packaging.version import Version

from ...models.remediation_plan import (
    ActionPlan,
    ActionType,
    AuditEntry,
    FixClass,
    FixPlan,
    PackageContext,
    PlanState,
    RemediationPlan,
)
from ...models.security_package_triage import SecurityPackageTriage
from ...tools.github_pr_collector.model.pull_request_metadata import PullRequestMetadata


@tool("build_remediation_plan")
def build_remediation_plan(
    pkg: SecurityPackageTriage,
) -> RemediationPlan:
    """Build a remediation plan from a package vulnerability triage result."""
    if pkg.istransitive:
        return build_transitive_plan(pkg)
    return build_direct_plan(pkg)


def build_direct_plan(pkg: SecurityPackageTriage) -> RemediationPlan:
    fix_class = derive_fix_class(pkg)
    action_type = derive_action_type(pkg, fix_class)
    severity = normalize_severity(pkg.vulnerabilities)
    ghsas = dedupe_ghsas(pkg.vulnerabilities)

    return RemediationPlan(
        plan_id=f"plan_{pkg.package}_{pkg.ecosystem}_{date.today():%Y%m%d}",
        created_at=datetime.utcnow(),
        package=PackageContext(
            name=pkg.package,
            ecosystem=pkg.ecosystem,
            current_version_range=pkg.current_version_range,
            remediated_version=pkg.remediated_version,
            effective_severity=severity,
            relationship=derive_relationship(pkg),
            transitive_source_package=pkg.transitive_source_package,
            unique_ghsas=ghsas,
        ),
        fix=FixPlan(
            fix_class=fix_class,
            non_breaking_fix=pkg.non_breaking_upgrade_version or None,
            breaking_fix=pkg.breaking_upgrade_version or None,
            upgrade_version=pkg.upgrade_version,
            partial_fix_available=bool(
                pkg.non_breaking_upgrade_version and pkg.breaking_upgrade_version
            ),
            patch_available=pkg.pull_patch is not None,
            non_breaking_closes=ghsas_closed_by(
                pkg.vulnerabilities,
                pkg.non_breaking_upgrade_version,
            ),
            breaking_closes=ghsas_closed_by(
                pkg.vulnerabilities,
                pkg.breaking_upgrade_version,
            ),
        ),
        action=ActionPlan(
            action_type=action_type,
            pull_url=resolve_pull_url(pkg, fix_class),
            pr_number=resolve_pr_number(pkg, fix_class),
            placeholder_markdown=(
                build_placeholder_markdown(pkg, fix_class, severity, ghsas)
                if action_type == ActionType.PLACEHOLDER_PR
                else ""
            ),
            issue_title=(
                build_issue_title(pkg, severity)
                if action_type == ActionType.OPEN_ISSUE
                else ""
            ),
            target_package=pkg.package,
        ),
        state=PlanState(
            issue_id=pkg.issue_metadata.get("id", ""),
            issue_url=pkg.issue_metadata.get("url", ""),
        ),
        audit=[
            AuditEntry(
                timestamp=datetime.utcnow().isoformat(),
                agent="remediation_planner",
                action="plan_created",
                detail=(
                    f"fix_class={fix_class.value}, "
                    f"action={action_type.value}, "
                    f"severity={severity}"
                ),
            )
        ],
    )


def build_transitive_plan(pkg: SecurityPackageTriage) -> RemediationPlan:
    """
    For transitive findings we don't plan a fix against pkg itself — pkg isn't
    declared anywhere we can bump directly. Instead we look for an existing PR
    that bumps one of pkg.transitive_source_package, and point the action at
    that. If no such PR exists, we open an issue naming the source package(s)
    that need to be bumped, rather than stubbing a placeholder PR we have no
    basis to author.
    """
    severity = normalize_severity(pkg.vulnerabilities)
    ghsas = dedupe_ghsas(pkg.vulnerabilities)
    source_pr, source_package = find_source_pull_metadata(pkg)

    if source_pr is not None:
        action_type = (
            ActionType.ROLLUP_PR
            if len(source_pr.version_bumps) > 1
            else ActionType.STANDALONE_PR
        )
        action = ActionPlan(
            action_type=action_type,
            pull_url=source_pr.pull_url,
            pr_number=source_pr.pr_number,
            placeholder_markdown="",
            issue_title="",
            target_package=source_package,
        )
    else:
        action = ActionPlan(
            action_type=ActionType.OPEN_ISSUE,
            pull_url="",
            pr_number=None,
            placeholder_markdown="",
            issue_title=build_transitive_issue_title(pkg, severity, source_package),
            target_package=source_package,
        )

    return RemediationPlan(
        plan_id=f"plan_{pkg.package}_{pkg.ecosystem}_{date.today():%Y%m%d}",
        created_at=datetime.utcnow(),
        package=PackageContext(
            name=pkg.package,
            ecosystem=pkg.ecosystem,
            current_version_range=pkg.current_version_range,
            remediated_version=pkg.remediated_version,
            effective_severity=severity,
            relationship="transitive",
            transitive_source_package=pkg.transitive_source_package,
            unique_ghsas=ghsas,
        ),
        fix=FixPlan(
            fix_class=FixClass.NO_FIX_AVAILABLE,
            non_breaking_fix=None,
            breaking_fix=None,
            upgrade_version="",
            partial_fix_available=False,
            patch_available=False,
            non_breaking_closes=[],
            breaking_closes=[],
        ),
        action=action,
        state=PlanState(
            issue_id=pkg.issue_metadata.get("id", ""),
            issue_url=pkg.issue_metadata.get("url", ""),
        ),
        audit=[
            AuditEntry(
                timestamp=datetime.utcnow().isoformat(),
                agent="remediation_planner",
                action="plan_created",
                detail=(
                    f"transitive_via={source_package or 'unknown'}, "
                    f"action={action.action_type.value}, "
                    f"severity={severity}"
                ),
            )
        ],
    )


def find_source_pull_metadata(
    pkg: SecurityPackageTriage,
) -> tuple[PullRequestMetadata | None, str]:
    """
    Search pkg.pull_metadata (all PRs seen for this finding's repo context)
    for one whose version_bumps touches one of pkg.transitive_source_package.
    Returns the matching PR and the source package name it matched on, or
    (None, first_source) if nothing matches.
    """
    sources = pkg.transitive_source_package or []
    for source in sources:
        for pr in pkg.pull_metadata:
            for bump in pr.version_bumps:
                if bump.package.lower() == source.lower():
                    return pr, source
    return None, (sources[0] if sources else "")


def build_transitive_issue_title(
    pkg: SecurityPackageTriage,
    severity: str,
    source_package: str,
) -> str:
    via = source_package or "an unidentified parent package"
    return (
        f"Security remediation — {severity.upper()} — "
        f"{pkg.package} ({pkg.ecosystem}) — transitive via {via}, "
        f"no source PR found"
    )


def derive_fix_class(pkg: SecurityPackageTriage) -> FixClass:
    if not pkg.isupgradable:
        return FixClass.NO_FIX_AVAILABLE

    has_non_breaking = bool(pkg.non_breaking_upgrade_version)
    has_breaking = bool(pkg.breaking_upgrade_version)

    if has_non_breaking and has_breaking:
        return FixClass.PARTIAL_FIX_AVAILABLE
    if has_breaking and not has_non_breaking:
        return FixClass.BREAKING_BUMP
    if has_non_breaking and not has_breaking:
        return FixClass.NON_BREAKING_BUMP

    return FixClass.NO_FIX_AVAILABLE


def derive_action_type(
    pkg: SecurityPackageTriage,
    fix_class: FixClass,
) -> ActionType:
    if fix_class == FixClass.NO_FIX_AVAILABLE:
        return ActionType.OPEN_ISSUE

    if fix_class == FixClass.NON_BREAKING_BUMP:
        if pkg.non_breaking_pull_available and pkg.non_breaking_pull_metadata:
            return ActionType.ROLLUP_PR
        return ActionType.PLACEHOLDER_PR

    if fix_class == FixClass.BREAKING_BUMP:
        if pkg.breaking_pull_available and pkg.breaking_pull_metadata:
            return ActionType.STANDALONE_PR
        return ActionType.PLACEHOLDER_PR

    if fix_class == FixClass.PARTIAL_FIX_AVAILABLE:
        if pkg.non_breaking_pull_available and pkg.non_breaking_pull_metadata:
            return ActionType.ROLLUP_PR
        if pkg.breaking_pull_available and pkg.breaking_pull_metadata:
            return ActionType.STANDALONE_PR
        return ActionType.PLACEHOLDER_PR

    return ActionType.OPEN_ISSUE


def resolve_pull_url(pkg: SecurityPackageTriage, fix_class: FixClass) -> str:
    if fix_class == FixClass.NON_BREAKING_BUMP and pkg.non_breaking_pull_metadata:
        return pkg.non_breaking_pull_metadata.pull_url
    if fix_class == FixClass.BREAKING_BUMP and pkg.breaking_pull_metadata:
        return pkg.breaking_pull_metadata.pull_url
    if fix_class == FixClass.PARTIAL_FIX_AVAILABLE:
        if pkg.non_breaking_pull_metadata:
            return pkg.non_breaking_pull_metadata.pull_url
        if pkg.breaking_pull_metadata:
            return pkg.breaking_pull_metadata.pull_url
    return ""


def resolve_pr_number(pkg: SecurityPackageTriage, fix_class: FixClass) -> int | None:
    if fix_class == FixClass.NON_BREAKING_BUMP and pkg.non_breaking_pull_metadata:
        return pkg.non_breaking_pull_metadata.pr_number
    if fix_class == FixClass.BREAKING_BUMP and pkg.breaking_pull_metadata:
        return pkg.breaking_pull_metadata.pr_number
    if fix_class == FixClass.PARTIAL_FIX_AVAILABLE:
        if pkg.non_breaking_pull_metadata:
            return pkg.non_breaking_pull_metadata.pr_number
        if pkg.breaking_pull_metadata:
            return pkg.breaking_pull_metadata.pr_number
    return None


def build_placeholder_markdown(
    pkg: SecurityPackageTriage,
    fix_class: FixClass,
    severity: str,
    ghsas: list[str],
) -> str:
    breaking = fix_class in (FixClass.BREAKING_BUMP, FixClass.PARTIAL_FIX_AVAILABLE)
    target = pkg.breaking_upgrade_version or pkg.non_breaking_upgrade_version

    return f"""## Security remediation — {pkg.package} ({pkg.ecosystem})

**Severity:** {severity.upper()}
**Current range:** {pkg.current_version_range}
**Target version:** {target}
**Breaking change:** {"Yes" if breaking else "No"}
**GHSAs:** {", ".join(ghsas)}

### Vulnerability summary
{build_vuln_summary_lines(pkg.vulnerabilities)}

### Resolution options
- [ ] Assign to coding agent (Copilot / LLM) to author the fix PR
- [ ] Self-resolve — implement migration manually

### Notes
_Add context, blockers, or migration hints here._
"""


def build_issue_title(pkg: SecurityPackageTriage, severity: str) -> str:
    return (
        f"Security remediation — {severity.upper()} — "
        f"{pkg.package} ({pkg.ecosystem}) — no fix available"
    )


def normalize_severity(vulnerabilities: list) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    if not vulnerabilities:
        return "unknown"
    return max(vulnerabilities, key=lambda v: order.get(v.severity, 0)).severity


def derive_relationship(pkg: SecurityPackageTriage) -> str:
    if pkg.istransitive:
        return "transitive"
    if any(vulnerability.relationship.lower() == "direct" for vulnerability in pkg.vulnerabilities):
        return "direct"
    if pkg.vulnerabilities:
        return pkg.vulnerabilities[0].relationship
    return "unknown"


def dedupe_ghsas(vulnerabilities: list) -> list[str]:
    seen, output = set(), []
    for vulnerability in vulnerabilities:
        if vulnerability.ghsa_id not in seen:
            seen.add(vulnerability.ghsa_id)
            output.append(vulnerability.ghsa_id)
    return output


def ghsas_closed_by(vulnerabilities: list, target_version: str) -> list[str]:
    if not target_version:
        return []
    target = Version(target_version)
    return [
        vulnerability.ghsa_id
        for vulnerability in vulnerabilities
        if vulnerability.first_patched and Version(vulnerability.first_patched) <= target
    ]


def build_vuln_summary(vulnerabilities: list) -> str:
    unique = {vulnerability.ghsa_id: vulnerability for vulnerability in vulnerabilities}
    return "; ".join(vulnerability.summary for vulnerability in unique.values())


def build_vuln_summary_lines(vulnerabilities: list) -> str:
    unique = {vulnerability.ghsa_id: vulnerability for vulnerability in vulnerabilities}
    return "\n".join(
        f"- **{vulnerability.ghsa_id}** (CVSS {vulnerability.cvss}) — {vulnerability.summary}"
        for vulnerability in unique.values()
    )