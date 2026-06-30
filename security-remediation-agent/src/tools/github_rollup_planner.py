import argparse
import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .github_codescanning_collector.codescanning_alerts_tool import get_codescanning_alerts
from .github_pr_collector.pull_requests_tool import get_open_pull_requests
from .github_pr_collector.model.pull_request_metadata import (
    filter_security_dependency_pull_requests,
)
from .github_vulnerability_collector.dependabot_alerts_tool import (
    DEFAULT_SEVERITIES,
    get_dependabot_alerts,
)
from .github_vulnerability_collector.model.vulnerability_alert import build_alerts_by_package


SEVERITIES = ("critical", "high", "medium", "low")
IMPACTS = ("non-breaking", "breaking")
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def parse_severities(value: str) -> set[str]:
    severities = {severity.strip().lower() for severity in value.split(",") if severity.strip()}
    invalid_severities = severities - DEFAULT_SEVERITIES
    if invalid_severities:
        valid_values = ", ".join(sorted(DEFAULT_SEVERITIES))
        invalid_values = ", ".join(sorted(invalid_severities))
        raise ValueError(
            f"Unsupported severity values: {invalid_values}. Expected one or more of: {valid_values}."
        )

    return severities or set(DEFAULT_SEVERITIES)


def highest_severity(package_alerts: list[dict[str, Any]]) -> str:
    return max(
        (
            (
                alert.get("severity")
                or (alert.get("security_advisory") or {}).get("severity")
                or ""
            ).lower()
            for alert in package_alerts
        ),
        key=lambda severity: SEVERITY_ORDER.get(severity, 0),
        default="",
    )


def patched_versions(package_alerts: list[dict[str, Any]]) -> list[str]:
    versions: list[str] = []
    seen: set[str] = set()
    for alert in package_alerts:
        vulnerability = alert.get("security_vulnerability") or {}
        first_patched = vulnerability.get("first_patched_version") or {}
        version = alert.get("first_patched") or first_patched.get("identifier", "")
        if version and version not in seen:
            seen.add(version)
            versions.append(version)
    return versions


def placeholder_markdown(package: str, severity: str, package_alerts: list[dict[str, Any]]) -> str:
    versions = patched_versions(package_alerts)
    target = ", ".join(versions) if versions else "unknown"
    summaries = []
    for alert in package_alerts:
        advisory = alert.get("security_advisory") or {}
        ghsa = alert.get("ghsa_id") or advisory.get("ghsa_id", "")
        summary = alert.get("summary") or advisory.get("summary", "")
        summaries.append(f"- **{ghsa}** {summary}".rstrip())

    return f"""## Security remediation — {package}

**Severity:** {severity.upper()}
**Target version:** {target}

### Vulnerability summary
{chr(10).join(summaries)}

### Resolution options
- [ ] Assign to coding agent (Copilot / LLM) to author the fix PR
- [ ] Self-resolve — implement migration manually
"""


async def build_rollup_plan(
    *,
    owner: str,
    repo: str,
    base_branch: str,
    run_id: str,
    severities: set[str],
) -> dict[str, Any]:
    dependabot_alerts, code_scanning_alerts, open_pull_requests = await asyncio.gather(
        get_dependabot_alerts(owner, repo, severities=severities),
        get_codescanning_alerts(owner, repo),
        get_open_pull_requests(owner, repo),
    )
    candidate_pull_requests = filter_security_dependency_pull_requests(
        owner=owner,
        repo=repo,
        pull_requests=open_pull_requests,
        alerts=dependabot_alerts,
        severities=severities,
    )

    plan = {f"{severity}-{impact}": [] for severity in SEVERITIES for impact in IMPACTS}
    matched_packages: set[str] = set()
    for item in candidate_pull_requests:
        package = item.get("package")
        if not item.get("severity") or not item.get("impact") or not package:
            continue
        plan[f"{item['severity']}-{item['impact']}"].append(item)
        matched_packages.add(package.lower())

    findings_without_pr = []
    for package, package_alerts in build_alerts_by_package(dependabot_alerts).items():
        if package in matched_packages:
            continue

        severity = highest_severity(package_alerts)
        if severity and severity in severities:
            versions = patched_versions(package_alerts)
            action_type = "placeholder_pr" if versions else "open_issue"
            findings_without_pr.append(
                {
                    "package": package,
                    "severity": severity,
                    "action_type": action_type,
                    "patched_versions": versions,
                    "placeholder_markdown": (
                        placeholder_markdown(package, severity, package_alerts)
                        if action_type == "placeholder_pr"
                        else ""
                    ),
                    "alerts": package_alerts,
                }
            )

    return {
        "base_branch": base_branch,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "run_id": run_id,
        "repo_scope": f"{owner}/{repo}",
        "plan": plan,
        "findings_without_pr": findings_without_pr,
        "auto_created_prs": [],
        "stats": {
            "total_open_alerts": len(dependabot_alerts),
            "total_open_prs_reviewed": len(open_pull_requests),
            "total_prs_matched": len(candidate_pull_requests),
            "total_prs_ignored": len(open_pull_requests) - len(candidate_pull_requests),
            "total_code_scanning_alerts": len(code_scanning_alerts),
            "total_findings_without_pr": len(findings_without_pr),
            "total_auto_created_prs": 0,
        },
    }


async def async_main() -> None:
    parser = argparse.ArgumentParser(description="Build a security vulnerability rollup plan.")
    parser.add_argument("--owner", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--base-branch", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--severities", default="critical,high,medium,low")
    parser.add_argument("--output", default="rollup-plan.json")
    args = parser.parse_args()

    plan = await build_rollup_plan(
        owner=args.owner,
        repo=args.repo,
        base_branch=args.base_branch,
        run_id=args.run_id,
        severities=parse_severities(args.severities),
    )
    Path(args.output).write_text(json.dumps(plan, indent=2), encoding="utf-8")


def main() -> None:
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
