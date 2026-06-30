from __future__ import annotations

import httpx

from ..models.remediation_plan_bundle import PlaceholderSubgroup
from ..tools.github_pr_collector.pull_requests_tool import get_github_headers


def _branch_name_for(subgroup: PlaceholderSubgroup) -> str:
    return f"security-placeholder/{subgroup.impact.lower().replace(' ', '-')}"


async def _find_existing_pr(
    owner: str, repo: str, branch_name: str, client: httpx.AsyncClient,
) -> dict | None:
    resp = await client.get(
        f"https://api.github.com/repos/{owner}/{repo}/pulls",
        params={"head": f"{owner}:{branch_name}", "state": "open"},
    )
    resp.raise_for_status()
    results = resp.json()
    return results[0] if results else None


async def _ensure_branch(
    owner: str, repo: str, branch_name: str, base_branch: str, client: httpx.AsyncClient,
) -> None:
    ref_check = await client.get(
        f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{branch_name}"
    )
    if ref_check.status_code == 200:
        return
    base_ref = await client.get(
        f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{base_branch}"
    )
    base_ref.raise_for_status()
    create_resp = await client.post(
        f"https://api.github.com/repos/{owner}/{repo}/git/refs",
        json={"ref": f"refs/heads/{branch_name}", "sha": base_ref.json()["object"]["sha"]},
    )
    create_resp.raise_for_status()


async def sync_placeholder_tracking_pr(
    owner: str,
    repo: str,
    subgroup: PlaceholderSubgroup,
    base_branch: str = "main",
) -> None:
    """
    Open (or update) the single tracking PR for this impact subgroup, with
    body = subgroup.combined_markdown — i.e. every package's
    placeholder_markdown joined together, one PR per impact. No separate
    markdown file or report column is needed afterward: the report just
    links to plan.action.pull_url, which now points at this PR.

    Re-running this on a later triage pass updates the body in place, so
    packages that get a real remediation PR later (and drop out of the
    placeholder bucket) disappear from this PR's body automatically.
    """
    if not subgroup.plans:
        return

    branch_name = _branch_name_for(subgroup)
    title = f"[Security Remediation] {subgroup.impact} — placeholder tracking"
    timeout = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0)

    async with httpx.AsyncClient(headers=get_github_headers(), timeout=timeout) as client:
        existing = await _find_existing_pr(owner, repo, branch_name, client)

        if existing:
            resp = await client.patch(
                f"https://api.github.com/repos/{owner}/{repo}/pulls/{existing['number']}",
                json={"title": title, "body": subgroup.combined_markdown},
            )
            resp.raise_for_status()
            pr = resp.json()
        else:
            await _ensure_branch(owner, repo, branch_name, base_branch, client)
            resp = await client.post(
                f"https://api.github.com/repos/{owner}/{repo}/pulls",
                json={
                    "title": title,
                    "head": branch_name,
                    "base": base_branch,
                    "body": subgroup.combined_markdown,
                    "draft": True,
                },
            )
            resp.raise_for_status()
            pr = resp.json()

    # Write the real PR back onto every plan in this subgroup — same
    # pull_url/pr_number fields a matched remediation PR would use.
    subgroup.apply_tracking_pr(pull_url=pr["html_url"], pr_number=pr["number"])