#!/usr/bin/env bash
set -euo pipefail

{
	echo "## Security Vulnerability Remediation"
	echo
} >>"$GITHUB_STEP_SUMMARY"

if [ ! -f workflow-plans.json ]; then
	echo "Orchestration did not complete." >>"$GITHUB_STEP_SUMMARY"
	exit 0
fi

base_branch="${BASE_BRANCH}"
open_security_alerts="$(jq '[.groups[].plans? // [] | .[] | (.package.unique_ghsas // [])[]] | unique | length' workflow-plans.json)"
open_code_scanning_alerts="$(jq '[.groups[].plans? // [] | .[] | (.package.scanning_alerts // [])[]] | length' workflow-plans.json)"
open_prs_reviewed="$(jq '[.groups[].plans? // [] | .[] | .action.pr_number? // empty] | unique | length' workflow-plans.json)"
prs_matched="$(jq '[.groups[].plans? // [] | .[] | select(.action.action_type == "rollup_pr" or .action.action_type == "standalone_pr") | .action.pr_number] | unique | length' workflow-plans.json)"
prs_ignored=$((open_prs_reviewed - prs_matched))
findings_without_pr="$(jq '[.groups[].plans? // [] | .[] | select(.action.action_type == "placeholder_pr" or .action.action_type == "open_issue")] | length' workflow-plans.json)"
auto_created_prs="$(jq '[.created_prs | to_entries[] | if (.value | type) == "array" then .value[] else .value end] | length' rollup-output.json 2>/dev/null || echo 0)"
auto_created_issues="$(jq '.created_issues | length' rollup-output.json 2>/dev/null || echo 0)"

{
	echo "| Metric | Value |"
	echo "|--------|-------|"
	echo "| Base branch | \`${base_branch}\` |"
	echo "| Open security alerts | ${open_security_alerts} |"
	echo "| Open code scanning alerts | ${open_code_scanning_alerts} |"
	echo "| Open PRs reviewed | ${open_prs_reviewed} |"
	echo "| PRs matched (used as remediation) | ${prs_matched} |"
	echo "| PRs ignored (no matching finding) | ${prs_ignored} |"
	echo "| Findings without existing PR | ${findings_without_pr} |"
	echo "| Remediation(Roll-up) PRs auto-created | ${auto_created_prs} |"
	echo "| Tracking issues created/updated | ${auto_created_issues} |"
	echo
} >>"$GITHUB_STEP_SUMMARY"

if [ -f rollup-output.json ]; then
	dry_run="$(jq -r '.dry_run' rollup-output.json)"
	if [ "$dry_run" = "true" ]; then
		{
			echo "> ℹ️ **Dry run mode** - no branches, PRs, or issues were created."
			echo
		} >>"$GITHUB_STEP_SUMMARY"
	fi

	pr_count="$(jq '.created_prs | length' rollup-output.json)"
	if [ "$pr_count" -gt 0 ]; then
		{
			echo "### Remediation Pull Requests"
			echo
		} >>"$GITHUB_STEP_SUMMARY"
		jq -r '
      .created_prs | to_entries[] |
      .key as $cat |
      (if (.value | type) == "array"
       then .value | unique_by(.number) | .[]
       else .value
       end) |
      "- **\($cat)**: [\(.title)](\(.url))"
    ' rollup-output.json >>"$GITHUB_STEP_SUMMARY"
		echo >>"$GITHUB_STEP_SUMMARY"
	fi

	issue_count="$(jq '.created_issues | length' rollup-output.json 2>/dev/null || echo 0)"
	if [ "$issue_count" -gt 0 ]; then
		{
			echo "### Tracking Issues"
			echo
		} >>"$GITHUB_STEP_SUMMARY"
		jq -r '.created_issues | to_entries[] | "- **\(.key)**: [\(.value.title)](\(.value.url))"' \
			rollup-output.json >>"$GITHUB_STEP_SUMMARY"
		echo >>"$GITHUB_STEP_SUMMARY"
	fi
fi

{
	echo "### Vulnerability Categories"
	echo
	echo "| Severity | Non-Breaking | Breaking |"
	echo "|----------|:------------:|:--------:|"
} >>"$GITHUB_STEP_SUMMARY"

for sev in critical high medium low; do
	nb="$(jq --arg s "$sev" '[.groups[$s].plans? // [] | .[] | select(.fix.fix_class != "BREAKING_BUMP")] | length' workflow-plans.json 2>/dev/null || echo 0)"
	br="$(jq --arg s "$sev" '[.groups[$s].plans? // [] | .[] | select(.fix.fix_class == "BREAKING_BUMP")] | length' workflow-plans.json 2>/dev/null || echo 0)"
	echo "| ${sev} | ${nb} | ${br} |" >>"$GITHUB_STEP_SUMMARY"
done
