#!/usr/bin/env bash
set -euo pipefail

OUTPUT_FILE="workflow-plans.json"
RESULTS_FILE="rollup-results.json"
echo '{"branches":{},"stubs":{}}' >"$RESULTS_FILE"

git fetch origin "${BASE_BRANCH}"

# Collect all unique categories from the orchestrator output
# category = "<severity>-<non-breaking|breaking>-<rollup|standalone>"
# Only rollup_pr and standalone_pr plans have real branches to merge.
categories="$(jq -r '
  (.groups // .) |
  [
    to_entries[] |
    .value.plans[]? |
    select(.action.action_type == "rollup_pr" or .action.action_type == "standalone_pr") |
    (.package.effective_severity) as $sev |
    (if .fix.fix_class == "BREAKING_BUMP" then "breaking" else "non-breaking" end) as $imp |
    (if .action.action_type == "rollup_pr" then "rollup" else "standalone" end) as $act |
    "\($sev)-\($imp)-\($act)"
  ] | unique[]
' "$OUTPUT_FILE")"

for category in $categories; do
	# category format: <sev>-<imp>-<act>  e.g. critical-non-breaking-rollup
	sev="$(echo "$category" | cut -d'-' -f1)"
	act="$(echo "$category" | rev | cut -d'-' -f1 | rev)"
	imp="$(echo "$category" | cut -d'-' -f2-$(($(echo "$category" | tr '-' '\n' | wc -l) - 1)))"

	# Extract plans for this category
	# pr_branch is not in the orchestrator output, so we resolve it via gh CLI.
	plans_json="$(jq --arg sev "$sev" --arg imp "$imp" --arg act "$act" '
    (.groups // .) |
    [
      to_entries[] |
      .value.plans[]? |
      select(
        .package.effective_severity == $sev and
        (if .fix.fix_class == "BREAKING_BUMP" then "breaking" else "non-breaking" end) == $imp and
        (if .action.action_type == "rollup_pr" then "rollup" else "standalone" end) == $act and
        .action.pr_number != null
      ) |
      {
        pr_number: .action.pr_number,
        pr_title:  (.package.name + ": upgrade to " + .fix.upgrade_version)
      }
    ]
  ' "$OUTPUT_FILE")"

	count="$(echo "$plans_json" | jq 'length')"
	if [ "$count" -eq 0 ]; then continue; fi

	# Resolve pr_branch for each plan via gh CLI
	resolved_plans="$(echo "$plans_json" | jq -c '.[]' | while read -r plan; do
		pr_num="$(echo "$plan" | jq -r '.pr_number')"
		pr_branch="$(gh pr view "$pr_num" --repo "${GITHUB_REPOSITORY}" --json headRefName -q '.headRefName' 2>/dev/null || echo '')"
		if [ -z "$pr_branch" ]; then
			echo "::warning::Could not resolve branch for PR #${pr_num}; skipping" >&2
			continue
		fi
		echo "$plan" | jq --arg b "$pr_branch" '. + {pr_branch: $b}'
	done | jq -sc '.')"

	count="$(echo "$resolved_plans" | jq 'length')"
	if [ "$count" -eq 0 ]; then continue; fi

	branch_name="security-remediation/${category}"
	echo "::group::${branch_name} - ${count} candidate PR(s)"

	git checkout -B "$branch_name" "origin/$BASE_BRANCH"

	included=()
	excluded=()

	while IFS=$'\t' read -r pr_number pr_branch pr_title; do
		echo "Processing PR #${pr_number}: ${pr_branch}"
		pr_head_repo="$(gh pr view "$pr_number" --repo "${GITHUB_REPOSITORY}" --json headRepositoryOwner --jq '.headRepositoryOwner.login' 2>/dev/null || echo "${GITHUB_REPOSITORY_OWNER}")"
		if [ "$pr_head_repo" = "${GITHUB_REPOSITORY_OWNER}" ]; then
			fetch_ref="${pr_branch}"
		else
			fetch_ref="pull/${pr_number}/head"
		fi

		if ! git fetch origin "${fetch_ref}" 2>/dev/null; then
			echo "::warning::Could not fetch branch '${pr_branch}' for PR #${pr_number}; excluding"
			excluded+=("${pr_number}")
			continue
		fi
		if git merge --no-ff FETCH_HEAD \
			-m "Merge remediation PR #${pr_number}: ${pr_title}" 2>/dev/null; then
			echo "Merged PR #${pr_number}"
			included+=("${pr_number}")
		else
			git merge --abort 2>/dev/null || true
			echo "::warning::Merge conflict for PR #${pr_number} (${pr_branch}); excluding"
			excluded+=("${pr_number}")
		fi
	done < <(echo "$resolved_plans" | jq -r '.[] | [(.pr_number | tostring), .pr_branch, .pr_title] | @tsv')

	pushed=false
	if [ "${#included[@]}" -gt 0 ]; then
		if git push --force origin "${branch_name}"; then
			pushed=true
			echo "Pushed ${branch_name}"
		else
			echo "::warning::Failed to push ${branch_name}"
		fi
	else
		echo "No PRs merged successfully for ${branch_name}; skipping push"
	fi

	included_json="$([ "${#included[@]}" -gt 0 ] && printf '%s\n' "${included[@]}" | grep -v '^null$' | jq -R 'tonumber' | jq -sc '.' || echo '[]')"
	excluded_json="$([ "${#excluded[@]}" -gt 0 ] && printf '%s\n' "${excluded[@]}" | grep -v '^null$' | jq -R 'tonumber' | jq -sc '.' || echo '[]')"

	tmp="$(mktemp)"
	jq \
		--arg cat "${category}" \
		--arg branch "${branch_name}" \
		--argjson included "${included_json}" \
		--argjson excluded "${excluded_json}" \
		--argjson pushed "$([ "${pushed}" = "true" ] && echo true || echo false)" \
		'.branches[$cat] = {
      branch:       $branch,
      included_prs: $included,
      excluded_prs: $excluded,
      pushed:       $pushed
    }' "$RESULTS_FILE" >"$tmp"
	mv "$tmp" "$RESULTS_FILE"

	echo "::endgroup::"
done

echo "Branch creation complete."

# Placeholder plans are split by severity and impact and put on separate stub branches.
echo "Creating stub branches for placeholder PRs..."

placeholder_plans="$(jq -r '
  (.groups // .) |
  to_entries[] |
  .value.plans[]? |
  select(.action.action_type == "placeholder_pr") |
  [
    (.package.effective_severity // .package.severity // "unknown" | ascii_downcase),
    (if .fix.fix_class == "BREAKING_BUMP" then "breaking" else "non-breaking" end),
    .package.name,
    .package.ecosystem,
    .plan_id,
    (.action.target_package // .package.name),
    (.fix.non_breaking_fix // .fix.breaking_fix // .fix.upgrade_version // .package.remediated_version // "")
  ] | @tsv
' "$OUTPUT_FILE")"

get_plan_markdown() {
	local pid="$1"
	jq -r --arg pid "$pid" '
    (.groups // .) |
    to_entries[] |
    .value.plans[]? |
    select(.plan_id == $pid) |
    .action.placeholder_markdown
  ' "$OUTPUT_FILE"
}

declare -A group_plan_count
mkdir -p /tmp/remediation-plans

while IFS=$'\t' read -r sev imp pkg_name ecosystem plan_id target_pkg fix_ver; do
	[ -z "$plan_id" ] && continue

	group_key="${sev}-${imp}"
	stub_branch="security-remediation/placeholder/${group_key}"
	content_file="/tmp/remediation-plans/${group_key}.md"

	if [ "${group_plan_count[$group_key]:-0}" -eq 0 ]; then
		{
			echo "# ${sev} Severity (${imp}) - Security Remediation Plan"
			echo
		} >"${content_file}"
	fi

	get_plan_markdown "$plan_id" >>"${content_file}"
	echo >>"${content_file}"
	group_plan_count[$group_key]=$((${group_plan_count[$group_key]:-0} + 1))

	tmp="$(mktemp)"
	jq \
		--arg plan_id "${plan_id}" \
		--arg branch "${stub_branch}" \
		'.stubs[$plan_id] = { branch: $branch }' \
		"$RESULTS_FILE" >"$tmp"
	mv "$tmp" "$RESULTS_FILE"

done <<<"$placeholder_plans"

for group_key in "${!group_plan_count[@]}"; do
	stub_branch="security-remediation/placeholder/${group_key}"
	content_file="/tmp/remediation-plans/${group_key}.md"

	echo "::group::Stub branch (single impact): ${stub_branch}"

	git checkout -B "${stub_branch}" "origin/${BASE_BRANCH}"

	plan_file="remediation-plan/plan-${group_key}.md"
	mkdir -p remediation-plan
	cp "${content_file}" "${plan_file}"
	git add "${plan_file}"

	if git diff --cached --quiet; then
		echo "::warning::No changes staged for ${stub_branch} after writing ${plan_file}; this should not happen"
	else
		git commit -m "chore: update security remediation plan for ${group_key} (${group_plan_count[$group_key]} package(s))"
	fi

	if git push --force origin "${stub_branch}"; then
		echo "Pushed ${stub_branch}"
	else
		echo "::warning::Failed to push ${stub_branch}"
		tmp="$(mktemp)"
		jq --arg b "${stub_branch}" '
      .stubs |= with_entries(select(.value.branch != $b))
    ' "$RESULTS_FILE" >"$tmp"
		mv "$tmp" "$RESULTS_FILE"
	fi
	echo "::endgroup::"
done

echo "Stub branch creation complete."
cat "$RESULTS_FILE"
