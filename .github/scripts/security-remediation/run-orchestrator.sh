#!/usr/bin/env bash
set -euo pipefail

python ./bc-scaffold/security-remediation-agent/main.py \
	--owner "${GITHUB_REPOSITORY_OWNER}" \
	--repo "${GITHUB_REPOSITORY#*/}" \
	>orchestrator-output.json

node .github/scripts/security-remediation/prepare-workflow-output.js
total_plans="$(jq '[.groups[].plans? // [] | length] | add // 0' workflow-plans.json)"
if [ "${total_plans}" -gt 0 ]; then
	echo "has_work=true" >>"$GITHUB_OUTPUT"
else
	echo "has_work=false" >>"$GITHUB_OUTPUT"
fi
echo "Total plans: ${total_plans}"
