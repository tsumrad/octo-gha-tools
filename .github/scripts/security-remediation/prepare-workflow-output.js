// Adapt the orchestrator's RemediationPlan to the workflow presentation model.
const fs = require('fs');
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'];

function normalizeSeverity(value) {
  const severity = value?.trim().toLowerCase();
  return severity === 'moderate' ? 'medium' : severity;
}

function prepareOutput(raw, severities = 'critical,high,medium,low') {
  if (!raw || !Array.isArray(raw.remediation_plans)) {
    throw new Error('Expected orchestrator RemediationPlan.remediation_plans array');
  }
  const selected = new Set(severities.split(',').map(normalizeSeverity));
  for (const severity of selected) {
    if (!SEVERITIES.includes(severity)) throw new Error(`Invalid severity: ${severity}`);
  }
  const groups = {};
  for (const [issueIndex, issue] of raw.remediation_plans.entries()) {
    for (const [packageIndex, pkg] of issue.packages.entries()) {
      const vulnerabilities = pkg.vulnerabilities || [];
      const severity = SEVERITIES.find(s => vulnerabilities.some(v => normalizeSeverity(v.severity) === s))
        || normalizeSeverity(issue.severity) || 'unknown';
      if (!selected.has(severity)) continue;
      const target = pkg.upgrade_to_version || pkg.fixed_maximum_version || pkg.fixed_minimum_version || '';
      // Only reuse a PR whose package and target match the planned upgrade.
      const pr = target && (pkg.pull_requests || []).find(p => p.pr_number &&
        (p.version_bumps || []).some(b => b.package.toLowerCase() === pkg.name.toLowerCase() && b.to_version === target));
      const action = pkg.action_type || (target
        ? (pr ? (pkg.isbreakable ? 'standalone_pr' : 'rollup_pr') : 'placeholder_pr')
        : 'open_issue');
      const actionType = ['rollup_pr', 'standalone_pr'].includes(action) && !pr ? 'placeholder_pr' : action;
      const advisories = [...new Set(vulnerabilities.map(v => v.ghsa_id).filter(Boolean))];
      const markdown = `### ${pkg.name} (${pkg.ecosystem || issue.ecosystem})\n\n` +
        `- [ ] **AC:** Upgrade \`${pkg.name}\` from \`${pkg.current_version || 'unknown'}\` to \`${target || 'no known fix'}\` ` +
        `(${pkg.relationship || 'unknown'}, ${pkg.isbreakable ? 'breaking' : 'non-breaking'}). Resolve ${advisories.join(', ') || 'the reported vulnerabilities'} and run the project tests.\n`;
      const plan = {
        plan_id: `${raw.plan_id}-${issueIndex}-${packageIndex}`,
        package: { ...pkg, ecosystem: pkg.ecosystem || issue.ecosystem,
          effective_severity: severity, current_version_range: pkg.current_version || 'unknown', unique_ghsas: advisories },
        fix: { fix_class: pkg.isbreakable ? 'BREAKING_BUMP' : (target ? 'NON_BREAKING_BUMP' : 'NO_FIX_AVAILABLE'), upgrade_version: target },
        action: { action_type: actionType, pr_number: pr?.pr_number || null,
          pull_url: pr?.pull_url || '', target_package: pkg.name, placeholder_markdown: markdown },
        state: {},
      };
      (groups[severity] ||= { plans: [] }).plans.push(plan);
    }
  }
  return { groups };
}

if (require.main === module) {
  const raw = JSON.parse(fs.readFileSync('orchestrator-output.json', 'utf8'));
  fs.writeFileSync('workflow-plans.json', JSON.stringify(prepareOutput(raw, process.env.SEVERITIES), null, 2));
}
module.exports = { prepareOutput };
