// Adapt the orchestrator's RemediationPlan to the workflow presentation model.
const fs = require('fs');
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'];

function normalizeSeverity(value) {
  const severity = value?.trim().toLowerCase();
  return severity === 'moderate' ? 'medium' : severity;
}

// A RemeditionPackage is direct when none of its OWN PackageContext entries
// (i.e. those describing this exact package, not a transitive child it
// happens to introduce/fix) are marked transitive. RemeditionPackage.packages
// can contain PackageContext entries for other vulnerable packages this
// package introduces as a parent - those must not affect this package's own
// direct/transitive classification.
function ownPackageContexts(remediationPackage) {
  const name = (remediationPackage.remediation_package || '').toLowerCase();
  const own = (remediationPackage.packages || []).filter(pkg => (pkg.name || '').toLowerCase() === name);
  return own.length ? own : (remediationPackage.packages || []);
}

function isTransitivePackage(remediationPackage) {
  return ownPackageContexts(remediationPackage).some(pkg => (pkg.relationship || '').toLowerCase() === 'transitive'
    || pkg.is_direct === false);
}

// A bundle package is breakable if any of its OWN PackageContext entries say so.
function isBreakablePackage(remediationPackage) {
  return ownPackageContexts(remediationPackage).some(pkg => pkg.isbreakable === true);
}

// A vulnerability alert (GHSA/CVE) can be attached to more than one
// PackageContext for the same remediation package - e.g. once per lockfile
// manifest path it resolves at - so dedupe by advisory identity before it
// feeds severity/advisory computation downstream.
function dedupeVulnerabilities(vulnerabilities) {
  const seen = new Set();
  const deduped = [];
  for (const vulnerability of vulnerabilities) {
    const key = (vulnerability.ghsa_id || vulnerability.cve_id || vulnerability.url || JSON.stringify(vulnerability)).toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(vulnerability);
  }
  return deduped;
}

function prepareOutput(raw, severities = 'critical,high,medium,low') {
  if (!raw || !Array.isArray(raw.remediation_plan_bundles)) {
    throw new Error('Expected orchestrator RemediationPlan.remediation_plan_bundles array');
  }
  const selected = new Set(severities.split(',').map(normalizeSeverity));
  for (const severity of selected) {
    if (!SEVERITIES.includes(severity)) throw new Error(`Invalid severity: ${severity}`);
  }
  const groups = {};
  for (const [bundleIndex, bundle] of raw.remediation_plan_bundles.entries()) {
    const bundleEcosystem = bundle.ecosystem || 'unknown';
    for (const [packageIndex, pkg] of (bundle.packages || []).entries()) {
      const vulnerabilities = dedupeVulnerabilities((pkg.packages || []).flatMap(p => p.vulnerabilities || []));
      const severity = SEVERITIES.find(s => vulnerabilities.some(v => normalizeSeverity(v.severity) === s))
        || normalizeSeverity(bundle.severity) || 'unknown';
      if (!selected.has(severity)) continue;
      const name = pkg.remediation_package;
      const ecosystem = pkg.ecosystem || bundleEcosystem;
      const target = pkg.remediation_version || '';
      const isbreakable = isBreakablePackage(pkg);
      const relationship = isTransitivePackage(pkg) ? 'transitive' : 'direct';
      // Only reuse a PR whose package and target match the planned upgrade.
      const pr = target && (pkg.remediation_prs || []).find(p => p.pr_number &&
        (p.version_bumps || []).some(b => b.package.toLowerCase() === name.toLowerCase() && b.to_version === target));
      const action = bundle.action_type || (target
        ? (pr ? (isbreakable ? 'standalone_pr' : 'rollup_pr') : 'placeholder_pr')
        : 'open_issue');
      const actionType = ['rollup_pr', 'standalone_pr'].includes(action) && !pr ? 'placeholder_pr' : action;
      const advisories = [...new Set(vulnerabilities.map(v => v.ghsa_id).filter(Boolean))];
      const dependencyOccurrences = (pkg.packages || []).flatMap(p => p.transitive_dependency_occurrences || []);
      const markdown = `### ${name} (${ecosystem})\n\n` +
        `- [ ] **AC:** Upgrade \`${name}\` from \`${pkg.current_version || 'unknown'}\` to \`${target || 'no known fix'}\` ` +
        `(${relationship}, ${isbreakable ? 'breaking' : 'non-breaking'}). Resolve ${advisories.join(', ') || 'the reported vulnerabilities'} and run the project tests.\n`;
      const plan = {
        plan_id: `${raw.plan_id || 'plan'}-${bundleIndex}-${packageIndex}`,
        package: {
          name,
          ecosystem,
          relationship,
          current_version: pkg.current_version,
          current_version_range: pkg.current_version || 'unknown',
          vulnerabilities,
          pull_requests: pkg.remediation_prs || [],
          dependency_occurrences: dependencyOccurrences,
          effective_severity: severity,
          unique_ghsas: advisories,
          isbreakable,
        },
        fix: { fix_class: isbreakable ? 'BREAKING_BUMP' : (target ? 'NON_BREAKING_BUMP' : 'NO_FIX_AVAILABLE'), upgrade_version: target },
        action: { action_type: actionType, pr_number: pr?.pr_number || null,
          pull_url: pr?.pull_url || '', target_package: name, placeholder_markdown: markdown },
        state: {},
        // Bundle metadata so create-issues.js can create one tracking
        // issue per package bundle (grouped by bundle.groupName) instead
        // of by ecosystem/impact heuristics.
        bundle: { groupName: bundle.groupName || 'default', ecosystem: bundleEcosystem, severity: bundle.severity || null },
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
