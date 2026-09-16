const { test } = require('node:test');
const assert = require('node:assert/strict');
const { prepareOutput } = require('./prepare-workflow-output');

test('normalizes moderate and medium in filters, alerts, and issue severity', () => {
  const raw = { plan_id: 'alias', remediation_plan_bundles: [
    { groupName: 'group-a', ecosystem: 'npm', packages: [
      { remediation_package: 'a', ecosystem: 'npm', packages: [{ vulnerabilities: [{ severity: 'medium' }] }] },
      { remediation_package: 'b', ecosystem: 'npm', packages: [{ vulnerabilities: [{ severity: 'Moderate' }, { severity: 'low' }] }] },
    ] },
    { groupName: 'group-b', ecosystem: 'npm', severity: 'moderate', packages: [
      { remediation_package: 'c', ecosystem: 'npm', packages: [{}] },
    ] },
  ] };
  for (const filter of ['moderate', 'medium', ' Medium, MODERATE ']) {
    const result = prepareOutput(raw, filter);
    assert.deepEqual(Object.keys(result.groups), ['medium']);
    assert.equal(result.groups.medium.plans.length, 3);
    assert.ok(result.groups.medium.plans.every(p => p.package.effective_severity === 'medium'));
  }
});

test('adapts ecosystem packages, chooses highest severity and routes actions', () => {
  const basePkg = (overrides = {}) => ({
    remediation_package: 'example',
    ecosystem: 'pip',
    current_version: '1.0',
    remediation_version: '1.2',
    packages: [{ vulnerabilities: [{ severity: 'low' }, { severity: 'high', ghsa_id: 'GHSA-example' }] }],
    remediation_prs: [{ pr_number: 12, version_bumps: [{ package: 'example', to_version: '1.2' }] }],
    ...overrides,
  });
  const raw = { plan_id: 'plan', remediation_plan_bundles: [{ groupName: 'default', ecosystem: 'pip', packages: [
    basePkg(),
    basePkg({ packages: [{ vulnerabilities: [{ severity: 'low' }, { severity: 'high', ghsa_id: 'GHSA-example' }], isbreakable: true }] }),
    basePkg({ remediation_prs: [] }),
    basePkg({ remediation_version: '', remediation_prs: [] }),
    basePkg({ remediation_prs: [{ pr_number: 13, version_bumps: [{ package: 'example', to_version: '1.1' }] }] }),
  ] }] };
  const plans = prepareOutput(raw).groups.high.plans;
  assert.deepEqual(plans.map(p => p.action.action_type),
    ['rollup_pr', 'standalone_pr', 'placeholder_pr', 'open_issue', 'placeholder_pr']);
  assert.equal(plans[0].action.pr_number, 12);
  assert.equal(plans[0].package.ecosystem, 'pip');
  assert.equal(plans[1].fix.fix_class, 'BREAKING_BUMP');
  assert.equal(new Set(plans.map(p => p.plan_id)).size, 5);
  assert.match(plans[2].action.placeholder_markdown, /GHSA-example/);
  assert.deepEqual(prepareOutput(raw, 'critical').groups, {});
  assert.ok(plans.every(p => p.bundle.groupName === 'default' && p.bundle.ecosystem === 'pip'));
});

test('marks a package transitive when any underlying PackageContext is non-root', () => {
  const raw = { plan_id: 'plan', remediation_plan_bundles: [{ groupName: 'grp', ecosystem: 'npm', packages: [
    { remediation_package: 'child', ecosystem: 'npm', current_version: '1.0', remediation_version: '1.1',
      packages: [{ relationship: 'transitive', vulnerabilities: [{ severity: 'high' }],
        transitive_dependency_occurrences: [{ package: 'child', version: '1.0', introducers: [{ package: 'parent', version: '2.0' }] }] }] },
  ] }] };
  const [plan] = prepareOutput(raw).groups.high.plans;
  assert.equal(plan.package.relationship, 'transitive');
  assert.equal(plan.package.dependency_occurrences.length, 1);
});

test('a direct package stays direct even when it also introduces an unrelated transitive vulnerability', () => {
  // Reproduces the axios scenario: axios is a direct dependency, but it also
  // introduces follow-redirects transitively. The remediation planner keys
  // the follow-redirects fix recommendation by the introducer's name
  // ("axios"), so RemeditionPackage("axios").packages ends up containing
  // BOTH axios's own (direct) PackageContext and follow-redirects's
  // (transitive) PackageContext. Only axios's own context should determine
  // axios's relationship.
  const raw = { plan_id: 'plan', remediation_plan_bundles: [{ groupName: 'grp', ecosystem: 'npm', packages: [
    { remediation_package: 'axios', ecosystem: 'npm', current_version: '0.28.0', remediation_version: '1.7.9',
      packages: [
        { name: 'axios', relationship: 'direct', vulnerabilities: [{ severity: 'high', package: 'axios' }] },
        { name: 'follow-redirects', relationship: 'transitive', vulnerabilities: [{ severity: 'high', package: 'follow-redirects' }],
          transitive_dependency_occurrences: [{ package: 'follow-redirects', version: '1.15.6',
            introducers: [{ package: 'axios', version: '0.28.0' }] }] },
      ] },
  ] }] };
  const [plan] = prepareOutput(raw).groups.high.plans;
  assert.equal(plan.package.relationship, 'direct');
});

test('dedupes vulnerability alerts merged across multiple PackageContext entries for one package', () => {
  // Reproduces the node-forge inflated-count scenario: node-forge resolves at
  // multiple lockfile locations/manifest paths, each producing its own
  // PackageContext carrying the SAME 11 Dependabot alerts. Without dedup,
  // flatMap((pkg.packages || []).vulnerabilities) triples that to 33+ and
  // inflates the "Vulnerability Categories" counts in generate-step-summary.sh
  // (which reads plan.package.vulnerabilities.length from workflow-plans.json).
  const alerts = [
    { number: 1, ghsa_id: 'GHSA-one', severity: 'high' },
    { number: 2, ghsa_id: 'GHSA-two', severity: 'high' },
  ];
  const raw = { plan_id: 'plan', remediation_plan_bundles: [{ groupName: 'grp', ecosystem: 'npm', packages: [
    { remediation_package: 'node-forge', ecosystem: 'npm', current_version: '0.10.0', remediation_version: '1.3.2',
      packages: [
        { name: 'node-forge', relationship: 'transitive', vulnerabilities: alerts },
        { name: 'node-forge', relationship: 'transitive', vulnerabilities: alerts }, // duplicate manifest-path occurrence
        { name: 'node-forge', relationship: 'transitive', vulnerabilities: alerts }, // duplicate manifest-path occurrence
      ] },
  ] }] };
  const [plan] = prepareOutput(raw).groups.high.plans;
  assert.equal(plan.package.vulnerabilities.length, 2);
  assert.deepEqual(plan.package.unique_ghsas.sort(), ['GHSA-one', 'GHSA-two']);
});

test('accepts empty plans and rejects missing output or invalid severity', () => {
  assert.deepEqual(prepareOutput({ remediation_plan_bundles: [] }), { groups: {} });
  assert.throws(() => prepareOutput(null), /RemediationPlan/);
  assert.throws(() => prepareOutput({ remediation_plan_bundles: [] }, 'invalid'), /Invalid severity/);
});
