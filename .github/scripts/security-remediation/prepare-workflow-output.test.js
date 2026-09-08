const { test } = require('node:test');
const assert = require('node:assert/strict');
const { prepareOutput } = require('./prepare-workflow-output');

test('normalizes moderate and medium in filters, alerts, and issue severity', () => {
  const raw = { plan_id: 'alias', remediation_plans: [
    { packages: [{ name: 'a', vulnerabilities: [{ severity: 'medium' }] },
      { name: 'b', vulnerabilities: [{ severity: 'Moderate' }, { severity: 'low' }] }] },
    { severity: 'moderate', packages: [{ name: 'c' }] },
  ] };
  for (const filter of ['moderate', 'medium', ' Medium, MODERATE ']) {
    const result = prepareOutput(raw, filter);
    assert.deepEqual(Object.keys(result.groups), ['medium']);
    assert.equal(result.groups.medium.plans.length, 3);
    assert.ok(result.groups.medium.plans.every(p => p.package.effective_severity === 'medium'));
  }
});

test('adapts ecosystem packages, chooses highest severity and routes actions', () => {
  const pkg = { name: 'example', current_version: '1.0', upgrade_to_version: '1.2',
    vulnerabilities: [{ severity: 'low' }, { severity: 'high', ghsa_id: 'GHSA-example' }],
    pull_requests: [{ pr_number: 12, version_bumps: [{ package: 'example', to_version: '1.2' }] }] };
  const raw = { plan_id: 'plan', remediation_plans: [{ ecosystem: 'pip', packages: [
    pkg, { ...pkg, isbreakable: true }, { ...pkg, pull_requests: [] },
    { ...pkg, upgrade_to_version: '', pull_requests: [] },
    { ...pkg, pull_requests: [{ pr_number: 13, version_bumps: [{ package: 'example', to_version: '1.1' }] }] },
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
});

test('accepts empty plans and rejects missing output or invalid severity', () => {
  assert.deepEqual(prepareOutput({ remediation_plans: [] }), { groups: {} });
  assert.throws(() => prepareOutput(null), /RemediationPlan/);
  assert.throws(() => prepareOutput({ remediation_plans: [] }, 'invalid'), /Invalid severity/);
});
