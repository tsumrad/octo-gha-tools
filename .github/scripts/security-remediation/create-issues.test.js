const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, 'create-issues.js'), 'utf8');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

test('tracking issues group by ecosystem and major package or minor-patch, across severities', async () => {
  const plan = (name, ecosystem, major = false) => ({
    package: { name, ecosystem, effective_severity: 'medium', unique_ghsas: [], current_version_range: '1.0.0' },
    fix: { fix_class: major ? 'BREAKING_BUMP' : 'NON_BREAKING_BUMP' },
    action: { action_type: 'open_issue' }, state: {},
  });
  const raw = { groups: {
    medium: { plans: [plan('axios', 'npm', true), plan('vite', 'npm', true),
      plan('postcss', 'npm'), plan('nanoid', 'npm'), plan('cryptography', 'pip')] },
    high: { plans: [plan('postcss', 'npm')] },
  } };
  raw.groups.high.plans[0].package.effective_severity = 'high';
  const starlette = plan('starlette', 'pip');
  starlette.package.relationship = 'transitive';
  starlette.package.dependency_occurrences = [{ package: 'starlette', version: '0.50.0',
    introducers: [{ package: 'fastapi', version: '0.125.0' },
      { package: 'fastapi-sqlalchemy', version: '0.2.1' }] }];
  raw.groups.medium.plans.push(starlette);
  // Pre-existing PRs matched upstream (not created by this script).
  raw.groups.medium.plans[2].action = { action_type: 'rollup_pr', pr_number: 10, pull_url: 'https://example.test/10' };
  raw.groups.high.plans[0].action = { action_type: 'rollup_pr', pr_number: 11, pull_url: 'https://example.test/11' };
  raw.groups.medium.plans[4].action = { action_type: 'rollup_pr', pr_number: 20, pull_url: 'https://example.test/20' };

  const remediationPlan = { summary: { context: {
    total_vulnerabilities: 61, total_code_scanning_alerts: 3,
    total_reviewed_prs: 9, total_ignored_prs: 8, total_remediation_prs: 1,
  }, ecosystem_summary: [] } };

  const created = [];
  const updated = [];
  let output;
  const existingTitle = '[Security Remediation] [npm] [Major(axios)]';
  const github = { rest: {
    search: { issuesAndPullRequests: async () => ({ data: { items: [
      { title: existingTitle, number: 42, html_url: 'https://example.test/42' },
    ] } }) },
    issues: {
      getLabel: async () => ({}), setLabels: async () => ({}), addLabels: async () => ({}),
      update: async args => { updated.push(args); },
      create: async args => { created.push(args); return { data: { number: created.length, html_url: 'https://example.test/issue' } }; },
    },
  } };
  const fakeFs = {
    readFileSync: file => JSON.stringify(file === 'orchestrator-output.json' ? remediationPlan : raw),
    existsSync: () => true,
    writeFileSync: (file, data) => { output = JSON.parse(data); },
  };
  await new AsyncFunction('github', 'context', 'core', 'require', 'process', 'console', source)(
    github, { repo: { owner: 'owner', repo: 'repo' }, serverUrl: 'https://github.com', runId: 1 },
    { info() {}, warning(message) { throw new Error(message); } },
    name => { assert.equal(name, 'fs'); return fakeFs; }, { env: { BASE_BRANCH: 'main' } }, console,
  );

  assert.equal(updated.length, 1);
  assert.equal(updated[0].issue_number, 42);
  assert.equal(created.length, 3);
  assert.equal(output.stats.total_issues_created, 4);
  assert.equal(Object.keys(output.created_issues).length, 4);
  assert.equal(output.stats.total_rollup_prs_created, 0);
  assert.deepEqual(output.created_prs, {});

  const minor = created.find(i => i.title === '[Security Remediation] [npm] [Minor-Patch]');
  assert.ok(minor);
  assert.match(minor.body, /Open security alerts \| 61/);
  assert.match(minor.body, /Open code scanning alerts \| 3/);
  assert.match(minor.body, /`postcss`/);
  assert.match(minor.body, /`nanoid`/);
  assert.doesNotMatch(minor.body, /axios|vite|cryptography/);
  assert.match(minor.body, /\[#10\]\(https:\/\/example\.test\/10\)/);

  const pipIssue = created.find(i => i.title.includes('[pip]'));
  assert.ok(pipIssue.body.includes('Transitive dependency **starlette 0.50.0** is introduced via'));
  assert.ok(pipIssue.body.includes('- fastapi 0.125.0 → starlette 0.50.0'));
  assert.ok(pipIssue.body.includes('- fastapi-sqlalchemy 0.2.1 → starlette 0.50.0'));
  assert.match(pipIssue.body, /\[#20\]\(https:\/\/example\.test\/20\)/);

  assert.deepEqual(output.summary, remediationPlan.summary);
  assert.equal(output.stats.total_reviewed_prs, 9);
  assert.doesNotMatch(updated[0].body, /vite|postcss|nanoid|cryptography/);
});

test('creates one tracking issue per package bundle when bundle metadata is present', async () => {
  const planWithBundle = (name, ecosystem, groupName) => ({
    package: { name, ecosystem, effective_severity: 'medium', unique_ghsas: [], current_version_range: '1.0.0' },
    fix: { fix_class: 'NON_BREAKING_BUMP' },
    action: { action_type: 'open_issue' }, state: {},
    bundle: { groupName, ecosystem, severity: 'medium' },
  });
  const raw = { groups: {
    medium: { plans: [
      planWithBundle('underscore', 'npm', 'default'),
      planWithBundle('moment-timezone', 'npm', 'default'),
      planWithBundle('node-sass', 'npm', 'css-tools'),
    ] },
  } };

  const remediationPlan = { summary: { context: {
    total_vulnerabilities: 3, total_code_scanning_alerts: 0,
    total_reviewed_prs: 0, total_ignored_prs: 0, total_remediation_prs: 0,
  } } };

  const created = [];
  let output;
  const github = { rest: {
    search: { issuesAndPullRequests: async () => ({ data: { items: [] } }) },
    issues: {
      getLabel: async () => ({}), setLabels: async () => ({}), addLabels: async () => ({}),
      update: async () => {},
      create: async args => { created.push(args); return { data: { number: created.length, html_url: 'https://example.test/issue' } }; },
    },
  } };
  const fakeFs = {
    readFileSync: file => JSON.stringify(file === 'orchestrator-output.json' ? remediationPlan : raw),
    existsSync: () => true,
    writeFileSync: (file, data) => { output = JSON.parse(data); },
  };
  await new AsyncFunction('github', 'context', 'core', 'require', 'process', 'console', source)(
    github, { repo: { owner: 'owner', repo: 'repo' }, serverUrl: 'https://github.com', runId: 1 },
    { info() {}, warning(message) { throw new Error(message); } },
    name => { assert.equal(name, 'fs'); return fakeFs; }, { env: { BASE_BRANCH: 'main' } }, console,
  );

  assert.equal(created.length, 2);
  const defaultIssue = created.find(i => i.title === '[Security Remediation] [npm] [default]');
  const cssToolsIssue = created.find(i => i.title === '[Security Remediation] [npm] [css-tools]');
  assert.ok(defaultIssue);
  assert.ok(cssToolsIssue);
  assert.match(defaultIssue.body, /`underscore`/);
  assert.match(defaultIssue.body, /`moment-timezone`/);
  assert.doesNotMatch(defaultIssue.body, /node-sass/);
  assert.match(cssToolsIssue.body, /`node-sass`/);
  assert.equal(output.stats.total_issues_created, 2);
});

test('dedupes exact-duplicate vulnerability alerts but keeps distinct alerts sharing one ghsa_id', async () => {
  // Reproduces the brace-expansion scenario from issue #134: the same
  // Dependabot alert (number 162) surfaces twice because its PackageContext
  // resolves at two lockfile manifest paths, and must collapse to one row.
  // Alert 161 shares the same ghsa_id but is a genuinely separate alert (a
  // different vulnerable version range/dependabot alert) and must remain.
  const alert = (number, range) => ({
    number, ghsa_id: 'GHSA-3jxr-9vmj-r5cp', cve_id: null,
    url: `https://github.com/owner/repo/security/dependabot/${number}`,
    summary: 'brace-expansion: DoS via exponential-time expansion', cvss: 5.3,
    vulnerable_range: range, first_patched: '2.1.2',
  });
  const plan = {
    package: {
      name: 'brace-expansion', ecosystem: 'npm', effective_severity: 'medium',
      unique_ghsas: ['GHSA-3jxr-9vmj-r5cp'], current_version_range: '1.0.0',
      vulnerabilities: [
        alert(162, '>= 2.0.0, < 2.1.2'),
        alert(162, '>= 2.0.0, < 2.1.2'), // exact duplicate (same manifest path resolved twice)
        alert(161, '< 1.1.16'), // distinct alert, same ghsa_id, different range
      ],
    },
    fix: { fix_class: 'NON_BREAKING_BUMP' },
    action: { action_type: 'open_issue' }, state: {},
  };
  const raw = { groups: { medium: { plans: [plan] } } };
  const remediationPlan = { summary: { context: {
    total_vulnerabilities: 3, total_code_scanning_alerts: 0,
    total_reviewed_prs: 0, total_ignored_prs: 0, total_remediation_prs: 0,
  } } };
  const created = [];
  let output;
  const github = { rest: {
    search: { issuesAndPullRequests: async () => ({ data: { items: [] } }) },
    issues: {
      getLabel: async () => ({}), setLabels: async () => ({}), addLabels: async () => ({}),
      update: async () => {},
      create: async args => { created.push(args); return { data: { number: created.length, html_url: 'https://example.test/issue' } }; },
    },
  } };
  const fakeFs = {
    readFileSync: file => JSON.stringify(file === 'orchestrator-output.json' ? remediationPlan : raw),
    existsSync: () => true,
    writeFileSync: (file, data) => { output = JSON.parse(data); },
  };
  await new AsyncFunction('github', 'context', 'core', 'require', 'process', 'console', source)(
    github, { repo: { owner: 'owner', repo: 'repo' }, serverUrl: 'https://github.com', runId: 1 },
    { info() {}, warning(message) { throw new Error(message); } },
    name => { assert.equal(name, 'fs'); return fakeFs; }, { env: { BASE_BRANCH: 'main' } }, console,
  );

  const body = created[0].body;
  const occurrences = body.match(/dependabot\/162/g) || [];
  assert.equal(occurrences.length, 1, 'duplicate alert 162 must appear only once');
  assert.match(body, /dependabot\/161/);
});

