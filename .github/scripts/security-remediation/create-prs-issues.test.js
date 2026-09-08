const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, 'create-prs-issues.js'), 'utf8');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

test('tracking issues group by ecosystem, major package or minor-patch, and severity', async () => {
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
  const created = [];
  const updated = [];
  let output;
  const existingTitle = '[Security Remediation] [npm] [Major(axios)] [Medium] Vulnerability Remediation Tracking';
  const github = { rest: {
    search: { issuesAndPullRequests: async () => ({ data: { items: [
      { title: existingTitle, number: 42, html_url: 'https://example.test/42' },
    ] } }) },
    issues: {
      getLabel: async () => ({}), setLabels: async () => ({}),
      update: async args => { updated.push(args); },
      create: async args => { created.push(args); return { data: { number: created.length, html_url: 'https://example.test/issue' } }; },
    },
  } };
  const fakeFs = {
    readFileSync: () => JSON.stringify(raw), existsSync: () => false,
    writeFileSync: (file, data) => { output = JSON.parse(data); },
  };
  await new AsyncFunction('github', 'context', 'core', 'require', 'process', 'console', source)(
    github, { repo: { owner: 'owner', repo: 'repo' }, serverUrl: 'https://github.com', runId: 1 },
    { info() {}, warning(message) { throw new Error(message); } },
    name => { assert.equal(name, 'fs'); return fakeFs; }, { env: { BASE_BRANCH: 'main' } }, console,
  );
  assert.equal(updated.length, 1);
  assert.equal(updated[0].issue_number, 42);
  assert.equal(created.length, 4);
  assert.equal(output.stats.total_issues_created, 5);
  assert.equal(Object.keys(output.created_issues).length, 5);
  const minor = created.find(i => i.title === '[Security Remediation] [npm] [Minor-Patch] [Medium] Vulnerability Remediation Tracking');
  assert.ok(minor);
  assert.match(minor.body, /`postcss`/);
  assert.match(minor.body, /`nanoid`/);
  assert.doesNotMatch(minor.body, /axios|vite|cryptography/);
  assert.doesNotMatch(updated[0].body, /vite|postcss|nanoid|cryptography/);
});
