const fs = require('fs');
const { owner, repo } = context.repo;
core.info(`Operating on caller repository: ${owner}/${repo}`);

const raw = JSON.parse(fs.readFileSync('workflow-plans.json', 'utf8'));
const output = raw.groups || raw;
const results = fs.existsSync('rollup-results.json')
  ? JSON.parse(fs.readFileSync('rollup-results.json', 'utf8'))
  : { branches: {} };
const BASE_BRANCH = process.env.BASE_BRANCH;

const IMP_LABEL = { 'non-breaking': 'Non-Breaking', breaking: 'Breaking' };
const ACT_LABEL = { rollup: 'Rollup', standalone: 'Standalone', placeholder: 'Placeholder', 'open-issue': 'Open Issue' };

const ACTION_LABELS = {
  'non-breaking-rollup': { color: '2da44e', description: 'Non-breaking fix included in a rollup PR' },
  'non-breaking-standalone': { color: '6fdd8b', description: 'Non-breaking fix with its own standalone PR' },
  'non-breaking-placeholder': { color: 'a8f0bc', description: 'Non-breaking fix - placeholder PR, needs manual attention' },
  'non-breaking-open-issue': { color: 'd4f5e2', description: 'Non-breaking finding - no fix available, issue opened' },
  'breaking-rollup': { color: 'e85e2b', description: 'Breaking bump included in a rollup PR' },
  'breaking-standalone': { color: 'f5854a', description: 'Breaking bump with its own standalone PR' },
  'breaking-placeholder': { color: 'f8b48a', description: 'Breaking bump - placeholder PR, needs manual attention' },
  'breaking-open-issue': { color: 'fbd9c5', description: 'Breaking finding - no fix available, issue opened' },
  'security-rollup': { color: 'e11d48', description: 'Security vulnerability rollup' },
};

const ACTION_TYPE_TO_SUFFIX = {
  rollup_pr: 'rollup',
  standalone_pr: 'standalone',
  placeholder_pr: 'placeholder',
  open_issue: 'open-issue',
};

function getImpact(plan) {
  return plan.fix.fix_class === 'BREAKING_BUMP' ? 'breaking' : 'non-breaking';
}

function getActionSuffix(plan) {
  return ACTION_TYPE_TO_SUFFIX[plan.action.action_type] || 'open-issue';
}

function getCategory(plan) {
  return `${getImpact(plan)}-${getActionSuffix(plan)}`;
}

function getActionLabel(plan) {
  return `${getImpact(plan)}-${getActionSuffix(plan)}`;
}

function buildAlerts(plan) {
  if (plan.package.vulnerabilities) return plan.package.vulnerabilities;
  const mdSummaries = {};
  const md = plan.action.placeholder_markdown || '';
  for (const m of md.matchAll(/- \*\*(GHSA-[\w-]+)\*\* \(CVSS ([\d.]+)\) - (.+)/g)) {
    mdSummaries[m[1]] = { cvss: parseFloat(m[2]), summary: m[3].trim() };
  }
  return plan.package.unique_ghsas.map(id => ({
    ghsa_id: id,
    cve_id: null,
    summary: mdSummaries[id]?.summary || `Vulnerability in ${plan.package.name}`,
    cvss: mdSummaries[id]?.cvss ?? null,
    url: `https://github.com/advisories/${id}`,
    vulnerable_range: plan.package.current_version_range,
    first_patched: plan.fix.upgrade_version || '—',
  }));
}

async function ensureAllLabels() {
  for (const [name, { color, description }] of Object.entries(ACTION_LABELS)) {
    try {
      await github.rest.issues.getLabel({ owner, repo, name });
    } catch {
      await github.rest.issues.createLabel({ owner, repo, name, color, description });
      core.info(`Created label: ${name}`);
    }
  }
}
await ensureAllLabels();

async function findIssue(title) {
  const q = `repo:${owner}/${repo} is:issue is:open in:title "${title}"`;
  const res = await github.rest.search.issuesAndPullRequests({ q, per_page: 10 });
  return res.data.items.find(i => i.title === title) || null;
}

async function findPR(headBranch) {
  const res = await github.rest.pulls.list({
    owner,
    repo,
    state: 'open',
    head: `${owner}:${headBranch}`,
    per_page: 5,
  });
  return res.data[0] || null;
}

async function appendRollupRefToIssue(issueNumber, rollupPrNumber, rollupPrUrl) {
  if (!issueNumber) return;
  try {
    const current = await github.rest.issues.get({ owner, repo, issue_number: issueNumber });
    const oldBody = current.data.body || '';
    if (oldBody.includes(`#${rollupPrNumber}`)) return;
    const addition = `\n\n**Rollup PR**: #${rollupPrNumber} - [view](${rollupPrUrl})  \n**Status**: Included in rollup`;
    await github.rest.issues.update({ owner, repo, issue_number: issueNumber, body: oldBody + addition });
  } catch (err) {
    core.warning(`Could not update per-PR issue #${issueNumber}: ${err.message}`);
  }
}

const categoryMap = {};
for (const group of Object.values(output)) {
  for (const plan of group.plans) {
    const cat = getCategory(plan);
    if (!categoryMap[cat]) categoryMap[cat] = [];
    categoryMap[cat].push(plan);
  }
}

const createdPRs = {};

for (const [category, branchResult] of Object.entries(results.branches)) {
  if (!branchResult.pushed) continue;

  const plans = categoryMap[category] || [];
  const parts = category.split('-');
  const act = parts[parts.length - 1];
  const imp = parts.slice(0, -1).join('-');

  const prTitle = `[Security Remediation] [${ACT_LABEL[act] || act}] ${IMP_LABEL[imp] || imp} Updates`;

  const included = plans.filter(p => branchResult.included_prs.includes(p.action.pr_number));
  const excluded = plans.filter(p => branchResult.excluded_prs.includes(p.action.pr_number));

  let body = `## [${ACT_LABEL[act] || act}] ${IMP_LABEL[imp] || imp} Dependency Updates\n\n`;
  body += `> Consolidated rollup of **${imp}** **${act}** dependency upgrades addressing open security vulnerabilities.\n\n`;

  if (included.length > 0) {
    body += `### Included Updates\n\n| Package | Type | From | To | Vulnerabilities |\n|---------|------|------|----|-----------------|\n`;
    const allPlans = Object.values(output).flatMap(g => g.plans || []);
    for (const plan of included) {
      const alerts = buildAlerts(plan);
      const vulns = alerts.map(a => `[${a.ghsa_id || a.cve_id || '?'}](${a.url})`).join(', ');
      const transitiveChildren = allPlans.filter(p => {
        const pIsTransitive = (p.package.relationship || '').toLowerCase() === 'transitive';
        if (!pIsTransitive) return false;
        const sources = p.package.transitive_source_package || [];
        return sources.some(src => src.split('@')[0].toLowerCase() === plan.package.name.toLowerCase());
      });
      body += `| \`${plan.package.name}\` | Direct | \`${plan.package.current_version_range}\` | \`${plan.fix.upgrade_version}\` | ${vulns} |\n`;
      for (const child of transitiveChildren) {
        const childVulns = (child.package.unique_ghsas || []).map(id =>
          `[${id}](https://github.com/advisories/${id})`).join(', ');
        const sources = (child.package.transitive_source_package || []).join(', ');
        body += `| -> \`${child.package.name}\` | Transitive via \`${sources}\` | \`${child.package.current_version_range}\` | resolved | ${childVulns} |\n`;
      }
    }
    body += '\n### Resolved Remediation PRs\n\n';
    for (const plan of included) {
      const issueRef = plan.state.issue_id ? ` (issue #${plan.state.issue_id})` : '';
      const pTitle = `${plan.package.name}: upgrade to ${plan.fix.upgrade_version}`;
      body += `- #${plan.action.pr_number} - ${pTitle}${issueRef}\n`;
    }
    body += '\n### Per-Finding Issues\n\n';
    for (const plan of included) {
      if (plan.state.issue_id) {
        body += `- #${plan.state.issue_id} - [${plan.package.name}](${plan.state.issue_url})\n`;
      }
    }
    body += '\n';
  }

  if (excluded.length > 0) {
    body += `### Excluded Updates (Merge Conflict)\n\nThe following remediation PRs could not be automatically merged and require manual attention:\n\n`;
    for (const plan of excluded) {
      body += `- #${plan.action.pr_number} - ${plan.package.name}: upgrade to ${plan.fix.upgrade_version}\n`;
    }
    body += '\n';
  }

  body += `---\n_Generated by [Security Vulnerability Remediation](${context.serverUrl}/${owner}/${repo}/actions/runs/${context.runId})_`;

  const rollupPrLabels = ['security-rollup'];
  const seenActionLabels = new Set();
  for (const plan of [...included, ...excluded]) {
    const al = getActionLabel(plan);
    if (!seenActionLabels.has(al)) {
      seenActionLabels.add(al);
      rollupPrLabels.push(al);
    }
  }

  try {
    const existing = await findPR(branchResult.branch);
    let pr;
    if (existing) {
      await github.rest.pulls.update({ owner, repo, pull_number: existing.number, title: prTitle, body });
      pr = existing;
      core.info(`Updated PR #${existing.number}: ${prTitle}`);
    } else {
      const created = await github.rest.pulls.create({ owner, repo, title: prTitle, body, head: branchResult.branch, base: BASE_BRANCH });
      pr = created.data;
      core.info(`Created PR #${pr.number}: ${prTitle}`);
    }
    await github.rest.issues.addLabels({ owner, repo, issue_number: pr.number, labels: rollupPrLabels }).catch(() => {});
    createdPRs[category] = { number: pr.number, url: pr.html_url, title: prTitle };

    for (const plan of included) {
      const issueNum = plan.state.issue_id ? parseInt(plan.state.issue_id) : null;
      await appendRollupRefToIssue(issueNum, pr.number, pr.html_url);
    }
  } catch (err) {
    core.warning(`Failed to create/update PR for ${category}: ${err.message}`);
  }
}

const stubs = results.stubs || {};
const plansByStubBranch = {};
for (const group of Object.values(output)) {
  for (const plan of group.plans) {
    if (plan.action.action_type !== 'placeholder_pr') continue;
    const stubBranch = stubs[plan.plan_id]?.branch;
    if (!stubBranch) {
      core.warning(`No stub branch found for placeholder plan ${plan.plan_id}; skipping`);
      continue;
    }
    if (!plansByStubBranch[stubBranch]) plansByStubBranch[stubBranch] = [];
    plansByStubBranch[stubBranch].push(plan);
  }
}

for (const [stubBranch, plans] of Object.entries(plansByStubBranch)) {
  const groupKey = stubBranch.split('/').pop();
  const imp = groupKey;

  const prTitle = `[Security Remediation] [Placeholder] ${IMP_LABEL[imp] || imp} Updates`;

  let body = `# Security Remediation - (${IMP_LABEL[imp] || imp}) Placeholder PRs\n\n`;
  body += `This PR tracks **${plans.length}** ${IMP_LABEL[imp] || imp} package(s) requiring manual remediation.\n`;
  body += `See \`remediation-plan/plan-${imp}.md\` on this branch for the full crisp fix spec - `;
  body += `push the actual version bumps to this branch, or assign to a coding agent.\n\n`;

  function extractAcLine(plan) {
    const md = plan.action.placeholder_markdown || '';
    const m = md.match(/- \[ \] \*\*AC:\*\* (.+)/);
    if (m) return m[1].trim();
    const relationship = (plan.package.relationship || '').toLowerCase() === 'transitive'
      ? 'transitive'
      : 'direct';
    const target = plan.fix.upgrade_version || plan.fix.non_breaking_fix || plan.fix.breaking_fix || plan.package.remediated_version || 'no known fix';
    const breaking = plan.fix.fix_class === 'BREAKING_BUMP' || plan.fix.fix_class === 'PARTIAL_FIX_AVAILABLE'
      ? 'BREAKING'
      : 'non-breaking';
    const advisories = (plan.package.unique_ghsas || []).length > 0
      ? (plan.package.unique_ghsas || []).join(', ')
      : 'no advisory ID';
    const sources = plan.package.transitive_source_package || [];
    const sourceText = relationship === 'transitive'
      ? ` via ${sources.length > 0 ? sources.map(s => `\`${s}\``).join(', ') : '\`unknown source package\`'}`
      : '';
    return `Bump \`${plan.package.name}\` (${relationship}${sourceText}): \`${plan.package.current_version_range || 'unknown'}\` -> \`>=${target}\` [${breaking}] - closes ${advisories}`;
  }

  body += `## Acceptance Criteria\n\n`;
  body += `_One line per package - package, current->target version, breaking flag, direct/transitive chain, and every GHSA it closes. Use these directly as the fix spec._\n\n`;
  for (const plan of plans) {
    body += `- [ ] ${extractAcLine(plan)}\n`;
  }
  body += '\n';

  body += `---\n_Generated by [Security Vulnerability Remediation](${context.serverUrl}/${owner}/${repo}/actions/runs/${context.runId})_`;

  const prLabels = ['security-rollup'];
  const seenLabels = new Set();
  for (const plan of plans) {
    const al = getActionLabel(plan);
    if (!seenLabels.has(al)) {
      seenLabels.add(al);
      prLabels.push(al);
    }
  }

  const cat = `${imp}-placeholder`;

  try {
    const existing = await findPR(stubBranch);
    let pr;
    if (existing) {
      await github.rest.pulls.update({ owner, repo, pull_number: existing.number, title: prTitle, body });
      pr = existing;
      core.info(`Updated placeholder PR #${existing.number}: ${prTitle}`);
    } else {
      const created = await github.rest.pulls.create({
        owner,
        repo,
        title: prTitle,
        body,
        head: stubBranch,
        base: BASE_BRANCH,
        draft: true,
      });
      pr = created.data;
      core.info(`Created placeholder PR #${pr.number}: ${prTitle}`);
    }
    await github.rest.issues.addLabels({ owner, repo, issue_number: pr.number, labels: prLabels }).catch(() => {});

    createdPRs[cat] = plans.map(p => ({
      number: pr.number,
      url: pr.html_url,
      title: prTitle,
      package: p.package.name,
    }));
  } catch (err) {
    core.warning(`Failed to create/update placeholder PR for ${stubBranch}: ${err.message}`);
  }
}

const createdIssues = {};
const issueGroups = new Map();

for (const sourceGroup of Object.values(output)) {
  for (const plan of sourceGroup.plans || []) {
    const ecosystem = plan.package.ecosystem || 'unknown';
    const upgradeGroup = getImpact(plan) === 'breaking'
      ? `Major(${plan.package.name})` : 'Minor-Patch';
    const key = JSON.stringify([ecosystem, upgradeGroup]);
    if (!issueGroups.has(key)) {
      issueGroups.set(key, { ecosystem, upgradeGroup, plans: [] });
    }
    issueGroups.get(key).plans.push(plan);
  }
}

for (const [issueKey, group] of issueGroups) {
  const { ecosystem, upgradeGroup } = group;
  const groupPlans = new Set(group.plans);
  const groupPRs = cat => {
    const prs = createdPRs[cat];
    return Array.isArray(prs)
      ? prs.filter(pr => group.plans.some(plan => plan.package.name === pr.package))
      : prs;
  };

  const nbPlans = group.plans.filter(p => p.fix.fix_class !== 'BREAKING_BUMP');
  const bPlans = group.plans.filter(p => p.fix.fix_class === 'BREAKING_BUMP');
  const isTransitivePkg = p => (p.package.relationship || '').toLowerCase() === 'transitive' || p.package.is_transitive === true;
  const directPlans = group.plans.filter(p => !isTransitivePkg(p));
  const transitivePs = group.plans.filter(isTransitivePkg);
  const totalAlerts = group.plans.reduce((n, p) => n + (p.package.unique_ghsas || []).length, 0);
  const title = `[Security Remediation] [${ecosystem}] [${upgradeGroup}] Vulnerability Remediation Tracking`;

  const uniqueDeps = arr => [...new Set(arr.map(p => p.package.name))].join(', ') || '—';
  const allDepsStr = uniqueDeps(group.plans);
  const directDepsStr = uniqueDeps(directPlans);
  const transitiveDepsStr = uniqueDeps(transitivePs);
  const nbDepsStr = uniqueDeps(nbPlans);
  const bDepsStr = uniqueDeps(bPlans);

  let body = `# [${ecosystem}] [${upgradeGroup}] Vulnerability Remediation Tracking\n\n`;
  body += `**Base Branch**: \`${BASE_BRANCH}\`\n`;
  body += `**Workflow Run**: [#${context.runId}](${context.serverUrl}/${owner}/${repo}/actions/runs/${context.runId})\n\n`;

  body += `## Summary\n\n| Category | Count | Dependencies |\n|---|---|---|\n`;
  body += `| Total security alerts | ${totalAlerts} | ${allDepsStr} |\n`;
  body += `| Direct dependencies affected | ${directPlans.length} | ${directDepsStr} |\n`;
  body += `| Transitive dependencies affected | ${transitivePs.length} | ${transitiveDepsStr} |\n`;
  body += `| Non-breaking updates | ${nbPlans.length} | ${nbDepsStr} |\n`;
  body += `| Breaking updates | ${bPlans.length} | ${bDepsStr} |\n\n`;

  const rollupRows = [];
  for (const imp of ['non-breaking', 'breaking']) {
    for (const act of ['rollup', 'standalone', 'placeholder', 'open-issue']) {
      const cat = `${imp}-${act}`;
      const cPlans = (categoryMap[cat] || []).filter(plan => groupPlans.has(plan));
      if (cPlans.length === 0) continue;
      const prInfo = groupPRs(cat);
      const br = results.branches?.[cat];
      const pkgList = cPlans.map(p => `\`${p.package.name}\``).join(', ');

      let link;
      let status;
      if (act === 'open-issue') {
        link = '—';
        status = 'No fix available - issue tracking only';
      } else if (act === 'placeholder') {
        if (prInfo && prInfo.length > 0) {
          const uniq = [...new Map(prInfo.map(p => [p.number, p])).values()];
          link = uniq.map(p => `[#${p.number}](${p.url})`).join(', ');
          status = 'Draft - awaiting agent/manual fix';
        } else {
          link = '—';
          status = 'Stub branch creation failed';
        }
      } else if (prInfo) {
        if (Array.isArray(prInfo)) {
          const links = [...new Map(prInfo.map(p => [p.number, p])).values()]
            .map(p => `[#${p.number}](${p.url})`).join(', ');
          link = links;
          status = 'Open';
        } else {
          link = `[${prInfo.title}](${prInfo.url})`;
          status = 'Open';
        }
      } else if (br?.pushed) {
        link = `\`security-remediation/${cat}\``;
        status = 'Branch created (PR unavailable)';
      } else {
        link = `\`security-remediation/${cat}\``;
        status = 'Branch creation failed';
      }
      rollupRows.push(`| ${IMP_LABEL[imp]} | ${ACT_LABEL[act] || act} | ${pkgList} | ${link} | ${status} |`);
    }
  }

  body += `## Remediation Pull Requests\n\n`;
  body += rollupRows.length > 0
    ? `| Impact | Action | Package | Pull Request | Status |\n|---|---|---|---|---|\n${rollupRows.join('\n')}\n\n`
    : '_No remediation PRs created._\n\n';

  for (const imp of ['non-breaking', 'breaking']) {
    for (const act of ['rollup', 'standalone', 'placeholder', 'open-issue']) {
      const cat = `${imp}-${act}`;
      const cPlans = (categoryMap[cat] || []).filter(plan => groupPlans.has(plan));
      if (cPlans.length === 0) continue;
      body += `## ${IMP_LABEL[imp]} - ${ACT_LABEL[act]} Updates\n\n`;

      if (act === 'placeholder') {
        const phPRs = groupPRs(cat) || [];
        const uniqPRs = [...new Map(phPRs.map(p => [p.number, p])).values()];
        if (uniqPRs.length > 0) {
          body += `**Placeholder PR**: ${uniqPRs.map(p => `[#${p.number}](${p.url})`).join(', ')} _(draft - push fixes or assign to agent)_\n\n`;
        }
      }

      for (const plan of cPlans) {
        const br = results.branches?.[cat];
        const inRollup = br?.included_prs?.includes(plan.action.pr_number);
        let status;
        if (plan.action.action_type === 'open_issue') {
          status = 'No fix available - tracking issue opened';
        } else if (plan.action.action_type === 'placeholder_pr') {
          status = 'Placeholder - awaiting agent/manual fix';
        } else {
          status = inRollup ? 'Included in rollup' : 'Excluded - merge conflict';
        }
        const alerts = buildAlerts(plan);
        const isTransitive = (plan.package.relationship || '').toLowerCase() === 'transitive' || plan.package.is_transitive === true;
        const transitiveOf = plan.package.transitive_source_packages || plan.package.transitive_source_package || [];
        const allPlans = group.plans;
        const transitiveChildren = allPlans.filter(p => {
          const pIsTransitive = (p.package.relationship || '').toLowerCase() === 'transitive' || p.package.is_transitive === true;
          if (!pIsTransitive) return false;
          const sources = p.package.transitive_source_packages || p.package.transitive_source_package || [];
          return sources.some(src => src.split('@')[0].toLowerCase() === plan.package.name.toLowerCase());
        });

        body += `### \`${plan.package.name}\`: \`${plan.package.current_version_range}\` -> \`${plan.fix.upgrade_version || plan.fix.non_breaking_fix || 'N/A'}\`\n\n`;
        body += `- **Remediation Status**: ${status}\n`;
        if (isTransitive) {
          const srcList = Array.isArray(transitiveOf) ? transitiveOf.join(', ') : String(transitiveOf);
          body += `- **Dependency Type**: Transitive (pulled in by: \`${srcList}\`)\n`;
          const fixVer = plan.fix.non_breaking_fix || plan.fix.breaking_fix || plan.fix.upgrade_version;
          if (fixVer) body += `- **Required Action**: Bump \`${plan.action.target_package}\` to \`>= ${fixVer}\`\n`;
          const mdNote = plan.action.placeholder_markdown || '';
          const undershoot = mdNote.match(/Existing PR #(\d+) is insufficient[^)]*\(([^)]+)\)/);
          if (undershoot) body += `- **Existing PR**: #${undershoot[1]} undershoots required version - [view](${undershoot[2]})\n`;
        } else {
          body += `- **Dependency Type**: Direct\n`;
          if (transitiveChildren.length > 0) {
            body += `- **Transitive Vulnerabilities Resolved**: ${transitiveChildren.map(t => `\`${t.package.name}\``).join(', ')}\n`;
          }
        }
        if (plan.action.pr_number) {
          body += `- **Remediation PR**: #${plan.action.pr_number} ([view](${plan.action.pull_url}))\n`;
        }
        if (plan.state.issue_id) {
          body += `- **Tracking Issue**: #${plan.state.issue_id} ([view](${plan.state.issue_url}))\n`;
        }
        body += `- **Fix Class**: ${plan.fix.fix_class}\n`;
        body += `- **Breaking Change**: ${plan.fix.fix_class === 'BREAKING_BUMP' ? 'Yes' : 'No'}\n\n`;

        if (alerts.length > 0) {
          body += `**Vulnerabilities**:\n\n| ID | Summary | CVSS | Affected Versions | Fixed In |\n|---|---|---|---|---|\n`;
          for (const a of alerts) {
            const id = a.ghsa_id || a.cve_id || '?';
            const cvss = a.cvss != null ? String(a.cvss) : '—';
            body += `| [${id}](${a.url}) | ${a.summary || '—'} | ${cvss} | ${a.vulnerable_range || '—'} | ${a.first_patched || '—'} |\n`;
          }
          body += '\n';
        }

        if (!isTransitive && transitiveChildren.length > 0) {
          body += `**Transitive Vulnerabilities Resolved by This Upgrade**:\n\n`;
          for (const child of transitiveChildren) {
            const childAlerts = buildAlerts(child);
            const childSrc = (child.package.transitive_source_packages || child.package.transitive_source_package || []).join(', ');
            body += `<details><summary><code>${child.package.name}</code> (transitive via <code>${childSrc}</code>)</summary>\n\n`;
            if (childAlerts.length > 0) {
              body += `| ID | Summary | CVSS | Affected Versions | Fixed In |\n|---|---|---|---|---|\n`;
              for (const a of childAlerts) {
                const id = a.ghsa_id || a.cve_id || '?';
                const cvss = a.cvss != null ? String(a.cvss) : '—';
                body += `| [${id}](${a.url}) | ${a.summary || '—'} | ${cvss} | ${a.vulnerable_range || '—'} | ${a.first_patched || '—'} |\n`;
              }
            } else {
              body += '_No individual vulnerability details available._\n';
            }
            body += `\n</details>\n\n`;
          }
        }
      }
    }
  }

  body += `## Recommended Merge Order\n\n`;
  body += `1. **Non-breaking updates first** - lower risk, no API changes expected\n`;
  body += `2. **Validate** in a staging or test environment before merging\n`;
  body += `3. **Breaking updates** - review dependent code for API or behavior changes\n`;
  body += `4. **Re-run** this workflow after each merge to refresh the tracking issue\n\n`;
  body += `---\n_Generated by [Security Vulnerability Remediation](${context.serverUrl}/${owner}/${repo}/actions/runs/${context.runId})_`;

  const issueLabels = ['security-rollup'];
  const seenIssueLabels = new Set();
  for (const plan of group.plans) {
    const al = getActionLabel(plan);
    if (!seenIssueLabels.has(al)) {
      seenIssueLabels.add(al);
      issueLabels.push(al);
    }
  }

  try {
    const existing = await findIssue(title);
    if (existing) {
      await github.rest.issues.update({ owner, repo, issue_number: existing.number, body });
      await github.rest.issues.setLabels({ owner, repo, issue_number: existing.number, labels: issueLabels }).catch(() => {});
      core.info(`Updated tracking issue #${existing.number}: ${title}`);
      createdIssues[issueKey] = { number: existing.number, url: existing.html_url, title };
    } else {
      const issue = await github.rest.issues.create({ owner, repo, title, body, labels: issueLabels });
      core.info(`Created tracking issue #${issue.data.number}: ${title}`);
      createdIssues[issueKey] = { number: issue.data.number, url: issue.data.html_url, title };
    }
  } catch (err) {
    core.warning(`Failed to create/update tracking issue for ${title}: ${err.message}`);
  }
}

const totalPlans = Object.values(output).reduce((n, g) => n + (g.plans || []).length, 0);
fs.writeFileSync('rollup-output.json', JSON.stringify({
  stats: {
    total_plans: totalPlans,
    total_rollup_prs_created: Object.keys(createdPRs).length,
    total_issues_created: Object.keys(createdIssues).length,
  },
  created_prs: createdPRs,
  created_issues: createdIssues,
  base_branch: BASE_BRANCH,
  dry_run: false,
}, null, 2));
