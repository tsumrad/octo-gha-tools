# 13. Reusable Workflow Execution Model

## 13.1 Overview

The Security Remediation Rollup Agent is implemented as a reusable GitHub Actions workflow.

The workflow is centrally maintained but executes inside the calling repository context.

The caller repository owns:

* workflow execution;
* runner allocation;
* authentication token;
* repository state;
* branches;
* pull requests;
* issues;
* security findings.

The central workflow repository only provides the automation logic.

---

## 13.2 Execution Boundary

Architecture:

```
Central Workflow Repository

tsumrad/gh-tools

.github/workflows/
└── security-remediation-rollup-agent.yml


              workflow_call
                    |
                    |
                    v


Caller Repository

customer/application-repository

.github/workflows/
└── security.yml


                    |
                    v


GitHub Actions Runner
(scope: caller repository)


                    |
       +------------+-------------+
       |            |             |
       v            v             v

 Security API   Git Operations   GitHub API

 Caller Repo    Caller Repo      Caller Repo
```

---

## 13.3 Caller Repository Runner Scope

When the reusable workflow starts:

```yaml
uses: tsumrad/gh-tools/.github/workflows/security-remediation-rollup-agent.yml@main
```

GitHub creates the workflow run under the caller repository.

The runner:

* checks out the caller repository;
* executes scripts against the caller workspace;
* uses the caller repository token;
* pushes branches to the caller repository;
* creates pull requests in the caller repository.

The workflow does not execute against:

```
tsumrad/gh-tools
```

unless that repository itself is the caller.

---

## 13.4 Repository Context

The workflow must always use:

```javascript
context.repo
```

or:

```javascript
github.repository
```

from the workflow runtime context.

Example:

```javascript
const { owner, repo } = context.repo;
```

This resolves to:

```
<caller-owner>/<caller-repository>
```

not:

```
tsumrad/gh-tools
```

---

## 13.5 Checkout Behavior

The reusable workflow checks out the caller repository.

Example:

```yaml
- name: Checkout repository
  uses: actions/checkout@v4
  with:
    repository: ${{ github.repository }}
```

The checkout target is therefore:

```
caller repository
```

---

## 13.6 Git Operations

All branch operations occur in the caller repository.

Example:

Create:

```
security-rollup/critical/dependency
```

inside:

```
caller-owner/caller-repository
```

Operations include:

* fetch;
* merge;
* commit;
* push.

No branches are created in the workflow source repository.

---

## 13.7 GitHub API Operations

All API calls resolve against the caller repository.

Examples:

Dependabot:

```
GET /repos/{caller-owner}/{caller-repository}/dependabot/alerts
```

Code scanning:

```
GET /repos/{caller-owner}/{caller-repository}/code-scanning/alerts
```

Pull requests:

```
GET /repos/{caller-owner}/{caller-repository}/pulls
```

Issues:

```
POST /repos/{caller-owner}/{caller-repository}/issues
```

---

## 13.8 Caller Workflow Example

Consumer repositories only configure execution:

```yaml
name: Security Remediation Agent

on:
  schedule:
    - cron: "0 6 * * 1"

  workflow_dispatch:

jobs:
  security:

    permissions:
      contents: write
      pull-requests: write
      issues: write
      security-events: read

    uses: tsumrad/gh-tools/.github/workflows/security-remediation-rollup-agent.yml@main

    with:
      enable_dependabot: true
      enable_code_scanning: true
      create_missing_fixes: true
      dry_run: false
```

---

## 13.9 Runner Customization

The caller controls runner selection.

Default:

```yaml
runs-on: ubuntu-latest
```

For reusable workflows requiring organization-specific runners:

```yaml
jobs:

  security:

    uses: tsumrad/gh-tools/.github/workflows/security-remediation-rollup-agent.yml@main

    with:
      runner: self-hosted
```

The reusable workflow executes according to the caller repository's available runner policy.

---

## 13.10 Security Model

The workflow follows these boundaries:

| Resource            | Owner                         |
| ------------------- | ----------------------------- |
| Workflow definition | Central automation repository |
| Workflow execution  | Caller repository             |
| Runner              | Caller repository             |
| Token               | Caller repository             |
| Branches            | Caller repository             |
| Pull requests       | Caller repository             |
| Issues              | Caller repository             |
| Security findings   | Caller repository             |

This guarantees that centralized automation can be reused without granting access to unrelated repositories.

```
```
