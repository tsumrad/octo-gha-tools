import pytest

from tools.github_pr_collector import pull_requests_tool as tool_module
from tools.github_pr_collector.model.pull_request_metadata import (
    PullRequestMetadata,
    filter_security_dependency_pull_requests,
)
from tools.github_pr_collector.pull_requests_tool import (
    get_open_pull_requests,
    security_dependency_pull_requests_tool,
)
from tools.github_pr_collector.utils.version_bump_resolver import get_version_bumps


class StubResponse:
    def __init__(self, data, headers=None):
        self.data = data
        self.headers = headers or {}

    def raise_for_status(self):
        return None

    def json(self):
        return self.data


class StubAsyncClient:
    requests = []
    pages = []
    links = []
    headers = None

    def __init__(self, *, headers, timeout):
        type(self).headers = headers

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

    async def get(self, url, params):
        type(self).requests.append({"url": url, "params": params})
        return StubResponse(type(self).pages.pop(0), {"Link": type(self).links.pop(0)})


@pytest.mark.parametrize(
    ("title", "expected"),
    [
        (
            "Bump requests from 2.31.0 to 2.32.0",
            {"package": "requests", "from_version": "2.31.0", "to_version": "2.32.0"},
        ),
        (
            "Bump django from 4.2.1 to 4.2.2",
            {"package": "django", "from_version": "4.2.1", "to_version": "4.2.2"},
        ),
        (
            "Bump org.springframework:spring-core from 5.3.0 to 6.0.0",
            {
                "package": "org.springframework:spring-core",
                "from_version": "5.3.0",
                "to_version": "6.0.0",
            },
        ),
    ],
)
def test_parse_version_bump(title, expected):
    assert get_version_bumps(title, "")[0].model_dump() == expected


def test_parse_renovate_body_table_version_bump():
    body = """
This PR contains the following updates:

| Package | Change | [Age](https://docs.renovatebot.com/merge-confidence/) | [Confidence](https://docs.renovatebot.com/merge-confidence/) |
|---|---|---|---|
| [typescript](https://www.typescriptlang.org/) ([source](https://redirect.github.com/microsoft/TypeScript)) | [`4.3.5` → `4.9.5`](https://renovatebot.com/diffs/npm/typescript/4.3.5/4.9.5) | ![age](https://developer.mend.io/api/mc/badges/age/npm/typescript/4.9.5?slim=true) | ![confidence](https://developer.mend.io/api/mc/badges/confidence/npm/typescript/4.3.5/4.9.5?slim=true) |

---

###
"""

    assert get_version_bumps("chore(deps): update dependency typescript to v4.9.5", body) == [
        {
            "package": "typescript",
            "from_version": "4.3.5",
            "to_version": "4.9.5",
        }
    ]


def test_parse_renovate_body_table_handles_multiple_entries():
    body = """
This PR contains the following updates:

| Package | Change | [Age](https://docs.renovatebot.com/merge-confidence/) | [Confidence](https://docs.renovatebot.com/merge-confidence/) |
|---|---|---|---|
| [@typescript-eslint/eslint-plugin](https://typescript-eslint.io/packages/eslint-plugin) ([source](https://redirect.github.com/typescript-eslint/typescript-eslint/tree/HEAD/packages/eslint-plugin)) | [`^2.30.0` → `^8.0.0`](https://renovatebot.com/diffs/npm/@typescript-eslint%2feslint-plugin/2.34.0/8.68.0) | ![age](https://developer.mend.io/api/mc/badges/age/npm/@typescript-eslint%2feslint-plugin/8.68.0?slim=true) | ![confidence](https://developer.mend.io/api/mc/badges/confidence/npm/@typescript-eslint%2feslint-plugin/2.34.0/8.68.0?slim=true) |
| [eslint](https://eslint.org) ([source](https://redirect.github.com/eslint/eslint)) | [`^6.8.0` → `^10.0.0`](https://renovatebot.com/diffs/npm/eslint/6.8.0/10.9.1) | ![age](https://developer.mend.io/api/mc/badges/age/npm/eslint/10.9.1?slim=true) | ![confidence](https://developer.mend.io/api/mc/badges/confidence/npm/eslint/6.8.0/10.9.1?slim=true) |

---
###
"""

    assert get_version_bumps("chore(deps): update multiple ESLint packages", body) == [
        {
            "package": "@typescript-eslint/eslint-plugin",
            "from_version": "2.30.0",
            "to_version": "8.0.0",
        },
        {
            "package": "eslint",
            "from_version": "6.8.0",
            "to_version": "10.0.0",
        },
    ]


def test_parse_renovate_body_table_handles_multiple_entries():
    body = """
This PR contains the following updates:

| Package | Change | [Age](https://docs.renovatebot.com/merge-confidence/) | [Confidence](https://docs.renovatebot.com/merge-confidence/) |
|---|---|---|---|
| [@typescript-eslint/eslint-plugin](https://typescript-eslint.io/packages/eslint-plugin) ([source](https://redirect.github.com/typescript-eslint/typescript-eslint/tree/HEAD/packages/eslint-plugin)) | [`^2.30.0` → `^8.0.0`](https://renovatebot.com/diffs/npm/@typescript-eslint%2feslint-plugin/2.34.0/8.68.0) | ![age](https://developer.mend.io/api/mc/badges/age/npm/@typescript-eslint%2feslint-plugin/8.68.0?slim=true) | ![confidence](https://developer.mend.io/api/mc/badges/confidence/npm/@typescript-eslint%2feslint-plugin/2.34.0/8.68.0?slim=true) |
| [eslint](https://eslint.org) ([source](https://redirect.github.com/eslint/eslint)) | [`^6.8.0` → `^10.0.0`](https://renovatebot.com/diffs/npm/eslint/6.8.0/10.9.1) | ![age](https://developer.mend.io/api/mc/badges/age/npm/eslint/10.9.1?slim=true) | ![confidence](https://developer.mend.io/api/mc/badges/confidence/npm/eslint/6.8.0/10.9.1?slim=true) |

---
###
"""

    assert get_version_bumps("chore(deps): update multiple ESLint packages", body) == [
        {
            "package": "@typescript-eslint/eslint-plugin",
            "from_version": "2.30.0",
            "to_version": "8.0.0",
        },
        {
            "package": "eslint",
            "from_version": "6.8.0",
            "to_version": "10.0.0",
        },
    ]


def test_pull_request_metadata_model_normalizes_pull_request():
    metadata = PullRequestMetadata.from_pull_request(
        pull_request={
            "number": 7,
            "title": "Bump requests from 2.31.0 to 3.0.0",
            "head": {"ref": "dependabot/pip/requests-3.0.0"},
            "html_url": "https://github.com/octo-org/octo-repo/pull/7",
            "user": {"login": "dependabot[bot]"},
        },
        version_bumps=get_version_bumps("Bump requests from 2.31.0 to 3.0.0", ""),
    )

    assert metadata.model_dump() == {
        "pr_number": 7,
        "pr_title": "Bump requests from 2.31.0 to 3.0.0",
        "pr_branch": "dependabot/pip/requests-3.0.0",
        "pull_url": "https://github.com/octo-org/octo-repo/pull/7",
        "version_bumps": [
            {
                "package": "requests",
                "from_version": "2.31.0",
                "to_version": "3.0.0",
            }
        ],
        "severity": "",
        "author": "dependabot[bot]",
    }


@pytest.mark.asyncio
async def test_get_open_pull_requests_paginates(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(tool_module.httpx, "AsyncClient", StubAsyncClient)
    StubAsyncClient.requests = []
    StubAsyncClient.pages = [
        [{"number": index} for index in range(tool_module.PER_PAGE)],
        [{"number": tool_module.PER_PAGE}],
    ]
    StubAsyncClient.links = [
        '<https://api.github.com/repositories/1/pulls?page=2>; rel="next"',
        "",
    ]

    pull_requests = await get_open_pull_requests("octo-org", "octo-repo")

    assert len(pull_requests) == tool_module.PER_PAGE + 1
    assert StubAsyncClient.headers["Authorization"] == "Bearer token"
    assert StubAsyncClient.requests == [
        {
            "url": "https://api.github.com/repos/octo-org/octo-repo/pulls",
            "params": {"state": "open", "per_page": tool_module.PER_PAGE},
        },
        {
            "url": "https://api.github.com/repositories/1/pulls?page=2",
            "params": None,
        },
    ]


def test_filter_security_dependency_pull_requests_keeps_bot_pull_requests():
    pull_requests = [
        {
            "number": 7,
            "title": "Bump requests from 2.31.0 to 3.0.0",
            "head": {"ref": "dependabot/pip/requests-3.0.0"},
            "html_url": "https://github.com/octo-org/octo-repo/pull/7",
            "user": {"login": "dependabot[bot]"},
        },
        {
            "number": 8,
            "title": "Bump unrelated from 1.0.0 to 1.0.1",
            "user": {"login": "renovate[bot]"},
        },
        {"number": 9, "title": "Refactor package installer", "user": {"login": "octocat"}},
    ]

    candidates = filter_security_dependency_pull_requests(
        owner="octo-org",
        repo="octo-repo",
        pull_requests=pull_requests,
    )

    assert candidates == [
        {
            "pr_number": 7,
            "pr_title": "Bump requests from 2.31.0 to 3.0.0",
            "pr_branch": "dependabot/pip/requests-3.0.0",
            "pull_url": "https://github.com/octo-org/octo-repo/pull/7",
            "version_bumps": [
                {
                    "package": "requests",
                    "from_version": "2.31.0",
                    "to_version": "3.0.0",
                }
            ],
            "severity": "",
            "author": "dependabot[bot]",
        },
        {
            "pr_number": 8,
            "pr_title": "Bump unrelated from 1.0.0 to 1.0.1",
            "pr_branch": "",
            "pull_url": "",
            "version_bumps": [
                {
                    "package": "unrelated",
                    "from_version": "1.0.0",
                    "to_version": "1.0.1",
                }
            ],
            "severity": "",
            "author": "renovate[bot]",
        },
    ]


@pytest.mark.asyncio
async def test_security_dependency_pull_requests_tool_fetches_and_filters(monkeypatch):
    async def stub_get_open_pull_requests(owner, repo):
        return [
            {
                "number": 7,
                "title": "Bump requests from 2.31.0 to 2.32.0",
                "user": {"login": "dependabot[bot]"},
            }
        ]

    monkeypatch.setattr(tool_module, "get_open_pull_requests", stub_get_open_pull_requests)

    candidates = await security_dependency_pull_requests_tool.ainvoke(
        {
            "owner": "octo-org",
            "repo": "octo-repo",
        }
    )

    assert candidates[0]["pr_number"] == 7
    assert candidates[0]["author"] == "dependabot[bot]"
