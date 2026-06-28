import pytest

from tools.github_pr_collector import pull_requests_tool as tool_module
from tools.github_pr_collector.model.pull_request_metadata import (
    PullRequestMetadata,
    filter_security_dependency_pull_requests,
    is_breaking_change,
    parse_version_bump,
)
from tools.github_pr_collector.pull_requests_tool import (
    get_open_pull_requests,
    security_dependency_pull_requests_tool,
)


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
            "Update django requirements from 4.2.1 to 4.2.2",
            {"package": "django", "from_version": "4.2.1", "to_version": "4.2.2"},
        ),
        (
            "Update org.springframework:spring-core from 5.3.0 to 6.0.0",
            {
                "package": "org.springframework:spring-core",
                "from_version": "5.3.0",
                "to_version": "6.0.0",
            },
        ),
    ],
)
def test_parse_version_bump(title, expected):
    assert parse_version_bump(title).model_dump() == expected


def test_is_breaking_change_compares_major_versions():
    assert is_breaking_change("1.2.3", "2.0.0") is True
    assert is_breaking_change("1.2.3", "1.3.0") is False


def test_pull_request_metadata_model_normalizes_pull_request():
    metadata = PullRequestMetadata.from_pull_request(
        pull_request={
            "number": 7,
            "title": "Bump requests from 2.31.0 to 3.0.0",
            "head": {"ref": "dependabot/pip/requests-3.0.0"},
            "html_url": "https://github.com/octo-org/octo-repo/pull/7",
            "user": {"login": "dependabot[bot]"},
        },
        package_alerts=[{"severity": "high"}],
        severity="high",
        version_bump=parse_version_bump("Bump requests from 2.31.0 to 3.0.0"),
    )

    assert metadata.model_dump() == {
        "pr_number": 7,
        "pr_title": "Bump requests from 2.31.0 to 3.0.0",
        "pr_branch": "dependabot/pip/requests-3.0.0",
        "pull_url": "https://github.com/octo-org/octo-repo/pull/7",
        "package": "requests",
        "from_version": "2.31.0",
        "to_version": "3.0.0",
        "breaking": True,
        "severity": "high",
        "impact": "breaking",
        "alerts": [{"severity": "high"}],
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


def test_filter_security_dependency_pull_requests_matches_alerted_dependency():
    pull_requests = [
        {
            "number": 7,
            "title": "Bump requests from 2.31.0 to 3.0.0",
            "head": {"ref": "dependabot/pip/requests-3.0.0"},
            "html_url": "https://github.com/octo-org/octo-repo/pull/7",
            "user": {"login": "dependabot[bot]"},
        },
        {"number": 8, "title": "Bump unrelated from 1.0.0 to 1.0.1"},
        {"number": 9, "title": "Refactor package installer"},
    ]
    alerts = [
        {
            "number": 1,
            "dependency": {"package": {"name": "requests", "ecosystem": "pip"}},
            "security_advisory": {"severity": "high"},
            "security_vulnerability": {},
        }
    ]

    candidates = filter_security_dependency_pull_requests(pull_requests, alerts)

    assert candidates == [
        {
            "pr_number": 7,
            "pr_title": "Bump requests from 2.31.0 to 3.0.0",
            "pr_branch": "dependabot/pip/requests-3.0.0",
            "pull_url": "https://github.com/octo-org/octo-repo/pull/7",
            "package": "requests",
            "from_version": "2.31.0",
            "to_version": "3.0.0",
            "breaking": True,
            "severity": "high",
            "impact": "breaking",
            "alerts": [
                {
                    "number": 1,
                    "url": "",
                    "summary": "",
                    "severity": "high",
                    "cvss": None,
                    "cve_id": "",
                    "ghsa_id": "",
                    "ecosystem": "pip",
                    "vulnerable_range": "",
                    "first_patched": "",
                }
            ],
            "author": "dependabot[bot]",
        }
    ]


@pytest.mark.asyncio
async def test_security_dependency_pull_requests_tool_fetches_and_filters(monkeypatch):
    async def stub_get_open_pull_requests(owner, repo):
        return [{"number": 7, "title": "Bump requests from 2.31.0 to 2.32.0"}]

    monkeypatch.setattr(tool_module, "get_open_pull_requests", stub_get_open_pull_requests)

    candidates = await security_dependency_pull_requests_tool.ainvoke(
        {
            "owner": "octo-org",
            "repo": "octo-repo",
            "alerts": [
                {
                    "dependency": {"package": {"name": "requests"}},
                    "security_advisory": {"severity": "medium"},
                    "security_vulnerability": {},
                }
            ],
        }
    )

    assert candidates[0]["pr_number"] == 7
    assert candidates[0]["severity"] == "medium"
