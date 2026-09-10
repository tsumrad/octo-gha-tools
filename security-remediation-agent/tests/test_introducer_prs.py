import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from src.agents.vulnerability_triage_agent import VulnerabilityTriageAgent
from src.models.security_package_triage import SecurityPackageTriage
from src.engines.relationship_resolver.npm_resolver import NpmResolver
from src.engines.version_resolver.pip_parent_version_resolver import ParentResolution


class IntroducerPRTest(unittest.IsolatedAsyncioTestCase):
    async def test_follow_redirects_matches_both_scoped_and_unscoped_introducers(self):
        resolver = NpmResolver({"packages": {
            "": {"dependencies": {"@vue/cli-service": "4.5.19", "axios": "0.28.1"}},
            "node_modules/@vue/cli-service": {"version": "4.5.19", "dependencies": {"webpack-dev-server": "3.11.3"}},
            "node_modules/webpack-dev-server": {"version": "3.11.3", "dependencies": {"follow-redirects": "1.15.6"}},
            "node_modules/axios": {"version": "0.28.1", "dependencies": {"follow-redirects": "1.15.6"}},
            "node_modules/follow-redirects": {"version": "1.15.6"},
        }})
        item = SecurityPackageTriage("follow-redirects", "<=1.15.6", "1.15.7", ecosystem="npm", istransitive=True)
        item.dependency_occurrences = resolver.resolve(item.package)["occurrences"]
        item.transitive_source_package = ["@vue/cli-service@4.5.19", "axios@0.28.1"]
        def pr(number, name, old, new):
            return SimpleNamespace(pr_number=number, pull_url=f"https://example.test/{number}",
                pr_branch=f"bump-{number}", mergeable_state="clean",
                version_bumps=[SimpleNamespace(package=name, from_version=old, to_version=new)])
        parents = [pr(10, "@vue/cli-service", "4.5.19", "5.0.8"),
                   pr(11, "axios", "0.28.1", "1.7.9"), pr(12, "unrelated", "1.0", "2.0")]
        agent = VulnerabilityTriageAgent()
        lookup = agent.group_pull_requests_by_package(parents)
        await agent.populate_remediation_version(item, [], lookup)
        self.assertEqual({p["package"] for p in item.dependency_occurrences[0]["introducers"]},
                         {"@vue/cli-service", "axios"})
        self.assertEqual([p["pr_number"] for p in item.introducer_pull_requests], [10, 11])
        self.assertTrue(all(p["requires_verification"] for p in item.introducer_pull_requests))
        self.assertEqual(item.fixed_minimum_version, "1.15.7")
        self.assertEqual(item.pull_request_metadata, [])
        # Also exercise the version-suffixed source fallback, without resolver occurrences.
        item.dependency_occurrences = []
        await agent.populate_remediation_version(item, [], lookup)
        self.assertEqual([p["pr_number"] for p in item.introducer_pull_requests], [10, 11])

    async def test_parent_candidates_do_not_overwrite_child_versions(self):
        agent = VulnerabilityTriageAgent()
        item = SecurityPackageTriage("starlette", "<0.50", "0.50.0", ecosystem="pip", istransitive=True)
        item.dependency_occurrences = [{"introducers": [{"package": "fastapi"}]}]
        item.transitive_source_package = ["fastapi-sqlalchemy@0.2.1"]
        def pr(number, package, old, new):
            return SimpleNamespace(pr_number=number, pull_url=f"https://example.test/{number}",
                pr_branch=f"bump-{number}", mergeable_state=None,
                version_bumps=[SimpleNamespace(package=package, from_version=old, to_version=new)])
        parent = pr(1, "fastapi", "0.124.0", "0.125.0")
        other = pr(2, "FastAPI_SQLAlchemy", "0.2.0", "0.2.1")
        unrelated = pr(3, "requests", "2.0", "2.1")
        lookup = {"fastapi": [parent, parent], "fastapi_sqlalchemy": [other], "requests": [unrelated]}
        await agent.populate_remediation_version(item, [], lookup)
        self.assertEqual([p["pr_number"] for p in item.introducer_pull_requests], [1, 2])
        self.assertEqual(item.fixed_minimum_version, "0.50.0")
        self.assertFalse(item.is_pull_available)
        child = pr(4, "starlette", "0.49.0", "0.50.0")
        await agent.populate_remediation_version(item, [child], lookup)
        self.assertEqual(item.pull_request_metadata, [child])
        self.assertEqual(item.current_version, "0.49.0")
        self.assertEqual(len(item.introducer_pull_requests), 2)

    async def test_direct_packages_do_not_match_parent_prs(self):
        item = SecurityPackageTriage("starlette", "<0.50", "0.50.0")
        await VulnerabilityTriageAgent().populate_remediation_version(item, [])
        self.assertEqual(item.introducer_pull_requests, [])

    async def test_transitive_pip_without_pr_uses_verified_parent_version(self):
        agent = VulnerabilityTriageAgent()
        agent.pip_parent_version_resolver.resolve = AsyncMock(return_value=ParentResolution(
            parent="fastapi", child="starlette", resolved_version="0.125.0",
            installed_child_version="0.50.0", candidates_considered=["0.125.0"],
        ))
        item = SecurityPackageTriage("starlette", "<0.50", "0.50.0", ecosystem="pip", istransitive=True)
        item.dependency_occurrences = [{"introducers": [{"package": "fastapi", "version": "0.124.0"}]}]

        await agent.populate_remediation_version(item, [])

        agent.pip_parent_version_resolver.resolve.assert_awaited_once_with(
            "fastapi", "starlette", "0.50.0", current_parent_version="0.124.0",
        )
        self.assertEqual(item.fixed_minimum_version, "0.125.0")
        self.assertEqual(item.fixed_maximum_version, "0.125.0")
        self.assertEqual(item.upgrade_to_version, "0.125.0")
        self.assertEqual(item.introducer_pull_requests, [{
            "package": "fastapi", "from_version": "0.124.0", "to_version": "0.125.0",
            "requires_verification": False, "source": "pypi_verified",
        }])

    async def test_transitive_pip_without_pr_or_verified_candidate_falls_back_to_child_version(self):
        agent = VulnerabilityTriageAgent()
        agent.pip_parent_version_resolver.resolve = AsyncMock(return_value=ParentResolution(
            parent="fastapi", child="starlette", candidates_considered=["0.125.0"],
        ))
        item = SecurityPackageTriage("starlette", "<0.50", "0.50.0", ecosystem="pip", istransitive=True)
        item.dependency_occurrences = [{"introducers": [{"package": "fastapi", "version": "0.124.0"}]}]

        await agent.populate_remediation_version(item, [])

        self.assertEqual(item.fixed_minimum_version, "0.50.0")
        self.assertEqual(item.fixed_maximum_version, "0.50.0")
        self.assertEqual(item.introducer_pull_requests, [])
