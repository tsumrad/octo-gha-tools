import asyncio
import json
import sys
import types

sys.path.insert(0, ".")

from src.engines.package_relationship_resolver import PackageRelationshipResolver
from src.models.security_package_triage import SecurityPackageTriage
from src.models.gh.vulnerability_alert import VulnerabilityAlert


class FakeManifestProvider:
    def __init__(self):
        from src.models.security_remediation_context import SecurityRemediationCache
        self.cache = SecurityRemediationCache()

    @staticmethod
    def is_lockfile(path):
        from pathlib import PurePosixPath
        return PurePosixPath(path).name in {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "Pipfile.lock"}

    @staticmethod
    def normalize(package, ecosystem):
        return package.strip().lower()

    async def declared_packages(self, owner, repo, path, ref=None, ecosystem="npm"):
        # Simulate package.json NOT declaring ansi-regex directly.
        declared = {}
        key = self.cache.manifest_cache.key(owner, repo, path, ref)
        self.cache.manifest_cache.set_packages(key, ecosystem, declared)
        return declared

    async def get(self, owner, repo, path, ref=None, *, refresh=False):
        if path.endswith("package-lock.json"):
            return json.dumps({
                "packages": {
                    "": {"name": "root"},
                    "node_modules/jest": {"version": "30.3.0", "dependencies": {"ansi-regex": "^6.0.0"}},
                    "node_modules/jest/node_modules/ansi-regex": {"version": "6.2.2"},
                    "node_modules/@vue/cli-service": {"version": "4.5.19", "dependencies": {"ansi-regex": "^4.1.0"}},
                    "node_modules/@vue/cli-service/node_modules/ansi-regex": {"version": "4.1.0"},
                }
            })
        return None


async def main():
    resolver = PackageRelationshipResolver(manifest_provider=FakeManifestProvider())

    alert = VulnerabilityAlert(
        package="ansi-regex",
        ecosystem="npm",
        vulnerable_range=">= 4.0.0, < 4.1.1",
        first_patched="4.1.1",
        manifest_path="web/package-lock.json",
    )
    item = SecurityPackageTriage(
        package="ansi-regex",
        vulnerablility_version_range=">= 4.0.0, < 4.1.1",
        vulnerablility_fixed_version="4.1.1",
        ecosystem="npm",
        manifest_path="web/package-lock.json",
        vulnerabilities=[alert],
    )

    await resolver.populate("octo", "repo", [item])

    print("istransitive:", item.istransitive)
    print("occurrences:", item.transitive_dependency_occurrences)


asyncio.run(main())
