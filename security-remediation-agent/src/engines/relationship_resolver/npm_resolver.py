from __future__ import annotations

from collections import defaultdict
from typing import Any


class NpmResolver:
    DEP_FIELDS = (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
    )

    def __init__(self, lock: dict[str, Any]):
        self.packages = lock.get("packages", {})

        if not self.packages:
            raise ValueError(
                "Expected package-lock.json v2/v3 with 'packages'"
            )

        self.by_name = defaultdict(list)
        self.parents = defaultdict(set)

        self._build_index()

    def resolve(self, target: str) -> dict:
        occurrences = []

        for location in self.by_name.get(target, []):
            pkg = self.packages[location]

            occurrences.append({
                "package": target,
                "version": pkg.get("version"),
                "introducers": self._find_introducers(location),
            })

        return {
            "package": target,
            "occurrences": occurrences,
        }

    def _build_index(self) -> None:
        # Index package name -> locations
        for location in self.packages:
            if not location:
                continue

            name = self._package_name(location)
            self.by_name[name].append(location)

        # Build child -> parent reverse graph
        for parent_location, pkg in self.packages.items():
            for field in self.DEP_FIELDS:
                for child_name in pkg.get(field, {}):
                    child_location = self._resolve_child(
                        parent_location,
                        child_name,
                    )

                    if child_location:
                        self.parents[child_location].add(
                            parent_location
                        )

    def _find_introducers(
        self,
        location: str,
    ) -> list[dict]:
        result = {}
        visited = set()
        stack = [location]

        while stack:
            current = stack.pop()

            if current in visited:
                continue

            visited.add(current)

            for parent in self.parents.get(current, ()):

                # Root → current
                if parent == "":
                    name = self._package_name(current)
                    version = self.packages[current].get("version")

                    result[(name, version)] = {
                        "package": name,
                        "version": version,
                    }

                    continue

                stack.append(parent)

        return list(result.values())

    def _resolve_child(
        self,
        parent_location: str,
        child_name: str,
    ) -> str | None:

        current = parent_location

        while True:
            candidate = (
                f"{current}/node_modules/{child_name}"
                if current
                else f"node_modules/{child_name}"
            )

            if candidate in self.packages:
                return candidate

            if not current:
                return None

            marker = "/node_modules/"

            current = (
                current.rsplit(marker, 1)[0]
                if marker in current
                else ""
            )

    def _package_name(
        self,
        location: str,
    ) -> str:

        pkg = self.packages[location]

        if name := pkg.get("name"):
            return name

        tail = location.rsplit(
            "node_modules/",
            1,
        )[-1]

        if tail.startswith("@"):
            scope, name, *_ = tail.split("/")
            return f"{scope}/{name}"

        return tail.split("/")[0]