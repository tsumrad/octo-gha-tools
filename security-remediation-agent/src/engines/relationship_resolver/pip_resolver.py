import json
import subprocess
import sys
import re
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from pathlib import Path


class PipResolver:
    def __init__(self, requirements_file: str):
        self.requirements_file = requirements_file
        self._report = None

    @classmethod
    def from_text(cls, text: str):
        """Resolve ordinary PEP 508 requirements without writing the manifest to disk.

        Includes, pip options and source URLs need a separate project-aware resolver.
        Binary distributions avoid executing package build scripts during analysis.
        """
        compiled = cls._compiled_report(text)
        if compiled is not None:
            instance = cls("")
            instance._report = compiled
            return instance
        requirements = []
        for line in text.splitlines():
            line = line.split(" #", 1)[0].strip()
            if not line or line.startswith("#"):
                continue
            requirement = Requirement(line)
            if requirement.url:
                raise ValueError("Source URL requirements are not supported for parent resolution")
            requirements.append(str(requirement))
        instance = cls("")
        if not requirements:
            instance._report = {"install": []}
            return instance
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed",
             "--quiet", "--disable-pip-version-check", "--no-input", "--only-binary=:all:",
             "--report", "-", *requirements],
            capture_output=True, text=True, check=True, timeout=180,
        )
        instance._report = json.loads(result.stdout)
        return instance

    @staticmethod
    def _compiled_report(text: str):
        """Build the reverse graph from pip-compile pins and single/multiline via comments."""
        entries = {}
        current = None
        in_via = False
        has_via = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                comment = stripped[1:].strip()
                if current is not None and (comment == "via" or comment.startswith("via ")):
                    has_via = True
                    in_via = True
                    comment = comment[3:].strip()
                elif not (current is not None and in_via and re.match(r"^\s*#\s{2,}\S", line)):
                    in_via = False
                    continue
                for source in filter(None, (s.strip() for s in comment.split(","))):
                    if source.startswith(("-r ", "--requirement ")):
                        entries[current]["requested"] = True
                    elif not source.startswith("-"):
                        entries[current]["parents"].append(canonicalize_name(source))
                continue
            if not stripped:
                in_via = False
                continue
            in_via = False
            current = None
            if stripped.startswith(("--hash=", "--", "-r ", "-c ")):
                continue
            try:
                requirement = Requirement(stripped.rstrip("\\").strip())
            except ValueError:
                continue
            pins = [s.version for s in requirement.specifier if s.operator in {"==", "==="}]
            if len(pins) != 1:
                continue
            current = canonicalize_name(requirement.name)
            entries[current] = {"requested": False, "parents": [], "metadata": {
                "name": requirement.name, "version": pins[0], "requires_dist": [],
            }}
        if not has_via:
            return None
        for child, entry in entries.items():
            for parent in entry["parents"]:
                if parent in entries:
                    entries[parent]["metadata"]["requires_dist"].append(child)
        return {"install": list(entries.values())}

    def resolve(self, target: str) -> dict:
        if self._report is not None:
            return self._find_introducers(self._report, target)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--dry-run",
                "--ignore-installed",
                "--quiet",
                "--only-binary=:all:",
                "--report",
                "-",
                "-r",
                self.requirements_file,
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=180,
        )

        report = json.loads(result.stdout)
        self._report = report

        return self._find_introducers(report, target)

    def _find_introducers(
        self,
        report: dict,
        target: str,
    ) -> dict:
        packages = {}

        for item in report.get("install", []):
            metadata = item.get("metadata", {})

            name = metadata.get("name")
            version = metadata.get("version")

            if not name:
                continue
            packages[canonicalize_name(name)] = {
                "name": name,
                "version": version,
                "requires": metadata.get("requires_dist", []),
                "requested": item.get("requested", False),
                "extras": item.get("requested_extras", []),
            }

        reverse = {}

        from packaging.requirements import Requirement

        for parent in packages.values():
            for req_text in parent["requires"]:
                try:
                    req = Requirement(req_text)
                    if req.marker and not any(req.marker.evaluate({"extra": extra}) for extra in ["", *parent["extras"]]):
                        continue
                except Exception:
                    continue

                child = canonicalize_name(req.name)

                reverse.setdefault(child, []).append(
                    canonicalize_name(parent["name"])
                )

        target_key = canonicalize_name(target)

        introducers = {}
        visited = set()

        def walk(name: str):
            if name in visited:
                return

            visited.add(name)

            for parent_name in reverse.get(name, []):
                parent = packages[parent_name]

                if parent["requested"]:
                    introducers[parent_name] = {
                        "package": parent["name"],
                        "version": parent["version"],
                    }
                else:
                    walk(parent_name)

        walk(target_key)

        target_pkg = packages.get(target_key)

        return {
            "package": target,
            "version": (
                target_pkg["version"]
                if target_pkg
                else None
            ),
            "introducers": list(
                introducers.values()
            ),
        }
