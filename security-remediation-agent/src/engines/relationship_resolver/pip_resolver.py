import json
import re
import subprocess
import sys

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


class PipResolver:
    def __init__(self, requirements_file: str):
        self.requirements_file = requirements_file
        self._report = None

    @classmethod
    def from_text(cls, text: str):
        """
        Resolve dependencies from requirements text.

        If the text is pip-compile output containing '# via' comments,
        reconstruct the dependency graph directly from those comments.

        Otherwise use pip --dry-run --report to resolve the graph.
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
                raise ValueError(
                    "Source URL requirements are not supported "
                    "for parent resolution"
                )

            requirements.append(str(requirement))

        instance = cls("")

        if not requirements:
            instance._report = {"install": []}
            return instance

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--dry-run",
                "--ignore-installed",
                "--quiet",
                "--disable-pip-version-check",
                "--no-input",
                "--only-binary=:all:",
                "--report",
                "-",
                *requirements,
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=180,
        )

        instance._report = json.loads(result.stdout)

        return instance

    @staticmethod
    def _compiled_report(text: str):
        """
        Reconstruct a pip dependency graph from pip-compile output.

        Example:

            fastapi==0.125.0
                # via -r requirements.in

            starlette==0.50.0
                # via
                #   fastapi

        Produces semantics equivalent to pip's --report:

            fastapi:
                requested = True

            starlette:
                requested = False
                parent = fastapi

        Constraint files (-c / --constraint) NEVER make a package direct.
        """

        entries = {}

        current = None
        in_via = False
        has_via = False

        for line in text.splitlines():
            stripped = line.strip()

            # ----------------------------------------------------------
            # Parse comments belonging to current requirement
            # ----------------------------------------------------------

            if stripped.startswith("#"):
                if current is None:
                    continue

                comment = stripped[1:].strip()

                # Start of:
                #
                #   # via
                #   #   fastapi
                #
                # or:
                #
                #   # via -r requirements.in
                #
                if comment == "via" or comment.startswith("via "):
                    has_via = True
                    in_via = True

                    comment = comment[3:].strip()

                    if not comment:
                        continue

                # Continuation of a multiline # via block.
                elif in_via:
                    # pip-compile continuation lines are indented:
                    #
                    #     #   fastapi
                    #     #   -r requirements.in
                    #
                    if not re.match(r"^\s*#\s{2,}\S", line):
                        in_via = False
                        continue

                else:
                    continue

                sources = [
                    source.strip()
                    for source in comment.split(",")
                    if source.strip()
                ]

                for source in sources:

                    # -----------------------------------------------
                    # Explicit source manifest => DIRECT dependency
                    # -----------------------------------------------

                    if source.startswith(
                        ("-r ", "--requirement ")
                    ):
                        entries[current]["requested"] = True
                        continue

                    # -----------------------------------------------
                    # Constraint file does NOT make dependency direct
                    # -----------------------------------------------

                    if source.startswith(
                        ("-c ", "--constraint ")
                    ):
                        continue

                    # Ignore any other pip option.
                    if source.startswith("-"):
                        continue

                    # -----------------------------------------------
                    # Otherwise this is a dependency parent
                    # -----------------------------------------------

                    parent = canonicalize_name(source)

                    if parent not in entries[current]["parents"]:
                        entries[current]["parents"].append(parent)

                continue

            # ----------------------------------------------------------
            # Empty line terminates current via block
            # ----------------------------------------------------------

            if not stripped:
                current = None
                in_via = False
                continue

            in_via = False
            current = None

            # Ignore global pip options/includes.
            if stripped.startswith(
                (
                    "--hash=",
                    "--",
                    "-r ",
                    "-c ",
                )
            ):
                continue

            # pip-compile may produce line continuation for hashes.
            requirement_text = stripped.rstrip("\\").strip()

            try:
                requirement = Requirement(requirement_text)
            except ValueError:
                continue

            # We only care about fully pinned pip-compile entries.
            pins = [
                specifier.version
                for specifier in requirement.specifier
                if specifier.operator in {"==", "==="}
            ]

            if len(pins) != 1:
                continue

            current = canonicalize_name(requirement.name)

            entries[current] = {
                "requested": False,
                "parents": [],
                "metadata": {
                    "name": requirement.name,
                    "version": pins[0],
                    "requires_dist": [],
                },
            }

        # This wasn't pip-compile output.
        if not has_via:
            return None

        # --------------------------------------------------------------
        # Convert:
        #
        # starlette.parents = ["fastapi"]
        #
        # into:
        #
        # fastapi.requires_dist = ["starlette"]
        #
        # so _find_introducers() can use the same logic as pip --report.
        # --------------------------------------------------------------

        for child, entry in entries.items():
            for parent in entry["parents"]:
                if parent not in entries:
                    continue

                requires = entries[parent]["metadata"]["requires_dist"]

                if child not in requires:
                    requires.append(child)

        return {
            "install": list(entries.values())
        }

    def resolve(self, target: str) -> dict:
        """
        Return the installed/resolved target version and its actionable
        ROOT introducers.
        """

        if self._report is not None:
            return self._find_introducers(
                self._report,
                target,
            )

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--dry-run",
                "--ignore-installed",
                "--quiet",
                "--disable-pip-version-check",
                "--no-input",
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

        return self._find_introducers(
            report,
            target,
        )

    def _find_introducers(
        self,
        report: dict,
        target: str,
    ) -> dict:
        """
        Find actionable ROOT introducers for target.

        Rules:

        1. If target itself is explicitly requested/direct:
              target is the introducer.

        2. Otherwise walk upward through transitive parents until an
           explicitly requested/root dependency is reached.

        3. Return only root introducers.

        Example:

            requirements.in
                fastapi

            fastapi
                -> starlette
                    -> vulnerable-package

        vulnerable-package introducer:
            fastapi

        If requirements.in explicitly contains starlette:

            starlette

        then starlette itself is the introducer.
        """

        packages = {}

        # --------------------------------------------------------------
        # Normalize pip report
        # --------------------------------------------------------------

        for item in report.get("install", []):
            metadata = item.get("metadata", {})

            name = metadata.get("name")

            if not name:
                continue

            key = canonicalize_name(name)

            packages[key] = {
                "name": name,
                "version": metadata.get("version"),
                "requires": metadata.get(
                    "requires_dist",
                    [],
                ) or [],
                "requested": bool(
                    item.get("requested", False)
                ),
                "extras": item.get(
                    "requested_extras",
                    [],
                ) or [],
            }

        # --------------------------------------------------------------
        # Build reverse dependency graph:
        #
        # child -> [parents]
        #
        # fastapi -> starlette
        #
        # becomes:
        #
        # starlette -> [fastapi]
        # --------------------------------------------------------------

        reverse = {}

        for parent_key, parent in packages.items():

            for req_text in parent["requires"]:

                try:
                    req = Requirement(req_text)

                    # Respect environment/extras markers.
                    if req.marker:
                        extras = [
                            "",
                            *parent["extras"],
                        ]

                        if not any(
                            req.marker.evaluate(
                                {"extra": extra}
                            )
                            for extra in extras
                        ):
                            continue

                except Exception:
                    # Invalid metadata shouldn't break the entire
                    # dependency graph.
                    continue

                child_key = canonicalize_name(
                    req.name
                )

                parents = reverse.setdefault(
                    child_key,
                    [],
                )

                if parent_key not in parents:
                    parents.append(parent_key)

        target_key = canonicalize_name(target)
        target_pkg = packages.get(target_key)

        # --------------------------------------------------------------
        # Target wasn't found
        # --------------------------------------------------------------

        if target_pkg is None:
            return {
                "package": target,
                "version": None,
                "introducers": [],
            }

        # --------------------------------------------------------------
        # IMPORTANT:
        #
        # If the target itself is explicitly declared in requirements.in,
        # it is already the actionable root.
        #
        # Don't walk to FastAPI/etc and incorrectly report those as the
        # introducer.
        # --------------------------------------------------------------

        if target_pkg["requested"]:
            return {
                "package": target_pkg["name"],
                "version": target_pkg["version"],
                "introducers": [
                    {
                        "package": target_pkg["name"],
                        "version": target_pkg["version"],
                    }
                ],
            }

        # --------------------------------------------------------------
        # Transitive target:
        # walk upward until requested/root packages are reached.
        # --------------------------------------------------------------

        introducers = {}
        visited = set()

        def walk(name: str):
            if name in visited:
                return

            visited.add(name)

            for parent_key in reverse.get(
                name,
                [],
            ):
                parent = packages.get(parent_key)

                if parent is None:
                    continue

                if parent["requested"]:
                    introducers[parent_key] = {
                        "package": parent["name"],
                        "version": parent["version"],
                    }
                    continue

                walk(parent_key)

        walk(target_key)

        return {
            "package": target_pkg["name"],
            "version": target_pkg["version"],
            "introducers": list(
                introducers.values()
            ),
        }
   