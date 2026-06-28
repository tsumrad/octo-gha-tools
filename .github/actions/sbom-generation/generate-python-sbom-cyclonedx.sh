#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   generate-python-sbom-cyclonedx.sh <project_dir> <output_prefix>

PROJECT_DIR="${1:?project directory is required}"
OUTPUT_PREFIX="${2:?output prefix is required}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CYCLONEDX_BOM_VERSION="${CYCLONEDX_BOM_VERSION:-7.3.0}"
POETRY_VERSION="${POETRY_VERSION:-2.2.1}"

log() {
  echo "[python-sbom] $*"
}

die() {
  echo "[python-sbom] ERROR: $*" >&2
  exit 1
}

is_poetry_project() {
  [ -f "poetry.lock" ] || grep -q '^\[tool\.poetry\]' pyproject.toml 2>/dev/null
}

ensure_poetry_lock() {
  if [ ! -f "poetry.lock" ]; then
    log "poetry.lock not found; generating lock file"
    "$TOOL_POETRY" lock --no-interaction
  fi
}

verify_sbom() {
  local sbom_file="$1"
  local python_bin="$2"

  [ -f "$sbom_file" ] || die "SBOM output missing: $sbom_file"

  local component_count
  component_count="$("$python_bin" - "$sbom_file" <<'PY'
import json, sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

print(len(data.get("components") or []))
PY
)"

  if [ "$component_count" -eq 0 ]; then
    die "SBOM contains zero components: $sbom_file"
  fi

  log "SBOM contains $component_count components"
}

[ -d "$PROJECT_DIR" ] || die "Project directory does not exist: $PROJECT_DIR"

mkdir -p "$(dirname "$OUTPUT_PREFIX")"

OUTPUT_FILE="$(cd "$(dirname "$OUTPUT_PREFIX")" && pwd)/$(basename "$OUTPUT_PREFIX").cyclonedx.json"
SPDX_FILE="$(cd "$(dirname "$OUTPUT_PREFIX")" && pwd)/$(basename "$OUTPUT_PREFIX").spdx.json"
GITHUB_FILE="$(cd "$(dirname "$OUTPUT_PREFIX")" && pwd)/$(basename "$OUTPUT_PREFIX").github.json"

TOOL_VENV="$(mktemp -d)"
PROJECT_VENV=""

cleanup() {
  rm -rf "$TOOL_VENV"
  [ -n "${PROJECT_VENV}" ] && rm -rf "$PROJECT_VENV"
}
trap cleanup EXIT

log "Installing SBOM tooling"

python -m venv "$TOOL_VENV"
TOOL_PYTHON="$TOOL_VENV/bin/python"

"$TOOL_PYTHON" -m pip install --disable-pip-version-check --quiet \
  "cyclonedx-bom==$CYCLONEDX_BOM_VERSION" \
  "poetry==$POETRY_VERSION"

TOOL_POETRY="$TOOL_VENV/bin/poetry"

pushd "$PROJECT_DIR" >/dev/null

if is_poetry_project; then
  log "Detected Poetry project"

  ensure_poetry_lock

  PROJECT_VENV="$(mktemp -d)"

  log "Installing Poetry dependencies"

  export POETRY_VIRTUALENVS_CREATE=true
  export POETRY_VIRTUALENVS_PATH="$PROJECT_VENV"
  "$TOOL_POETRY" install --no-interaction --no-root

  PROJECT_PYTHON="$("$TOOL_POETRY" env info --executable)"

  log "Generating SBOM from installed Poetry environment"

  "$TOOL_PYTHON" -m cyclonedx_py environment \
    "$PROJECT_PYTHON" \
    --output-format JSON \
    --output-file "$OUTPUT_FILE"

elif [ -f "requirements.txt" ]; then
  log "Detected requirements.txt project"

  PROJECT_VENV="$(mktemp -d)"
  python -m venv "$PROJECT_VENV"

  PROJECT_PYTHON="$PROJECT_VENV/bin/python"

  log "Installing requirements"

  "$PROJECT_PYTHON" -m pip install --disable-pip-version-check --quiet --upgrade pip
  "$PROJECT_PYTHON" -m pip install --disable-pip-version-check --quiet -r requirements.txt

  log "Generating SBOM from installed environment"

  "$TOOL_PYTHON" -m cyclonedx_py environment \
    "$PROJECT_PYTHON" \
    --output-format JSON \
    --output-file "$OUTPUT_FILE"
else
  die "No supported dependency manifest found (poetry.lock, pyproject.toml, or requirements.txt)"
fi

log "Generating SPDX SBOM for dependency graph submission"

syft "dir:." \
  --output "spdx-json=$SPDX_FILE"

log "Generating GitHub dependency snapshot from installed environment"

"$PROJECT_PYTHON" - "$PROJECT_DIR" "$GITHUB_FILE" <<'PY'
import importlib.metadata
import json
import re
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_name(requirement: str) -> str | None:
    value = requirement.strip()
    if not value or value.startswith("#") or value.startswith(("-r ", "--requirement ")):
        return None
    if value.startswith(("-e ", "--editable ")):
        value = value.split(maxsplit=1)[1]
    if value.startswith((".", "/", "git+", "http://", "https://")):
        return None
    match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9_.-]*)", value)
    return normalize_name(match.group(1)) if match else None


def direct_dependencies(project_dir: Path) -> set[str]:
    dependencies: set[str] = set()

    requirements = project_dir / "requirements.txt"
    if requirements.is_file():
        for line in requirements.read_text(encoding="utf-8").splitlines():
            name = requirement_name(line)
            if name:
                dependencies.add(name)

    pyproject = project_dir / "pyproject.toml"
    if pyproject.is_file():
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        project = data.get("project") or {}
        for requirement in project.get("dependencies") or []:
            name = requirement_name(requirement)
            if name:
                dependencies.add(name)

        poetry_dependencies = (
            ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
        )
        for name in poetry_dependencies:
            normalized = normalize_name(name)
            if normalized != "python":
                dependencies.add(normalized)

    return dependencies


def purl(name: str, version: str) -> str:
    return f"pkg:pypi/{quote(normalize_name(name))}@{quote(version)}"


project_dir = Path(sys.argv[1]).resolve()
output_file = Path(sys.argv[2]).resolve()
direct = direct_dependencies(project_dir)
resolved = {}

for distribution in importlib.metadata.distributions():
    name = distribution.metadata.get("Name")
    version = distribution.version
    if not name or not version:
        continue

    normalized = normalize_name(name)
    resolved[normalized] = {
        "package_url": purl(name, version),
        "relationship": "direct" if normalized in direct else "indirect",
        "scope": "runtime",
    }

snapshot = {
    "version": 0,
    "sha": "",
    "ref": "",
    "scanned": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    "job": {
        "id": "",
        "correlator": "",
    },
    "detector": {
        "name": "python-installed-environment",
        "version": "1",
        "url": "https://github.com/tsumrad/gh-tools",
    },
    "manifests": {
        str(project_dir): {
            "name": project_dir.name or "python-project",
            "file": {
                "source_location": str(project_dir),
            },
            "resolved": dict(sorted(resolved.items())),
        }
    },
}

output_file.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

popd >/dev/null

verify_sbom "$OUTPUT_FILE" "$TOOL_PYTHON"

log "SBOM written to: $OUTPUT_FILE"