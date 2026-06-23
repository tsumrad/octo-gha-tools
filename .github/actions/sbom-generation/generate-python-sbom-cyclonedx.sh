#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   generate-python-sbom.sh <project_dir> <output_prefix>
#
# Produces:
#   <output_prefix>.cyclonedx.json


PROJECT_DIR="${1:?project directory is required}"
OUTPUT_PREFIX="${2:?output prefix is required}"

CYCLONEDX_BOM_VERSION="${CYCLONEDX_BOM_VERSION:-7.3.0}"
POETRY_VERSION="${POETRY_VERSION:-2.2.1}"
PYTHON_BIN="${PYTHON_BIN:-}"


log() {
	echo "[python-sbom] $*"
}


die() {
	echo "[python-sbom] ERROR: $*" >&2
	exit 1
}


resolve_python() {

	if [ -n "$PYTHON_BIN" ]; then

		command -v "$PYTHON_BIN" >/dev/null ||
			die "Configured Python not found: $PYTHON_BIN"

		return
	fi


	if command -v python3 >/dev/null; then
		PYTHON_BIN="python3"

	elif command -v python >/dev/null; then
		PYTHON_BIN="python"

	else
		die "Python interpreter not found"
	fi
}


is_poetry_project() {

	[ -f "poetry.lock" ] ||
	{
		[ -f "pyproject.toml" ] &&
		grep -q '^\[tool\.poetry\]' pyproject.toml
	}
}


requirements_file() {

	find . \
		-maxdepth 1 \
		-type f \
		-name 'requirements*.txt' |
		sort |
		head -n 1
}


install_tooling() {

	local packages=(
		"cyclonedx-bom==$CYCLONEDX_BOM_VERSION"
	)


	if is_poetry_project; then
		packages+=(
			"poetry==$POETRY_VERSION"
		)
	fi


	log "Installing SBOM tooling"


	"$PYTHON_BIN" -m venv "$TOOL_VENV"


	TOOL_PYTHON="$TOOL_VENV/bin/python"


	"$TOOL_PYTHON" -m pip install \
		--disable-pip-version-check \
		--quiet \
		"${packages[@]}"


	if is_poetry_project; then
		TOOL_POETRY="$TOOL_VENV/bin/poetry"
	fi
}


ensure_poetry_lock() {

	[ -f poetry.lock ] ||
		die "poetry.lock missing; deterministic SBOM requires lock file"
}


generate_poetry_environment() {

	log "Creating Poetry environment from lock file"


	PROJECT_VENV="$(mktemp -d)"


	export POETRY_VIRTUALENVS_CREATE=true
	export POETRY_VIRTUALENVS_PATH="$PROJECT_VENV"


	log "Installing Poetry dependencies"


	"$TOOL_POETRY" install \
		--no-interaction \
		--no-root


	PROJECT_PYTHON="$(
		"$TOOL_POETRY" env info --executable
	)"
}


generate_requirements_environment() {

	local requirements="$1"


	log "Installing requirements: ${requirements#./}"


	PROJECT_VENV="$(mktemp -d)"


	"$PYTHON_BIN" -m venv "$PROJECT_VENV"


	PROJECT_PYTHON="$PROJECT_VENV/bin/python"


	"$PROJECT_PYTHON" -m pip install \
		--disable-pip-version-check \
		--quiet \
		--upgrade pip


	"$PROJECT_PYTHON" -m pip install \
		--disable-pip-version-check \
		--quiet \
		-r "$requirements"
}


generate_cyclonedx_sbom() {

	log "Generating dependency graph CycloneDX SBOM"


	if is_poetry_project; then

		log "Detected Poetry project"

		ensure_poetry_lock

		generate_poetry_environment


		log "Generating SBOM from resolved environment"


		"$TOOL_PYTHON" -m cyclonedx_py environment \
			"$PROJECT_PYTHON" \
			--output-format JSON \
			--output-file "$CYCLONEDX_OUTPUT"


	elif [ -n "${REQUIREMENTS_FILE:-}" ]; then

		log "Detected requirements project"

		generate_requirements_environment \
			"$REQUIREMENTS_FILE"


		"$TOOL_PYTHON" -m cyclonedx_py environment \
			"$PROJECT_PYTHON" \
			--output-format JSON \
			--output-file "$CYCLONEDX_OUTPUT"

	else

		die "No dependency graph source found"

	fi
}


verify_cyclonedx() {

	[ -f "$CYCLONEDX_OUTPUT" ] ||
		die "CycloneDX output missing"


	local components
	local dependencies


	components="$(
		jq '.components | length' "$CYCLONEDX_OUTPUT"
	)"


	dependencies="$(
		jq '.dependencies | length' "$CYCLONEDX_OUTPUT"
	)"


	[ "$components" -gt 0 ] ||
		die "CycloneDX contains no components"


	log "CycloneDX components: $components"

	log "CycloneDX dependency graph entries: $dependencies"


	if [ "$dependencies" -eq 0 ]; then

		die "CycloneDX dependency graph missing"

	fi
}


[ -d "$PROJECT_DIR" ] ||
	die "Project directory does not exist: $PROJECT_DIR"


resolve_python


CYCLONEDX_OUTPUT="$(
	cd "$(dirname "$OUTPUT_PREFIX")" &&
	pwd
)/$(basename "$OUTPUT_PREFIX").cyclonedx.json"


TOOL_VENV="$(mktemp -d)"

PROJECT_VENV=""


cleanup() {

	rm -rf "$TOOL_VENV"


	if [ -n "${PROJECT_VENV:-}" ]; then
		rm -rf "$PROJECT_VENV"
	fi
}


trap cleanup EXIT


pushd "$PROJECT_DIR" >/dev/null


install_tooling


REQUIREMENTS_FILE=""

if ! is_poetry_project; then

	REQUIREMENTS_FILE="$(requirements_file)"

fi


if is_poetry_project || [ -n "$REQUIREMENTS_FILE" ]; then

	generate_cyclonedx_sbom

else

	die "No supported dependency manifest found"

fi


popd >/dev/null


verify_cyclonedx


log "CycloneDX dependency SBOM: $CYCLONEDX_OUTPUT"