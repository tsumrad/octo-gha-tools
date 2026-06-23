#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   generate-sbom.sh <source> <output_prefix>
#
# Example:
#   generate-sbom.sh "dir:." "filesystem"
#
# Produces:
#   filesystem.cyclonedx.json
#   filesystem.spdx.json

SOURCE="${1:?source is required}"
OUTPUT_PREFIX="${2:?output prefix is required}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() {
	echo "[sbom] $*"
}

source_directory() {
	case "$SOURCE" in
		dir:*) printf '%s\n' "${SOURCE#dir:}" ;;
		*) return 1 ;;
	esac
}

has_python_dependency_manifest() {
	local project_dir="$1"

	[ -f "$project_dir/poetry.lock" ] ||
	find "$project_dir" -maxdepth 1 -type f -name 'requirements*.txt' | grep -q . ||
	{
		[ -f "$project_dir/pyproject.toml" ] &&
		grep -q "\[tool.poetry\]" "$project_dir/pyproject.toml"
	}
}

generate_cyclonedx_sbom() {
	local source="$1"

	log "Generating CycloneDX SBOM with Syft"

	syft "$source" \
		--output "cyclonedx-json=${OUTPUT_PREFIX}.cyclonedx.json"
}

generate_spdx_sbom() {
	local source="$1"

	log "Generating SPDX JSON 2.2 SBOM with Python metadata"

	syft "$source" \
		--catalogers python-package-cataloger \
		--output "spdx-json@2.2=${OUTPUT_PREFIX}.spdx.json"
}

generate_python_dependency_sbom() {
	local project_dir="$1"

	log "Generating dependency-aware Python CycloneDX SBOM"

	bash "$SCRIPT_DIR/generate-python-sbom-cyclonedx.sh" \
		"$project_dir" \
		"$OUTPUT_PREFIX"
}


PROJECT_DIR="$(source_directory)" || {
	log "Non-directory source detected"

	generate_cyclonedx_sbom "$SOURCE"
	generate_spdx_sbom "$SOURCE"

	exit 0
}


if has_python_dependency_manifest "$PROJECT_DIR"; then
	log "Python dependency manifest detected"

	# Generate dependency-aware CycloneDX SBOM
	generate_python_dependency_sbom "$PROJECT_DIR"

	# IMPORTANT:
	# Generate SPDX from the Python project directory,
	# not the raw source/container filesystem.
	generate_spdx_sbom "$PROJECT_DIR"

else
	log "No Python dependency manifest detected"

	generate_cyclonedx_sbom "$SOURCE"
	generate_spdx_sbom "$SOURCE"
fi


log "SBOM generation completed"

ls -lh \
	"${OUTPUT_PREFIX}.cyclonedx.json" \
	"${OUTPUT_PREFIX}.spdx.json" 2>/dev/null || true


log "Validating SPDX package metadata"

jq '
[
	.packages[]
	| {
		name,
		versionInfo,
		purl: [
			.externalRefs[]?
			| select(.referenceType=="purl")
			| .referenceLocator
		]
	}
]
| .[0:10]
' "${OUTPUT_PREFIX}.spdx.json"