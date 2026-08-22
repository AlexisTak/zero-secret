#!/usr/bin/env bash
# Génère le SBOM CycloneDX (Rust + Go) et le consolide sous security/sbom/. Appelé par
# `make sbom`. Fichiers régénérés à chaque appel — non committés (voir .gitignore).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT="$ROOT/security/sbom"
mkdir -p "$OUT/rust" "$OUT/go"

echo "-- SBOM Rust (workspace) --" >&2
(cd "$ROOT" && cargo cyclonedx --format json --all-features --spec-version 1.5)
find "$ROOT/apps" "$ROOT/crates" -maxdepth 2 -name '*.cdx.json' -print0 |
	while IFS= read -r -d '' f; do
		mv "$f" "$OUT/rust/$(basename "$f")"
	done

echo "-- SBOM Go (un module par module de go.work) --" >&2
go list -m -f '{{.Path}} {{.Dir}}' | while IFS=' ' read -r modpath moddir; do
	name=$(basename "$modpath")
	cyclonedx-gomod mod -json -output "$OUT/go/$name.cdx.json" "$moddir"
done

echo "SBOM régénéré sous $OUT — non committé, voir .gitignore." >&2
