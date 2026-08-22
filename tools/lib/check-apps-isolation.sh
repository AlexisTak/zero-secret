#!/usr/bin/env bash
# Règle 7 (CLAUDE.md) : un composant de apps/ ne dépend jamais d'un autre composant de apps/.
# Détection statique — pas de build, pour rester rapide dans `make check`.
#
# Usage : check_apps_isolation <racine>
# Sortie non nulle et message sur stderr par violation trouvée.
set -euo pipefail

check_apps_isolation() {
	local root="$1"
	local apps_dir="$root/apps"
	local violations=0

	[[ -d "$apps_dir" ]] || return 0

	local app_dir app_name
	for app_dir in "$apps_dir"/*/; do
		[[ -d "$app_dir" ]] || continue
		app_name=$(basename "$app_dir")

		# --- Go : imports "apps/<autre>" dans les fichiers .go du composant ---
		local go_file
		while IFS= read -r -d '' go_file; do
			local hits
			hits=$(grep -EHo '"[^"]*/apps/[A-Za-z0-9_-]+' "$go_file" 2>/dev/null || true)
			[[ -z "$hits" ]] && continue
			while IFS= read -r hit; do
				local imported
				imported=$(printf '%s' "$hit" | grep -Eo '/apps/[A-Za-z0-9_-]+$' | sed 's#^/apps/##')
				if [[ -n "$imported" && "$imported" != "$app_name" ]]; then
					echo "VIOLATION apps-isolation : $go_file importe apps/$imported (composant $app_name)." >&2
					violations=$((violations + 1))
				fi
			done <<<"$hits"
		done < <(find "$app_dir" -name '*.go' -print0)

		# --- Rust : dépendances Cargo.toml dont le path résolu tombe sous apps/<autre> ---
		local toml
		while IFS= read -r -d '' toml; do
			local toml_dir
			toml_dir=$(dirname "$toml")
			local path_line
			while IFS= read -r path_line; do
				local rel_path resolved
				rel_path=$(printf '%s' "$path_line" | grep -Eo 'path\s*=\s*"[^"]+"' | sed -E 's/path\s*=\s*"([^"]+)"/\1/')
				[[ -z "$rel_path" ]] && continue
				resolved=$(realpath -m "$toml_dir/$rel_path")
				local apps_root
				apps_root=$(realpath -m "$apps_dir")
				local this_app
				this_app=$(realpath -m "$app_dir")
				if [[ "$resolved" == "$apps_root"/* && "$resolved" != "$this_app"* ]]; then
					echo "VIOLATION apps-isolation : $toml dépend de $resolved (composant $app_name)." >&2
					violations=$((violations + 1))
				fi
			done < <(grep -E 'path\s*=\s*"' "$toml" 2>/dev/null || true)
		done < <(find "$app_dir" -maxdepth 1 -name 'Cargo.toml' -print0)
	done

	return "$violations"
}
