#!/usr/bin/env bash
# Génère une attestation de provenance (format in-toto simplifié) pour les artefacts d'un build
# Jenkins. Remplace le rôle de actions/attest-build-provenance (GitHub) — voir ADR-005 :
# Jenkins n'a pas d'équivalent OIDC natif, cette attestation est signée séparément par cosign
# avec la clé stockée dans le Jenkins Credentials Store.
#
# Usage : generate-provenance.sh <commit> <build_url> <build_number> <artefact...>
set -euo pipefail

commit="$1"
build_url="$2"
build_number="$3"
shift 3

subjects="[]"
for artefact in "$@"; do
	digest=$(sha256sum "$artefact" | cut -d' ' -f1)
	name=$(basename "$artefact")
	subjects=$(echo "$subjects" | jq --arg name "$name" --arg digest "$digest" \
		'. + [{"name": $name, "digest": {"sha256": $digest}}]')
done

jq -n \
	--argjson subject "$subjects" \
	--arg commit "$commit" \
	--arg buildUrl "$build_url" \
	--arg buildNumber "$build_number" \
	'{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": $subject,
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {
			"buildDefinition": {
				"buildType": "https://biscuits-ia.fr/zero-secret/jenkins-pipeline/v1",
				"externalParameters": {
					"jenkinsfile": "Jenkinsfile"
				},
				"resolvedDependencies": [
					{ "uri": ("git+https://github.com/Biscuits-ia/biscuits-shield@" + $commit) }
				]
			},
			"runDetails": {
				"builder": { "id": "https://biscuits-ia.fr/zero-secret/jenkins" },
				"metadata": {
					"invocationId": $buildUrl,
					"buildNumber": $buildNumber
				}
			}
		}
	}'
