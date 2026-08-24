# tools/

Scripts appelés par le `Makefile`. Pas de logique métier ici — orchestration uniquement.

| Script | Appelé par | Rôle |
|---|---|---|
| `check-arch.sh` | `make test-arch` | Règles de dépendance `apps/`, interdiction crypto directe, fichiers générés à jour |
| `collect-sbom.sh` | `make sbom` | SBOM CycloneDX Rust (`cargo-cyclonedx`) + Go (`cyclonedx-gomod`), consolidés sous `security/sbom/` |
| `generate-cbom.sh` | `make sbom` | Régénère l'inventaire cryptographique depuis `crates/zs-crypto` |
| `generate-provenance.sh` | **orphelin depuis ADR-033** | Statement in-toto/SLSA simplifié, signé par cosign — écrit pour le Jenkinsfile d'ADR-005 (remplacé). La CI GitHub Actions signe désormais via `actions/attest-build-provenance@v1` (keyless OIDC), qui ne l'appelle pas. Conservé, pas supprimé, au cas où une signature manuelle hors CI serait un jour nécessaire — à retirer si ce besoin ne se matérialise pas. |
| `migrate.sh` | `make up` | Applique les migrations PostgreSQL sur l'environnement local |
