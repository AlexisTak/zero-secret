# tools/

Scripts appelés par le `Makefile`. Pas de logique métier ici — orchestration uniquement.

| Script | Appelé par | Rôle |
|---|---|---|
| `check-arch.sh` | `make test-arch` | Règles de dépendance `apps/`, interdiction crypto directe, fichiers générés à jour |
| `collect-sbom.sh` | `make sbom` | SBOM CycloneDX Rust (`cargo-cyclonedx`) + Go (`cyclonedx-gomod`), consolidés sous `security/sbom/` |
| `generate-cbom.sh` | `make sbom` | Régénère l'inventaire cryptographique depuis `crates/zs-crypto` |
| `migrate.sh` | `make up` | Applique les migrations PostgreSQL sur l'environnement local |
