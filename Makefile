SHELL := /bin/bash
.DEFAULT_GOAL := help
.PHONY: help setup generate check test test-crypto test-e2e fuzz audit sbom up down replay clean

# go.work regroupe plusieurs modules sous des sous-dossiers indépendants (pas de module à la
# racine) : le pattern ./... ne fonctionne pas depuis la racine du workspace. On itère sur les
# modules déclarés dans go.work.
define go-each
	@go list -m -f '{{.Dir}}' | while IFS= read -r d; do \
		echo "-- $$d --"; \
		(cd "$$d" && $(1)) || exit 1; \
	done
endef

help: ## Affiche cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

setup: ## Dépendances, SoftHSM2, hooks git, outillage
	@command -v cargo >/dev/null || { echo "cargo absent"; exit 1; }
	@command -v go    >/dev/null || { echo "go absent"; exit 1; }
	cargo install --locked cargo-deny cargo-audit cargo-fuzz cargo-nextest cargo-cyclonedx || true
	go install golang.org/x/vuln/cmd/govulncheck@latest || true
	go install github.com/zricethezav/gitleaks/v8@latest || true
	go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest || true
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest || true
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest || true
	git config core.hooksPath .githooks
	git config commit.gpgsign true
	@echo "Vérifier SoftHSM2 : $$ZS_HSM_MODULE"
	@echo "commit.gpgsign activé localement — nécessite une clé de signature configurée (git config user.signingkey)."

generate: ## Régénère types et clients depuis contracts/ — À LANCER APRÈS TOUTE MODIF DE CONTRAT
	cd contracts && buf lint
	cd contracts && buf breaking --against '../.git#branch=main,subdir=contracts' || true
	cd contracts && buf generate
	@echo "Go régénéré dans pkg/gen (committé). Rust régénéré à la compilation par"
	@echo "crates/zs-policy/build.rs (ADR-004) — lancer 'cargo build -p zs-policy' pour vérifier."
	bash tools/generate-openapi.sh
	@echo "Fichiers générés — ne jamais les éditer à la main."

check: ## fmt + lint + tests d'architecture (rapide)
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features -- -D warnings
	gofmt -l . | tee /dev/stderr | (! read)
	$(call go-each,go vet ./...)
	$(MAKE) test-arch

test-arch: ## Règles de dépendance, interdiction crypto directe, fichiers générés à jour
	@bash tools/check-arch.sh

test: ## Unitaires + propriété + politiques
	cargo nextest run --all-features
	$(call go-each,go test ./... -race)
	# `cedar test` n'existe pas : le CLI expose `validate` et `run-tests`, et n'accepte qu'un
	# fichier de politiques (pas un dossier). tools/cedar-test.sh fait les deux (L2.1).
	# `|| true` conservé tel quel : rendre l'étape bloquante suppose de provisionner le CLI
	# Cedar dans .github/workflows/ci.yml — changement de CI, validation humaine explicite requise.
	bash tools/cedar-test.sh || true
	# policies/platform n'existe pas encore : Rego plateforme non commencé (audit.md §5.2).
	# Message explicite plutôt qu'un `|| true` qui masquerait aussi une vraie régression Rego
	# le jour où le dossier existera.
	@if [ -d policies/platform ]; then \
		opa test policies/platform policies/tests -v; \
	else \
		echo "policies/platform absent — Rego plateforme non implémenté, voir audit.md §5.2"; \
	fi

test-crypto: ## Vecteurs Wycheproof, conformité WebAuthn, intégration PKCS#11 (H1, ADR-011)
	# `--features conformance` retiré (audit.md §3.2) : aucun des deux crates ne déclare cette
	# feature, la cible échouait immédiatement. Vecteurs Wycheproof/WebAuthn officiels toujours
	# absents du dépôt — à sourcer séparément (audit.md §3.2).
	cargo test -p zs-crypto -- --include-ignored
	cargo test -p zs-webauthn -- --include-ignored
	@echo "Vérifier SoftHSM2 : $$ZS_HSM_MODULE"
	cargo test -p zs-hsm -- --include-ignored

fuzz: ## Fuzzing ciblé — make fuzz TARGET=attestation_parser
	@test -n "$(TARGET)" || { echo "Usage: make fuzz TARGET=<cible>"; exit 1; }
	cargo fuzz run $(TARGET) -- -max_total_time=300

audit: ## cargo-audit, cargo-deny, govulncheck, gitleaks
	cargo audit
	cargo deny check licenses bans sources advisories
	$(call go-each,govulncheck ./...)
	gitleaks detect --no-banner --redact

sbom: ## SBOM CycloneDX + inventaire cryptographique (CBOM)
	@bash tools/collect-sbom.sh
	@mkdir -p security/crypto-inventory
	@bash tools/generate-cbom.sh > security/crypto-inventory/cbom.json
	@echo "CBOM régénéré — vérifier le diff avant commit."

up: ## Environnement local complet (Podman)
	podman-compose -f deploy/compose.dev.yml up -d
	@echo "Attente de PostgreSQL (healthcheck)..."
	@until podman-compose -f deploy/compose.dev.yml ps postgres | grep -q "healthy"; do sleep 1; done
	bash tools/migrate.sh
	@echo "OpenBao : jeton root généré à la volée, voir 'podman-compose -f deploy/compose.dev.yml logs openbao'."

down: ## Arrête l'environnement local
	podman-compose -f deploy/compose.dev.yml down -v

test-e2e: ## Tests de bout en bout contre l'environnement local (make up requis)
	@bash tests/e2e/audit_writer_refuses_delete.sh

replay: ## Rejeu des décisions depuis le journal d'audit — NON IMPLÉMENTÉ (audit.md §5.4)
	@echo "make replay : crate zs-replay non implémenté — voir audit.md §5.4. Rejeu indisponible." >&2
	@exit 1

clean:
	cargo clean && go clean -cache
