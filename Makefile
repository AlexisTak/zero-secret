SHELL := /bin/bash
.DEFAULT_GOAL := help
.PHONY: help setup generate check test test-crypto fuzz audit sbom up down replay clean

help: ## Affiche cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

setup: ## Dépendances, SoftHSM2, hooks git, outillage
	@command -v cargo >/dev/null || { echo "cargo absent"; exit 1; }
	@command -v go    >/dev/null || { echo "go absent"; exit 1; }
	cargo install --locked cargo-deny cargo-audit cargo-fuzz cargo-nextest || true
	go install golang.org/x/vuln/cmd/govulncheck@latest || true
	git config core.hooksPath .githooks
	@echo "Vérifier SoftHSM2 : $$ZS_HSM_MODULE"

generate: ## Régénère types et clients depuis contracts/ — À LANCER APRÈS TOUTE MODIF DE CONTRAT
	buf lint contracts/proto
	buf breaking contracts/proto --against '.git#branch=main,subdir=contracts/proto' || true
	buf generate contracts/proto
	@echo "Fichiers générés — ne jamais les éditer à la main."

check: ## fmt + lint + tests d'architecture (rapide)
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features -- -D warnings
	gofmt -l . | tee /dev/stderr | (! read)
	go vet ./...
	$(MAKE) test-arch

test-arch: ## Règles de dépendance, interdiction crypto directe, fichiers générés à jour
	@bash tools/check-arch.sh

test: ## Unitaires + propriété + politiques
	cargo nextest run --all-features
	go test ./... -race
	cedar test --policies policies/access --tests policies/tests || true
	opa test policies/platform policies/tests -v || true

test-crypto: ## Vecteurs Wycheproof, conformité WebAuthn
	cargo test -p zs-crypto --features conformance -- --include-ignored
	cargo test -p zs-webauthn --features conformance -- --include-ignored

fuzz: ## Fuzzing ciblé — make fuzz TARGET=attestation_parser
	@test -n "$(TARGET)" || { echo "Usage: make fuzz TARGET=<cible>"; exit 1; }
	cargo fuzz run $(TARGET) -- -max_total_time=300

audit: ## cargo-audit, cargo-deny, govulncheck, gitleaks
	cargo audit
	cargo deny check licenses bans sources advisories
	govulncheck ./...
	gitleaks detect --no-banner --redact

sbom: ## SBOM CycloneDX + inventaire cryptographique (CBOM)
	cargo cyclonedx --format json --output-pattern package -- --all-features
	cyclonedx-gomod mod -json -output security/sbom/go.cdx.json .
	@bash tools/generate-cbom.sh > security/crypto-inventory/cbom.json
	@echo "CBOM régénéré — vérifier le diff avant commit."

up: ## Environnement local complet (Podman)
	podman-compose -f deploy/compose.dev.yml up -d
	@sleep 3 && bash tools/migrate.sh

down: ## Arrête l'environnement local
	podman-compose -f deploy/compose.dev.yml down -v

replay: ## Rejeu des décisions depuis le journal d'audit
	cargo run -p zs-replay -- --from $(FROM) --to $(TO)

clean:
	cargo clean && go clean -cache
