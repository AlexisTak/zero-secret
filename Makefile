SHELL := /bin/bash
.DEFAULT_GOAL := help
.PHONY: help setup generate check test test-extensions test-crypto test-e2e fuzz audit security-quick security-full security-fuzz sbom up down replay clean

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
	go install github.com/open-policy-agent/opa@latest || true
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

test: ## Unitaires + propriété + politiques d'accès (Core MVP)
	cargo nextest run --all-features
	$(call go-each,go test ./... -race)
	# `cedar test` n'existe pas : le CLI expose `validate` et `run-tests`, et n'accepte qu'un
	# fichier de politiques (pas un dossier). tools/cedar-test.sh fait les deux (L2.1).
	#
	# BLOQUANT depuis la réduction de périmètre. Le `|| true` précédent laissait passer une
	# régression du moteur d'autorisation du Core alors que la conformité d'infrastructure, elle,
	# bloquait : la CI garantissait la politique optionnelle et pas la politique critique. Le CLI
	# Cedar est désormais provisionné par le job build-test (.github/workflows/ci.yml).
	bash tools/cedar-test.sh

test-extensions: ## Conformité plateforme (Rego/OPA) — EXPERIMENTAL, hors Core MVP
	# extensions/policy-platform/ n'est importé par aucun composant de apps/ ni crates/ : son
	# échec ne compromet aucune garantie du MVP. Cible séparée pour que `make test` reste le
	# périmètre Core, et job CI distinct.
	# Le CLI OPA doit être présent : https://openpolicyagent.org/docs/latest/#running-opa
	opa test extensions/policy-platform/policies extensions/policy-platform/tests -v

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

security-quick: ## Tests de sécurité handler-level + fonctions pures — CI, rapide, pas d'infra requise
# Chaque etape est executee meme si la precedente echoue, mais son code de sortie est CONSERVE et
# rejoue a la fin : sans cela un test rouge qui ne produit aucun finding (la plupart signalent par
# t.Fatal, pas par un rapport) laisserait la cible verte — chaine fail-open, contraire a la regle
# absolue #2. La decision bloquante finale est portee par l agregateur (code de sortie 1 si un
# finding blocking=true subsiste), jamais par un grep sur la mise en forme du JSON.
# -count=1 desactive le cache de go test : un test servi depuis le cache ne reexecute pas
# writeSecurityReport, et le rapport serait vide alors que les findings existent.
	@rc=0; \
	go list -m -f '{{.Dir}}' | while IFS= read -r d; do \
		echo "-- $$d --"; \
		(cd "$$d" && go test ./... -count=1 -race -run 'TestSecurity|FuzzSecurity') || exit 1; \
	done || rc=1; \
	cargo test -p identity-provider --lib security_ || rc=1; \
	(cd apps/console-web && npm run build && node --test "dist/**/security.test.js") || rc=1; \
	bash tests/security/infrastructure/check_compose_dev.sh || rc=1; \
	(cd tests/security/report/aggregate && go run . ../output > ../output/report.md); agg=$$?; \
	cat tests/security/report/output/report.md 2>/dev/null || true; \
	[ $$agg -eq 0 ] || rc=1; \
	exit $$rc

security-full: ## Suite complète contre l'environnement local — make up requis (Postgres + SoftHSM2)
	@echo "Phase 2 — nécessite make up, voir tests/security/README.md"
	@exit 1

security-fuzz: ## Fuzzing natif Go des décodeurs JSON, budget borné
# Restreint aux modules portant reellement une cible Fuzz : go test -fuzz sort en erreur quand
# aucune cible ne matche, ce qui rendait la cible inutilisable des le premier module sans fuzz.
	@for d in apps/admin-api apps/access-broker; do \
		echo "-- $$d --"; \
		(cd "$$d" && go test ./internal/httpapi/... -fuzz=FuzzSecurity -fuzztime=60s) || exit 1; \
	done

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
