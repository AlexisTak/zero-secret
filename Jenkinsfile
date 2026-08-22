// Chaîne CI — backlog L0.4, sur Jenkins (ADR-005 : remplace GitHub Actions).
//
// Agents jetables : chaque stage tourne dans un conteneur Docker frais, détruit après usage
// (plugin Docker Pipeline). `agent none` au niveau du pipeline — aucun agent persistant.
//
// Ordre des étapes imposé par le backlog : format → lint → détection de secrets → build →
// tests → tests d'architecture → analyse de dépendances → SBOM → CBOM → build reproductible →
// signature → attestation.

pipeline {
    agent none

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    stages {
        stage('format + lint (Rust)') {
            agent { docker { image 'rust:1-bookworm' } }
            steps {
                sh 'rustup component add rustfmt clippy'
                sh 'cargo fmt --all -- --check'
                sh 'cargo clippy --workspace --all-targets --all-features -- -D warnings'
            }
        }

        stage('format + lint (Go)') {
            agent { docker { image 'golang:1.23-bookworm' } }
            steps {
                sh 'test -z "$(gofmt -l .)" || { gofmt -l .; exit 1; }'
                sh '''
                    go list -m -f '{{.Dir}}' | while IFS= read -r d; do
                        (cd "$d" && go vet ./...) || exit 1
                    done
                '''
            }
        }

        stage('contrats (buf lint + breaking)') {
            // Reprend la logique de l'ancien .github/workflows/contracts.yml (retiré, ADR-005).
            // Prérequis d'exploitation : le clonage du job Jenkins doit avoir l'historique
            // complet (désactiver le "shallow clone" dans la config du job/multibranch), sinon
            // `buf breaking --against .git#branch=main` ne trouve pas la branche de référence.
            when { anyOf { changeset 'contracts/**'; changeset 'pkg/gen/**' } }
            agent { docker { image 'bufbuild/buf:latest'; args '--entrypoint=""' } }
            steps {
                dir('contracts') {
                    sh 'buf lint'
                    sh '''
                        buf breaking --against "../.git#branch=main,subdir=contracts" || {
                            echo "buf breaking a échoué : vérifier une éventuelle suppression de champ." >&2
                            exit 1
                        }
                    '''
                }
            }
        }

        stage('contrats : pkg/gen à jour') {
            when { anyOf { changeset 'contracts/**'; changeset 'pkg/gen/**' } }
            agent { docker { image 'golang:1.23-bookworm' } }
            steps {
                sh 'go install google.golang.org/protobuf/cmd/protoc-gen-go@latest'
                sh 'go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest'
                sh '''
                    apt-get update && apt-get install -y --no-install-recommends curl
                    curl -sSL https://github.com/bufbuild/buf/releases/download/v1.72.0/buf-Linux-x86_64 -o /usr/local/bin/buf
                    chmod +x /usr/local/bin/buf
                    export PATH="$PATH:$(go env GOPATH)/bin"
                    (cd contracts && buf generate)
                    git diff --exit-code -- pkg/gen || {
                        echo "pkg/gen diverge de contracts/proto — lancer make generate et committer." >&2
                        exit 1
                    }
                '''
            }
        }

        stage('détection de secrets') {
            agent { docker { image 'zricethezav/gitleaks:latest'; args '--entrypoint=""' } }
            steps {
                // fetch-depth complet : gitleaks scanne l'historique, pas seulement HEAD
                sh 'gitleaks detect --no-banner --redact --source .'
            }
        }

        stage('build + tests (Rust)') {
            agent { docker { image 'rust:1-bookworm' } }
            steps {
                sh 'cargo build --workspace'
                sh 'cargo install --locked cargo-nextest || true'
                sh 'cargo nextest run --all-features || cargo test --all-features'
            }
        }

        stage('build + tests (Go)') {
            agent { docker { image 'golang:1.23-bookworm' } }
            steps {
                sh '''
                    go list -m -f '{{.Dir}}' | while IFS= read -r d; do
                        (cd "$d" && go build ./... && go test ./... -race) || exit 1
                    done
                '''
            }
        }

        stage('tests d\'architecture (L0.2)') {
            agent { docker { image 'ubuntu:22.04' } }
            steps {
                sh 'bash tools/check-arch.sh'
            }
        }

        stage('analyse de dépendances (Rust)') {
            agent { docker { image 'rust:1-bookworm' } }
            steps {
                sh 'cargo install --locked cargo-audit cargo-deny'
                sh 'cargo audit'
                sh 'cargo deny check licenses bans sources advisories'
            }
        }

        stage('analyse de dépendances (Go)') {
            agent { docker { image 'golang:1.23-bookworm' } }
            steps {
                sh '''
                    go install golang.org/x/vuln/cmd/govulncheck@latest
                    go list -m -f '{{.Dir}}' | while IFS= read -r d; do
                        (cd "$d" && govulncheck ./...) || exit 1
                    done
                '''
            }
        }

        stage('SBOM (Rust) + CBOM') {
            agent { docker { image 'rust:1-bookworm' } }
            steps {
                sh '''
                    cargo install --locked cargo-cyclonedx
                    cargo cyclonedx --format json --all-features --spec-version 1.5
                    mkdir -p security/sbom/rust
                    find apps crates -maxdepth 2 -name '*.cdx.json' -exec mv {} security/sbom/rust/ \\;
                    bash tools/generate-cbom.sh > security/crypto-inventory/cbom.json
                '''
                archiveArtifacts artifacts: 'security/sbom/rust/*.json,security/crypto-inventory/cbom.json', fingerprint: true
            }
        }

        stage('SBOM (Go)') {
            // Toolchain Go dédiée (1.23, go.work) — pas d'apt-get golang-go dans l'image Rust :
            // Debian bookworm fournit un Go trop ancien pour go.work (pas d'auto-toolchain).
            // Duplique une partie de tools/collect-sbom.sh (conçu pour un seul hôte avec les
            // deux toolchains) — inévitable ici puisque chaque stage a son propre conteneur.
            agent { docker { image 'golang:1.23-bookworm' } }
            steps {
                sh '''
                    go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest
                    mkdir -p security/sbom/go
                    go list -m -f '{{.Path}} {{.Dir}}' | while IFS=' ' read -r modpath moddir; do
                        name=$(basename "$modpath")
                        cyclonedx-gomod mod -json -output "security/sbom/go/$name.cdx.json" "$moddir"
                    done
                '''
                archiveArtifacts artifacts: 'security/sbom/go/*.json', fingerprint: true
            }
        }

        stage('build reproductible (informatif)') {
            agent { docker { image 'rust:1-bookworm' } }
            steps {
                // Non bloquant : voir docs/backlog.md L0.4 — limite constatée localement
                // (build Rust non déterministe sans configuration dédiée).
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''
                        cargo build --release -p identity-provider -p policy-engine
                        cp target/release/identity-provider /tmp/build1-identity-provider
                        cp target/release/policy-engine /tmp/build1-policy-engine
                        cargo clean --release -p identity-provider -p policy-engine
                        cargo build --release -p identity-provider -p policy-engine
                        diff <(sha256sum /tmp/build1-identity-provider | cut -d' ' -f1) \
                             <(sha256sum target/release/identity-provider | cut -d' ' -f1)
                        diff <(sha256sum /tmp/build1-policy-engine | cut -d' ' -f1) \
                             <(sha256sum target/release/policy-engine | cut -d' ' -f1)
                    '''
                }
            }
        }

        stage('signature + attestation') {
            // Seulement sur main : ADR-005 — clé de signature dans le Jenkins Credentials
            // Store (dérogation documentée à la règle absolue #1, rotation tous les 90 jours).
            when { branch 'main' }
            agent { docker { image 'rust:1-bookworm'; args '-u root' } }
            environment {
                COSIGN_KEY  = credentials('zero-secret-cosign-key')      // fichier clé privée cosign
                COSIGN_PASSWORD = credentials('zero-secret-cosign-password')
            }
            steps {
                sh '''
                    apt-get update && apt-get install -y --no-install-recommends curl jq
                    curl -sSL https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64 -o /usr/local/bin/cosign
                    chmod +x /usr/local/bin/cosign

                    cargo build --release -p identity-provider -p policy-engine

                    bash tools/generate-provenance.sh \
                        "${GIT_COMMIT}" "${BUILD_URL}" "${BUILD_NUMBER}" \
                        target/release/identity-provider target/release/policy-engine \
                        > provenance.intoto.json

                    for artefact in target/release/identity-provider target/release/policy-engine provenance.intoto.json; do
                        cosign sign-blob --key "$COSIGN_KEY" --yes \
                            --output-signature "${artefact}.sig" "${artefact}"
                    done
                '''
                archiveArtifacts artifacts: 'target/release/identity-provider,target/release/identity-provider.sig,target/release/policy-engine,target/release/policy-engine.sig,provenance.intoto.json,provenance.intoto.json.sig', fingerprint: true
            }
        }
    }
}
