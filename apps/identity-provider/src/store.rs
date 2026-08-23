//! Persistance sqlx pour la cérémonie WebAuthn (H5, ADR-023). Deux rôles Postgres distincts, un
//! pool par rôle : `identity_app` (schéma `identity` — challenges, authentificateurs) et
//! `audit_writer` (schéma `audit` — journal, ajout seul), jamais le même pool pour les deux
//! (règle d'architecture `docs/architecture.md` : « aucun rôle applicatif en écriture sur plus
//! d'un schéma »).
//!
//! N'implémente pas littéralement `zs_webauthn::store::{ChallengeStore, SignCounterStore}`
//! (traits synchrones, `&self` bloquant) : `sqlx` est asynchrone, et pontifier via
//! `block_in_place`/`block_on` depuis un handler déjà async ajoute une indirection sans
//! bénéfice ici (aucun autre appelant ne consomme ces traits par polymorphisme). Les méthodes
//! ci-dessous respectent exactement la même sémantique d'atomicité documentée par ces traits —
//! consommer/avancer en une seule requête `UPDATE ... WHERE ... RETURNING`, jamais un `SELECT`
//! puis un `UPDATE` séparés (mise en garde `referent-crypto`, fenêtre TOCTOU).

use zs_crypto::authenticator_proof::Algorithm;

pub struct IdentityStore {
    pool: sqlx::PgPool,
}

pub struct ConsumedChallenge {
    pub subject_id: String,
    pub ceremony_kind: String,
}

pub struct AuthenticatorRow {
    pub subject_id: String,
    pub credential_id: Vec<u8>,
    pub algorithm: Algorithm,
    pub public_key: Vec<u8>,
    pub counter_supported: bool,
    pub sign_count: u32,
    pub revoked: bool,
}

fn algorithm_to_column(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::Es256 => "es256",
        Algorithm::EdDsa => "eddsa",
    }
}

fn algorithm_from_column(value: &str) -> Option<Algorithm> {
    match value {
        "es256" => Some(Algorithm::Es256),
        "eddsa" => Some(Algorithm::EdDsa),
        _ => None,
    }
}

impl IdentityStore {
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = sqlx::PgPool::connect(database_url).await?;
        Ok(Self { pool })
    }

    /// Émet et persiste un nouveau challenge. `ttl_seconds` est une fenêtre courte (cérémonie
    /// WebAuthn interactive, pas un jeton de longue durée) — voir `RP_CHALLENGE_TTL_SECONDS`
    /// dans `main.rs`.
    pub async fn issue_challenge(
        &self,
        challenge: &[u8],
        subject_id: &str,
        ceremony_kind: &str,
        ttl_seconds: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO identity.challenges (challenge, subject_id, ceremony_kind, expires_at) \
             VALUES ($1, $2, $3, now() + make_interval(secs => $4))",
        )
        .bind(challenge)
        .bind(subject_id)
        .bind(ceremony_kind)
        .bind(ttl_seconds as f64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Consomme un challenge — atomique, anti-rejeu. `Ok(None)` couvre absent/expiré/déjà
    /// consommé sans distinction (pas d'oracle pour un attaquant, même contrat que
    /// `zs_webauthn::store::ChallengeStore::consume`). Appelée **avant** toute vérification de
    /// cérémonie, jamais après (un échec de vérification ne doit pas laisser le challenge
    /// rejouable).
    pub async fn consume_challenge(
        &self,
        challenge: &[u8],
        expected_ceremony_kind: &str,
    ) -> Result<Option<ConsumedChallenge>, sqlx::Error> {
        use sqlx::Row;
        let row = sqlx::query(
            "UPDATE identity.challenges SET used_at = now() \
             WHERE challenge = $1 AND ceremony_kind = $2 AND used_at IS NULL AND expires_at > now() \
             RETURNING subject_id",
        )
        .bind(challenge)
        .bind(expected_ceremony_kind)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| ConsumedChallenge {
            subject_id: r.get("subject_id"),
            ceremony_kind: expected_ceremony_kind.to_string(),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_authenticator(
        &self,
        subject_id: &str,
        credential_id: &[u8],
        algorithm: Algorithm,
        public_key: &[u8],
        sign_count: u32,
        aaguid: &[u8],
        attestation_format: &str,
        counter_supported: bool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO identity.authenticators \
             (credential_id, subject_id, suite, algorithm, public_key, sign_count, aaguid, \
              attestation_format, counter_supported) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(credential_id)
        .bind(subject_id)
        .bind(zs_crypto::authenticator_proof::SUITE_V1)
        .bind(algorithm_to_column(algorithm))
        .bind(public_key)
        .bind(sign_count as i64)
        .bind(aaguid)
        .bind(attestation_format)
        .bind(counter_supported)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Résout un authentificateur par son identifiant, révoqué ou non — le filtrage sur la
    /// révocation appartient à l'appelant (même principe que `RegisteredCredential.revoked`,
    /// vérifié explicitement par `verify_authentication_ceremony`, pas caché ici).
    pub async fn find_authenticator(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<AuthenticatorRow>, sqlx::Error> {
        use sqlx::Row;
        let row = sqlx::query(
            "SELECT subject_id, credential_id, algorithm, public_key, sign_count, \
                    counter_supported, (revoked_at IS NOT NULL) AS revoked \
             FROM identity.authenticators WHERE credential_id = $1",
        )
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else { return Ok(None) };
        let algorithm_text: String = row.get("algorithm");
        let Some(algorithm) = algorithm_from_column(&algorithm_text) else {
            // Colonne corrompue ou suite retirée entre-temps — refus par défaut, pas de panique
            // sur une entrée de base de données (règle absolue #2).
            return Ok(None);
        };
        let sign_count: i64 = row.get("sign_count");
        Ok(Some(AuthenticatorRow {
            subject_id: row.get("subject_id"),
            credential_id: row.get("credential_id"),
            algorithm,
            public_key: row.get("public_key"),
            counter_supported: row.get("counter_supported"),
            sign_count: sign_count.max(0) as u32,
            revoked: row.get("revoked"),
        }))
    }

    /// Identifiants de credential non révoqués pour un sujet — construit `allowCredentials`
    /// côté navigateur à l'émission du challenge d'authentification.
    pub async fn credential_ids_for_subject(
        &self,
        subject_id: &str,
    ) -> Result<Vec<Vec<u8>>, sqlx::Error> {
        use sqlx::Row;
        let rows = sqlx::query(
            "SELECT credential_id FROM identity.authenticators \
             WHERE subject_id = $1 AND revoked_at IS NULL",
        )
        .bind(subject_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.get("credential_id")).collect())
    }

    /// Avance le compteur de signature — atomique, détecte un clonage suspecté par construction
    /// (même contrat que `zs_webauthn::store::SignCounterStore::advance`). `Ok(false)` couvre
    /// aussi bien une régression stricte qu'un rejeu exact.
    pub async fn advance_sign_count(
        &self,
        credential_id: &[u8],
        received: u32,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE identity.authenticators SET sign_count = $2 \
             WHERE credential_id = $1 AND sign_count < $2",
        )
        .bind(credential_id)
        .bind(received as i64)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }
}

pub struct AuditStore {
    pool: sqlx::PgPool,
}

/// Tête de chaîne d'un domaine d'autorité — position et empreinte pour dériver le prochain
/// `sequence`/`prev_hash` (mêmes valeurs que `zs_audit::chain::{ChainEntry, hash_sealed_event}`
/// attendent, jamais reconstruites depuis les colonnes décomposées : voir migration 005).
pub struct ChainHead {
    pub next_sequence: u64,
    pub prev_hash: [u8; 32],
}

impl AuditStore {
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = sqlx::PgPool::connect(database_url).await?;
        Ok(Self { pool })
    }

    pub async fn chain_head(&self, authority_domain: &str) -> Result<ChainHead, sqlx::Error> {
        use sqlx::Row;
        let row = sqlx::query(
            "SELECT sequence, sealed_bytes FROM audit.events \
             WHERE authority_domain = $1 ORDER BY sequence DESC LIMIT 1",
        )
        .bind(authority_domain)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            None => ChainHead {
                next_sequence: 0,
                prev_hash: zs_audit::CHAIN_ROOT,
            },
            Some(row) => {
                let sequence: i64 = row.get("sequence");
                let sealed_bytes: Vec<u8> = row.get("sealed_bytes");
                ChainHead {
                    next_sequence: sequence as u64 + 1,
                    prev_hash: zs_audit::hash_sealed_event(&sealed_bytes),
                }
            }
        })
    }

    /// Ajoute un événement déjà scellé à la chaîne. Atomique via la contrainte d'unicité
    /// `(authority_domain, sequence)` (migration 002) — un conflit de concurrence remonte comme
    /// une erreur `sqlx::Error` ordinaire, jamais ré-essayé silencieusement avec une nouvelle
    /// séquence (`zs_audit::sink::AuditChainStore`, mise en garde `referent-crypto`).
    #[allow(clippy::too_many_arguments)]
    pub async fn append(
        &self,
        event_id: &str,
        sequence: u64,
        occurred_at: &str,
        authority_domain: &str,
        event_type: &str,
        actor: serde_json::Value,
        outcome: &str,
        prev_hash_hex: &str,
        signature: serde_json::Value,
        sealed_bytes: &[u8],
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO audit.events \
             (event_id, sequence, occurred_at, authority_domain, event_type, actor, outcome, \
              prev_hash, signature, sealed_bytes) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(event_id)
        .bind(sequence as i64)
        .bind(occurred_at)
        .bind(authority_domain)
        .bind(event_type)
        .bind(actor)
        .bind(outcome)
        .bind(prev_hash_hex)
        .bind(signature)
        .bind(sealed_bytes)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
