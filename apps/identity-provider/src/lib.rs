//! `identity-provider` — deux entrées réseau. gRPC (ce fichier) : vérification d'assertion
//! `identity-assertion/v1` (`contracts/proto/identity/v1/assertion_verification.proto`, H3,
//! ADR-016) — frontière Rust/Go, jamais FFI (ADR-001), seule façon dont `access-broker` (L2.3,
//! Go) fait vérifier une assertion sans importer de bibliothèque crypto directement. HTTP
//! (`httpapi`, H5, ADR-023) : émission de challenge et vérification de cérémonie WebAuthn — la
//! seule voie d'**émission** réelle d'assertion et d'événement d'audit de ce composant.
//!
//! gRPC en clair (pas de TLS) — jamais un déploiement de production sans mTLS. Prérequis distinct
//! (SPIFFE/SPIRE, ADR-001), non traité ici, signalé explicitement.

pub mod httpapi;
pub mod store;

use tonic::{Request, Response, Status, transport::Server};

use zs_crypto::identity_assertion::{self, AcceptancePolicy, AcceptedVerifyingKey, VerifyError};
use zs_identity::identity::v1::assertion_verification_service_server::{
    AssertionVerificationService, AssertionVerificationServiceServer,
};
use zs_identity::identity::v1::{VerifyAssertionRequest, VerifyAssertionResponse};

const ACCEPTED_SUITES: &[&str] = &[identity_assertion::SUITE_V1];

pub struct AssertionVerifier {
    key: AcceptedVerifyingKey,
}

impl AssertionVerifier {
    pub fn new(key: AcceptedVerifyingKey) -> Self {
        Self { key }
    }
}

#[tonic::async_trait]
impl AssertionVerificationService for AssertionVerifier {
    async fn verify_assertion(
        &self,
        request: Request<VerifyAssertionRequest>,
    ) -> Result<Response<VerifyAssertionResponse>, Status> {
        let req = request.into_inner();

        // La fraîcheur d'une assertion (expires_at) dépend nécessairement de « maintenant » au
        // moment de la vérification — à la différence du PDP (L2.2), qui reçoit tout le contexte
        // en entrée. Une vérification en ligne n'a pas cette contrainte : elle EST l'appel réseau.
        let now = rfc3339_now();
        let policy = AcceptancePolicy {
            accepted_suites: ACCEPTED_SUITES,
            now: identity_assertion::Timestamp::new(now)
                .expect("rfc3339_now produit toujours un format valide pour Timestamp::new"),
            expected_authority_domain: req.expected_authority_domain,
        };

        let response = match identity_assertion::verify(
            std::slice::from_ref(&self.key),
            &req.assertion,
            &policy,
        ) {
            Ok(verified) => VerifyAssertionResponse {
                valid: true,
                reason: String::new(),
                subject_id: verified.subject_id().to_string(),
                aal: verified.aal().to_string(),
                auth_method: verified.auth_method().to_string(),
                audit_event_id: verified.audit_event_id().to_string(),
            },
            Err(e) => VerifyAssertionResponse {
                valid: false,
                reason: verify_error_reason(&e).to_string(),
                subject_id: String::new(),
                aal: String::new(),
                auth_method: String::new(),
                audit_event_id: String::new(),
            },
        };

        Ok(Response::new(response))
    }
}

/// Catégorie de refus, jamais un détail exploitable pour affiner une attaque (même liste que
/// `zs_crypto::identity_assertion::VerifyError`, traduite en chaîne stable pour le contrat gRPC).
fn verify_error_reason(e: &VerifyError) -> &'static str {
    match e {
        VerifyError::UnknownSuite => "suite_inconnue",
        VerifyError::MalformedKey => "cle_malformee",
        VerifyError::TooLarge => "taille_excessive",
        VerifyError::MalformedDocument => "document_malforme",
        VerifyError::NonCanonical => "non_canonique",
        VerifyError::InvalidSignatureArity => "arite_signature_incorrecte",
        VerifyError::UnknownKeyId => "identifiant_de_cle_inconnu",
        VerifyError::InvalidSignature => "signature_invalide",
        VerifyError::UnexpectedAuthorityDomain => "domaine_dautorite_inattendu",
        VerifyError::NotYetValidOrExpired => "expiree_ou_pas_encore_valide",
    }
}

pub async fn serve(
    addr: std::net::SocketAddr,
    key: AcceptedVerifyingKey,
) -> Result<(), tonic::transport::Error> {
    let service = AssertionVerifier::new(key);
    Server::builder()
        .add_service(AssertionVerificationServiceServer::new(service))
        .serve(addr)
        .await
}

/// Horodatage RFC 3339 UTC strict (`AAAA-MM-JJThh:mm:ssZ`, format exigé par
/// `zs_crypto::common::Timestamp::new`) de l'instant courant. Calcul manuel (algorithme
/// civil_from_days, Howard Hinnant — http://howardhinnant.github.io/date_algorithms.html) plutôt
/// qu'une dépendance de calendrier (`chrono`/`time`) : le format est fixe et étroit (pas de calcul
/// calendaire général requis), une nouvelle dépendance n'était pas justifiée pour ça seul (règle
/// absolue #10).
pub(crate) fn rfc3339_now() -> String {
    format_rfc3339(unix_now_seconds())
}

/// `(maintenant, maintenant + ttl_seconds)`, formatés RFC 3339 — évite de reformater puis
/// reparser une chaîne pour calculer une expiration (H5, `httpapi::authentication_verify`) :
/// l'arithmétique reste en secondes Unix, seul le format de sortie change.
pub(crate) fn rfc3339_now_and_after(ttl_seconds: i64) -> (String, String) {
    let now = unix_now_seconds();
    (format_rfc3339(now), format_rfc3339(now + ttl_seconds))
}

fn unix_now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("horloge système antérieure à 1970")
        .as_secs() as i64
}

fn format_rfc3339(total_seconds: i64) -> String {
    let days = total_seconds.div_euclid(86_400);
    let seconds_of_day = total_seconds.rem_euclid(86_400);

    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3600;
    let minute = (seconds_of_day % 3600) / 60;
    let second = seconds_of_day % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_epoch_est_1970_01_01() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn civil_from_days_est_correct_sur_une_date_connue() {
        // 2026-08-23 = 20688 jours depuis 1970-01-01 (vérifié indépendamment).
        assert_eq!(civil_from_days(20_688), (2026, 8, 23));
    }

    #[test]
    fn rfc3339_now_respecte_le_format_attendu_par_timestamp() {
        let s = rfc3339_now();
        assert!(identity_assertion::Timestamp::new(s).is_ok());
    }
}
