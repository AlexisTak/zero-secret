//! Test d'intégration réel (H3) : démarre le service gRPC `AssertionVerificationService`,
//! l'interroge avec un vrai client `tonic` (pas un double), sur une assertion réellement scellée
//! par un signeur de test déterministe (`p256`, RFC 6979 — légitime uniquement ici, jamais en
//! production où seul `zs-hsm` signe). Le bloc `p256` est confiné dans `mod tests` : c'est
//! l'exemption documentée de `tools/lib/check-no-direct-crypto.sh` (« un test qui simule un
//! acteur externe peut légitimement importer une bibliothèque crypto pour fabriquer une signature
//! de test »).

mod tests {
    use std::collections::BTreeMap;

    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature as P256Signature, SigningKey};
    use serde_json::{Value, json};

    use zs_identity::identity::v1::VerifyAssertionRequest;
    use zs_identity::identity::v1::assertion_verification_service_client::AssertionVerificationServiceClient;

    const DOMAIN_PREFIX: &str = "zero-secret/identity-assertion/v1";
    const AUTHORITY_DOMAIN: &str = "identity-provider";

    struct TestSigner {
        signing_key: SigningKey,
    }

    impl TestSigner {
        fn new() -> Self {
            Self {
                signing_key: SigningKey::from_bytes(&[0x11u8; 32].into()).unwrap(),
            }
        }

        fn public_key_sec1(&self) -> Vec<u8> {
            self.signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec()
        }

        // Même convention que zs_crypto::common::key_id_from_public_key (8 premiers octets hex
        // du SHA-256 de la clé) — reconstruite ici à la main plutôt qu'importée (privée hors
        // zs-crypto), sha2 évité en utilisant directement le Digest interne de p256::ecdsa.
        fn key_id(&self) -> String {
            use sha2::{Digest, Sha256};
            let point = self.signing_key.verifying_key().to_encoded_point(false);
            let digest = Sha256::digest(point.as_bytes());
            hex_encode(&digest[..8])
        }
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// JCS simplifié, robuste au backing de `serde_json::Map` (même précaution que
    /// `zs_crypto::common::canonical_bytes`, ADR-015) : insertion depuis un `BTreeMap` déjà trié.
    fn canonical_bytes(fields: BTreeMap<&str, Value>) -> Vec<u8> {
        let map: serde_json::Map<String, Value> = fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        serde_json::to_vec(&Value::Object(map)).unwrap()
    }

    fn seal_test_assertion(
        signer: &TestSigner,
        subject_id: &str,
        issued_at: &str,
        expires_at: &str,
    ) -> Vec<u8> {
        let mut unsigned = BTreeMap::new();
        unsigned.insert("schema_version", json!(1));
        unsigned.insert("suite", json!("identity-assertion/v1"));
        unsigned.insert("authority_domain", json!(AUTHORITY_DOMAIN));
        unsigned.insert("subject_id", json!(subject_id));
        unsigned.insert("aal", json!("AAL2"));
        unsigned.insert("auth_method", json!("webauthn/device-bound"));
        unsigned.insert("audience", json!("policy-engine"));
        unsigned.insert("issued_at", json!(issued_at));
        unsigned.insert("expires_at", json!(expires_at));
        unsigned.insert(
            "audit_event_id",
            json!("0198e6c1-0000-7000-8000-000000000000"),
        );

        let unsigned_bytes = canonical_bytes(unsigned.clone());

        let mut message = Vec::with_capacity(DOMAIN_PREFIX.len() + 1 + unsigned_bytes.len());
        message.extend_from_slice(DOMAIN_PREFIX.as_bytes());
        message.push(0x00);
        message.extend_from_slice(&unsigned_bytes);

        // p256::ecdsa::Signer::sign hache le message en SHA-256 puis signe le prehash (RFC 6979)
        // — équivalent au sign_prehash(sha256(message)) de production, sans dépendance sha2
        // directe dans ce fichier.
        let signature: P256Signature = signer.signing_key.sign(&message);

        let mut full = unsigned;
        full.insert(
            "signatures",
            json!([{
                "component": "ecdsa-p256",
                "key_id": signer.key_id(),
                "value": hex_encode(&signature.to_bytes()),
            }]),
        );
        canonical_bytes(full)
    }

    async fn spawn_server(addr: std::net::SocketAddr, signer: &TestSigner) {
        let key = zs_crypto::identity_assertion::accept_verifying_key(
            zs_crypto::identity_assertion::SUITE_V1,
            &signer.key_id(),
            &signer.public_key_sec1(),
        )
        .expect("clé de test valide");
        tokio::spawn(async move {
            identity_provider::serve(addr, key)
                .await
                .expect("serveur identity-provider");
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    #[tokio::test]
    async fn assertion_valide_est_verifiee_de_bout_en_bout() {
        let signer = TestSigner::new();
        let addr: std::net::SocketAddr = "127.0.0.1:51701".parse().unwrap();
        spawn_server(addr, &signer).await;

        let assertion = seal_test_assertion(
            &signer,
            "sub-approbateur-1",
            "2020-01-01T00:00:00Z", // loin dans le passé et le futur : indépendant de l'heure
            "2999-01-01T00:00:00Z", // exacte à laquelle le test tourne ("maintenant" réel)
        );

        let mut client = AssertionVerificationServiceClient::connect(format!("http://{addr}"))
            .await
            .expect("connexion");
        let response = client
            .verify_assertion(VerifyAssertionRequest {
                assertion,
                expected_authority_domain: AUTHORITY_DOMAIN.to_string(),
            })
            .await
            .expect("appel gRPC")
            .into_inner();

        assert!(
            response.valid,
            "raison de refus inattendue : {}",
            response.reason
        );
        assert_eq!(response.subject_id, "sub-approbateur-1");
        assert_eq!(response.aal, "AAL2");
        assert!(response.reason.is_empty());
    }

    #[tokio::test]
    async fn signature_alteree_est_refusee() {
        let signer = TestSigner::new();
        let addr: std::net::SocketAddr = "127.0.0.1:51702".parse().unwrap();
        spawn_server(addr, &signer).await;

        let mut assertion = seal_test_assertion(
            &signer,
            "sub-approbateur-2",
            "2026-08-23T10:00:00Z",
            "2999-01-01T00:00:00Z",
        );
        // Corrompt un octet au milieu du document scellé — signature ou champ, peu importe : le
        // résultat attendu est un refus, pas une erreur gRPC.
        let mid = assertion.len() / 2;
        assertion[mid] ^= 0xFF;

        let mut client = AssertionVerificationServiceClient::connect(format!("http://{addr}"))
            .await
            .expect("connexion");
        let response = client
            .verify_assertion(VerifyAssertionRequest {
                assertion,
                expected_authority_domain: AUTHORITY_DOMAIN.to_string(),
            })
            .await
            .expect("l'appel gRPC réussit (le refus est la réponse, pas une erreur de transport)")
            .into_inner();

        assert!(!response.valid);
        assert!(!response.reason.is_empty());
        assert!(response.subject_id.is_empty());
    }

    #[tokio::test]
    async fn assertion_expiree_est_refusee() {
        let signer = TestSigner::new();
        let addr: std::net::SocketAddr = "127.0.0.1:51703".parse().unwrap();
        spawn_server(addr, &signer).await;

        let assertion = seal_test_assertion(
            &signer,
            "sub-approbateur-3",
            "2020-01-01T00:00:00Z",
            "2020-01-01T00:02:00Z", // expirée depuis longtemps par rapport à "maintenant" réel
        );

        let mut client = AssertionVerificationServiceClient::connect(format!("http://{addr}"))
            .await
            .expect("connexion");
        let response = client
            .verify_assertion(VerifyAssertionRequest {
                assertion,
                expected_authority_domain: AUTHORITY_DOMAIN.to_string(),
            })
            .await
            .expect("appel gRPC")
            .into_inner();

        assert!(!response.valid);
        assert_eq!(response.reason, "expiree_ou_pas_encore_valide");
    }

    #[tokio::test]
    async fn domaine_dautorite_inattendu_est_refuse() {
        let signer = TestSigner::new();
        let addr: std::net::SocketAddr = "127.0.0.1:51704".parse().unwrap();
        spawn_server(addr, &signer).await;

        let assertion = seal_test_assertion(
            &signer,
            "sub-approbateur-4",
            "2026-08-23T10:00:00Z",
            "2999-01-01T00:00:00Z",
        );

        let mut client = AssertionVerificationServiceClient::connect(format!("http://{addr}"))
            .await
            .expect("connexion");
        let response = client
            .verify_assertion(VerifyAssertionRequest {
                assertion,
                expected_authority_domain: "un-autre-domaine".to_string(),
            })
            .await
            .expect("appel gRPC")
            .into_inner();

        assert!(!response.valid);
        assert_eq!(response.reason, "domaine_dautorite_inattendu");
    }
}
