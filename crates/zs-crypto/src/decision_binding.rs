//! `decision-binding/v1` — empreintes d'intégrité liant une décision du PDP (`policy-engine`,
//! L2.2) à la requête évaluée et au corpus de politiques évalué, pour un rejeu hors ligne
//! bit-exact (`DecisionResponse.decision_hash`/`policy_version`, `decision.proto`).
//!
//! Ce n'est PAS une suite de signature : aucune clé, pas d'émetteur/vérificateur, pas
//! d'hybridation PQC applicable (SHA-256 seul reste adéquat pour une empreinte d'intégrité — les
//! cibles post-quantiques de `zs-crypto/CLAUDE.md` concernent la signature/l'échange de clé, pas
//! le hachage de contenu). Deux fonctions distinctes, jamais un hash générique exporté : une
//! seule fonction `sha256(bytes)` publique inviterait chaque appelant à improviser sa propre
//! canonicalisation, exactement le risque de divergence que `common::canonical_bytes` existe pour
//! éviter (ADR-012/013).
//!
//! Consultation `referent-crypto` (ADR-015) : ce calcul doit passer par `zs-crypto` et non par un
//! hash « maison » dans `zs-policy`, pour les mêmes raisons que le double-hachage `aws-lc-rs`
//! découvert en L1.2c — deux canonicalisations indépendantes d'un même contenu divergent
//! silencieusement.

use crate::common;

pub const SUITE_V1: &str = "decision-binding/v1";

/// Empreinte opaque, préfixée de la suite dans sa représentation textuelle
/// (`decision-binding/v1:<hex>`) — jamais un `[u8; 32]` nu exposé, pour qu'un futur `v2` change de
/// représentation sans casser silencieusement un appelant qui aurait comparé des octets bruts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionBinding {
    suite: &'static str,
    digest: [u8; 32],
}

impl DecisionBinding {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Forme stockée dans `decision_hash`/`policy_version` (`decision.proto`, deux champs
    /// `string`) — hexadécimal minuscule, cohérent avec `identity_assertion`/`audit_seal`.
    pub fn to_hex_string(&self) -> String {
        format!("{}:{}", self.suite, common::hex_encode(&self.digest))
    }
}

/// Empreinte d'une requête de décision : `sha256(domain || 0x00 || jcs(request))`.
///
/// `request` est un `serde_json::Value` déjà construit par l'appelant (typiquement une
/// sérialisation JSON du `DecisionRequest` protobuf) — ce module ne connaît pas le type
/// `policy.v1::DecisionRequest`, qui vit dans `zs-policy` (règle absolue #7 : `zs-crypto` ne
/// dépend d'aucun crate applicatif).
pub fn bind_request(request: &serde_json::Value) -> DecisionBinding {
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(format!("{SUITE_V1}/request\0").as_bytes());
    message.extend_from_slice(&common::canonical_bytes(request));
    DecisionBinding {
        suite: SUITE_V1,
        digest: common::sha256(&message),
    }
}

/// Un fichier du corpus de politiques, tel que lu par l'appelant. `relative_path` est le chemin
/// relatif à la racine du corpus (ex. `access/db_connect.cedar`), toujours en séparateurs `/`
/// (jamais `\`, pour rester reproductible entre systèmes de fichiers) ; `contents` est le texte
/// du fichier, déjà validé UTF-8 sans BOM par l'appelant (`bind_policy_corpus` refuse sinon).
pub struct CorpusFile<'a> {
    pub relative_path: &'a str,
    pub contents: &'a str,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CorpusBindingError {
    #[error("fichier de corpus non-UTF-8 ou porteur d'un BOM : '{0}'")]
    InvalidEncoding(String),
    #[error("chemin de corpus non normalisé (contient '\\\\' ou n'est pas relatif) : '{0}'")]
    InvalidPath(String),
}

/// Empreinte du corpus de politiques évalué : schéma Cedar + tous les fichiers `.cedar`, triés
/// par chemin relatif **octet par octet** (`sort_unstable`, comparaison `&str` — jamais une
/// locale), hachés individuellement puis combinés en arbre trié plutôt qu'une concaténation
/// naïve (une concaténation directe rendrait `["ab", "c"]` et `["a", "bc"]` indistinguables — un
/// renommage de fichier pourrait produire la même empreinte qu'un déplacement de contenu entre
/// deux fichiers). Inclut la version du crate `cedar-policy` : une mise à jour du moteur change la
/// sémantique d'évaluation à corpus textuellement identique, donc doit changer l'empreinte.
pub fn bind_policy_corpus(
    schema: &str,
    cedar_engine_version: &str,
    files: &[CorpusFile<'_>],
) -> Result<DecisionBinding, CorpusBindingError> {
    for f in files {
        if f.relative_path.contains('\\') || f.relative_path.starts_with('/') {
            return Err(CorpusBindingError::InvalidPath(f.relative_path.to_string()));
        }
        if f.contents.starts_with('\u{FEFF}') {
            return Err(CorpusBindingError::InvalidEncoding(
                f.relative_path.to_string(),
            ));
        }
    }

    let mut sorted: Vec<&CorpusFile<'_>> = files.iter().collect();
    sorted.sort_unstable_by(|a, b| a.relative_path.as_bytes().cmp(b.relative_path.as_bytes()));

    let mut message = Vec::new();
    message.extend_from_slice(format!("{SUITE_V1}/policy-corpus\0").as_bytes());
    message.extend_from_slice(format!("cedar-policy={cedar_engine_version}\0").as_bytes());

    // Schéma : longueur préfixée (pas de séparateur ambigu).
    message.extend_from_slice(&(schema.len() as u64).to_be_bytes());
    message.extend_from_slice(schema.as_bytes());

    message.extend_from_slice(&(sorted.len() as u64).to_be_bytes());
    for f in &sorted {
        message.extend_from_slice(&(f.relative_path.len() as u64).to_be_bytes());
        message.extend_from_slice(f.relative_path.as_bytes());
        message.extend_from_slice(&(f.contents.len() as u64).to_be_bytes());
        message.extend_from_slice(f.contents.as_bytes());
    }

    Ok(DecisionBinding {
        suite: SUITE_V1,
        digest: common::sha256(&message),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empreinte_de_requete_est_deterministe() {
        let r = json!({"request_id": "abc", "action": "db.connect"});
        assert_eq!(bind_request(&r), bind_request(&r));
    }

    #[test]
    fn empreinte_de_requete_change_avec_le_contenu() {
        let a = json!({"request_id": "abc"});
        let b = json!({"request_id": "abd"});
        assert_ne!(bind_request(&a), bind_request(&b));
    }

    #[test]
    fn representation_textuelle_prefixee_de_la_suite() {
        let r = json!({"x": 1});
        let hex = bind_request(&r).to_hex_string();
        assert!(hex.starts_with("decision-binding/v1:"));
        assert_eq!(hex.len(), "decision-binding/v1:".len() + 64);
    }

    #[test]
    fn empreinte_de_corpus_est_deterministe() {
        let files = [CorpusFile {
            relative_path: "access/db_connect.cedar",
            contents: "permit(...);",
        }];
        let a = bind_policy_corpus("{}", "4.12.0", &files).unwrap();
        let b = bind_policy_corpus("{}", "4.12.0", &files).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn empreinte_de_corpus_independante_de_lordre_dentree() {
        let f1 = CorpusFile {
            relative_path: "a.cedar",
            contents: "1",
        };
        let f2 = CorpusFile {
            relative_path: "b.cedar",
            contents: "2",
        };
        let dans_lordre = bind_policy_corpus("{}", "4.12.0", &[f1, f2]).unwrap();

        let f1b = CorpusFile {
            relative_path: "a.cedar",
            contents: "1",
        };
        let f2b = CorpusFile {
            relative_path: "b.cedar",
            contents: "2",
        };
        let inverse = bind_policy_corpus("{}", "4.12.0", &[f2b, f1b]).unwrap();

        assert_eq!(dans_lordre, inverse);
    }

    #[test]
    fn empreinte_de_corpus_distingue_deplacement_de_contenu_entre_fichiers() {
        // ["ab", "c"] concaténé naïvement égalerait ["a", "bc"] : la longueur préfixée doit
        // empêcher cette collision de frontière.
        let a = [
            CorpusFile {
                relative_path: "x.cedar",
                contents: "ab",
            },
            CorpusFile {
                relative_path: "y.cedar",
                contents: "c",
            },
        ];
        let b = [
            CorpusFile {
                relative_path: "x.cedar",
                contents: "a",
            },
            CorpusFile {
                relative_path: "y.cedar",
                contents: "bc",
            },
        ];
        assert_ne!(
            bind_policy_corpus("{}", "4.12.0", &a).unwrap(),
            bind_policy_corpus("{}", "4.12.0", &b).unwrap()
        );
    }

    #[test]
    fn empreinte_de_corpus_change_avec_la_version_du_moteur_cedar() {
        let files = [CorpusFile {
            relative_path: "a.cedar",
            contents: "1",
        }];
        let v1 = bind_policy_corpus("{}", "4.12.0", &files).unwrap();
        let v2 = bind_policy_corpus("{}", "4.13.0", &files).unwrap();
        assert_ne!(v1, v2);
    }

    #[test]
    fn empreinte_de_corpus_change_avec_le_schema() {
        let files = [CorpusFile {
            relative_path: "a.cedar",
            contents: "1",
        }];
        let a = bind_policy_corpus("{\"x\":1}", "4.12.0", &files).unwrap();
        let b = bind_policy_corpus("{\"x\":2}", "4.12.0", &files).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn fichier_avec_bom_est_refuse() {
        let files = [CorpusFile {
            relative_path: "a.cedar",
            contents: "\u{FEFF}permit(...)",
        }];
        assert_eq!(
            bind_policy_corpus("{}", "4.12.0", &files),
            Err(CorpusBindingError::InvalidEncoding("a.cedar".to_string()))
        );
    }

    #[test]
    fn chemin_non_normalise_est_refuse() {
        let files = [CorpusFile {
            relative_path: "access\\db_connect.cedar",
            contents: "x",
        }];
        assert_eq!(
            bind_policy_corpus("{}", "4.12.0", &files),
            Err(CorpusBindingError::InvalidPath(
                "access\\db_connect.cedar".to_string()
            ))
        );
    }
}
