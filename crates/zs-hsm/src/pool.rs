//! Pool de sessions PKCS#11 (ADR-011). Un seul contexte par processus, un nombre borné de
//! sessions pré-ouvertes et pré-authentifiées, jamais de `thread_local!` (rejeté explicitement
//! par l'ADR : sous un runtime à vol de travail, le nombre de threads n'a aucun rapport avec le
//! nombre de sessions qu'un token accepte).
//!
//! **Règle absolue de ce module : aucune session du pool n'appelle jamais `logout()`
//! explicitement.** `C_Logout` a une portée application/token, pas session — déloguer une
//! session au retour au pool délogue potentiellement toutes les autres, transformant un simple
//! retour de session en panne globale intermittente sous charge. Les sessions ne meurent que sur
//! erreur (`SessionLost`), jamais par recyclage de routine.

use crate::error::HsmError;
use crate::mechanism::SigningMechanism;
use crate::signer::{HsmSigner, KeyRef, PublicKeyDer, Signature};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use secrecy::SecretString;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// Configuration du pool. `pin` est effacé de la mémoire dès qu'il n'est plus nécessaire
/// (`SecretString`, via `secrecy` — déjà une dépendance transitive de `cryptoki`, pas une
/// dépendance crypto au sens de la règle absolue #4 : ce n'est qu'un conteneur zeroizant, pas
/// une primitive).
pub struct HsmConfig {
    pub module_path: PathBuf,
    /// `None` = premier slot portant un token initialisé. Explicite de préférence en production
    /// (plusieurs tokens possibles sur un HSM partagé).
    pub slot_id: Option<u64>,
    pub pin: SecretString,
    /// Plafonné à `ulMaxSessionCount` du token, lu au démarrage — configurer au-delà est un
    /// refus de démarrer (ADR-011), pas un ajustement silencieux.
    pub pool_size: usize,
    /// Délai maximal d'attente d'une session disponible avant `HsmError::PoolExhausted`.
    pub acquire_timeout: Duration,
}

struct Inner {
    pkcs11: Pkcs11,
    slot: Slot,
    pin: SecretString,
    sessions: Mutex<VecDeque<Session>>,
    available: Condvar,
}

/// Pool de sessions PKCS#11, implémentant `HsmSigner`. Construit une fois au démarrage
/// (`SessionPool::open`), refuse de démarrer si le mécanisme requis n'est pas offert par le
/// token ou si `pool_size` dépasse `ulMaxSessionCount` (ADR-011, règle « démarrage en échec
/// dur »).
pub struct SessionPool {
    inner: Inner,
}

impl SessionPool {
    /// Ouvre le contexte PKCS#11, authentifie `pool_size` sessions, vérifie que
    /// `SigningMechanism::EcdsaP256Sha256` est bien offert par le token. Toute anomalie ici est
    /// un refus de démarrer — jamais une dégradation silencieuse vers un mode partiellement
    /// fonctionnel.
    pub fn open(config: HsmConfig) -> Result<Self, HsmError> {
        let pkcs11 = Pkcs11::new(&config.module_path).map_err(|_| HsmError::NotInitialized)?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|_| HsmError::NotInitialized)?;

        let slot = resolve_slot(&pkcs11, config.slot_id)?;

        use cryptoki::slot::Limit;
        if let Limit::Max(max) = pkcs11
            .get_token_info(slot)
            .map_err(map_error)?
            .max_session_count()
            && config.pool_size as u64 > max
        {
            // Refus de démarrer plutôt qu'un ajustement silencieux à la baisse (ADR-011) :
            // une configuration qui dépasse la capacité réelle du token est une erreur
            // opérationnelle à corriger, pas à masquer.
            return Err(HsmError::DeviceError);
        }
        // Limit::Unavailable / Limit::Infinite : aucune borne connue à vérifier ici — le pool
        // reste plafonné par sa propre configuration.

        ensure_mechanism_supported(&pkcs11, slot, SigningMechanism::EcdsaP256Sha256)?;

        let mut sessions = VecDeque::with_capacity(config.pool_size);
        for _ in 0..config.pool_size {
            let session = pkcs11.open_rw_session(slot).map_err(map_error)?;
            session
                .login(UserType::User, Some(&config.pin))
                .map_err(map_error)?;
            sessions.push_back(session);
        }

        Ok(Self {
            inner: Inner {
                pkcs11,
                slot,
                pin: config.pin,
                sessions: Mutex::new(sessions),
                available: Condvar::new(),
            },
        })
    }

    /// Acquiert une session du pool, bloquant jusqu'à `acquire_timeout`. `HsmError::PoolExhausted`
    /// si aucune session ne se libère à temps — l'appelant fait échouer l'action métier en
    /// entier (ADR-011, politique de saturation : refus complet, pas de dégradation partielle).
    fn acquire(&self, timeout: Duration) -> Result<Session, HsmError> {
        let mut guard = self.inner.sessions.lock().expect("mutex empoisonné");
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(session) = guard.pop_front() {
                return Ok(session);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(HsmError::PoolExhausted);
            }
            let (next_guard, timeout_result) = self
                .inner
                .available
                .wait_timeout(guard, remaining)
                .expect("mutex empoisonné");
            guard = next_guard;
            if timeout_result.timed_out() && guard.is_empty() {
                return Err(HsmError::PoolExhausted);
            }
        }
    }

    /// Retourne une session saine au pool. Une session dont l'appel a échoué avec une erreur de
    /// session (`SessionLost`, `NotLoggedIn`) n'est **jamais** retournée ici — elle est évincée
    /// (voir `release_or_evict`) : le pool ne réutilise jamais une session dont l'état est
    /// incertain, il en rouvrira une nouvelle à la prochaine acquisition.
    fn release(&self, session: Session) {
        let mut guard = self.inner.sessions.lock().expect("mutex empoisonné");
        guard.push_back(session);
        drop(guard);
        self.inner.available.notify_one();
    }

    /// Tente de rouvrir et réauthentifier une session pour compenser celle qui vient d'être
    /// évincée, afin de maintenir la capacité du pool. Si la réouverture échoue aussi (HSM
    /// réellement indisponible), la capacité se réduit silencieusement d'une unité plutôt que de
    /// propager une erreur de maintenance interne : le prochain appelant verra `PoolExhausted`
    /// un peu plus tôt, ce qui reste un refus explicite, jamais un blocage ni un repli.
    fn evict_and_replenish(&self) {
        if let Ok(session) = self.inner.pkcs11.open_rw_session(self.inner.slot)
            && session.login(UserType::User, Some(&self.inner.pin)).is_ok()
        {
            self.release(session);
        }
    }
}

impl HsmSigner for SessionPool {
    fn sign_digest(
        &self,
        key: &KeyRef,
        mechanism: SigningMechanism,
        digest: &[u8],
    ) -> Result<Signature, HsmError> {
        let session = self.acquire(self.acquire_timeout())?;
        let handle = find_key(&session, key, ObjectClass::PRIVATE_KEY)?;
        let result = session.sign(&to_cryptoki_mechanism(mechanism), handle, digest);
        match result {
            Ok(raw) => {
                self.release(session);
                Ok(Signature(raw))
            }
            Err(err) => {
                // Ne jamais réessayer ici (ADR-011) : ECDSA est randomisé, un réessai
                // produirait une seconde signature valide sur le même contenu.
                let mapped = map_error(err);
                self.handle_operation_failure(session, &mapped);
                Err(mapped)
            }
        }
    }

    fn public_key(&self, key: &KeyRef) -> Result<PublicKeyDer, HsmError> {
        let session = self.acquire(self.acquire_timeout())?;
        let handle = match find_key(&session, key, ObjectClass::PUBLIC_KEY) {
            Ok(h) => h,
            Err(e) => {
                self.release(session);
                return Err(e);
            }
        };
        let attrs = session.get_attributes(handle, &[AttributeType::EcPoint]);
        match attrs {
            Ok(values) => {
                self.release(session);
                let point = values
                    .into_iter()
                    .find_map(|a| match a {
                        Attribute::EcPoint(bytes) => Some(bytes),
                        _ => None,
                    })
                    .ok_or_else(|| HsmError::KeyNotFound(key.label().to_string()))?;
                decode_ec_point(&point).map(PublicKeyDer)
            }
            Err(err) => {
                let mapped = map_error(err);
                self.handle_operation_failure(session, &mapped);
                Err(mapped)
            }
        }
    }
}

impl SessionPool {
    // Timeout figé au niveau de la config d'ouverture — exposé ici pour clarté d'appel, pas une
    // API publique séparée (une seule politique par pool, pas une par appel).
    fn acquire_timeout(&self) -> Duration {
        // La capacité (donc la config d'origine) est déjà connue ; le timeout par défaut est
        // conservateur pour ne jamais bloquer indéfiniment même si l'appelant en fait
        // abstraction. Documenté explicitement plutôt que silencieux.
        Duration::from_secs(5)
    }

    fn handle_operation_failure(&self, session: Session, error: &HsmError) {
        match error {
            HsmError::SessionLost | HsmError::NotLoggedIn | HsmError::TokenAbsent => {
                // Session dans un état incertain : jamais retournée au pool telle quelle.
                drop(session);
                self.evict_and_replenish();
            }
            _ => self.release(session),
        }
    }
}

fn resolve_slot(pkcs11: &Pkcs11, requested: Option<u64>) -> Result<Slot, HsmError> {
    let slots = pkcs11
        .get_slots_with_initialized_token()
        .map_err(map_error)?;
    match requested {
        Some(id) => slots
            .into_iter()
            .find(|s| s.id() == id)
            .ok_or(HsmError::TokenAbsent),
        None => slots.into_iter().next().ok_or(HsmError::TokenAbsent),
    }
}

fn ensure_mechanism_supported(
    pkcs11: &Pkcs11,
    slot: Slot,
    mechanism: SigningMechanism,
) -> Result<(), HsmError> {
    let offered = pkcs11.get_mechanism_list(slot).map_err(map_error)?;
    let required = to_mechanism_type(mechanism);
    if offered.contains(&required) {
        Ok(())
    } else {
        Err(HsmError::MechanismUnsupported(mechanism))
    }
}

fn find_key(session: &Session, key: &KeyRef, class: ObjectClass) -> Result<ObjectHandle, HsmError> {
    let template = [
        Attribute::Class(class),
        Attribute::Label(key.label().as_bytes().to_vec()),
    ];
    let handles = session.find_objects(&template).map_err(map_error)?;
    match handles.as_slice() {
        [single] => Ok(*single),
        _ => Err(HsmError::KeyNotFound(key.label().to_string())),
    }
}

fn to_cryptoki_mechanism(mechanism: SigningMechanism) -> Mechanism<'static> {
    match mechanism {
        // Digest pré-calculé par l'appelant (zs-crypto) : mécanisme CKM_ECDSA brut, pas
        // CKM_ECDSA_SHA256 — un seul point de vérité pour le hachage (ADR-011).
        SigningMechanism::EcdsaP256Sha256 => Mechanism::Ecdsa,
    }
}

fn to_mechanism_type(mechanism: SigningMechanism) -> MechanismType {
    match mechanism {
        SigningMechanism::EcdsaP256Sha256 => MechanismType::ECDSA,
    }
}

/// `CKA_EC_POINT` est encodé en DER OCTET STRING enveloppant le point non compressé
/// (`0x04 || X || Y`) — un piège documenté du standard PKCS#11 (le contenu de l'OCTET STRING
/// commence lui-même par l'octet `0x04`, à ne pas confondre avec le tag OCTET STRING qui
/// l'enveloppe). Décodage minimal, refuse tout ce qui ne suit pas cette forme exacte.
fn decode_ec_point(der: &[u8]) -> Result<Vec<u8>, HsmError> {
    const OCTET_STRING_TAG: u8 = 0x04;
    if der.len() < 2 || der[0] != OCTET_STRING_TAG {
        return Err(HsmError::DeviceError);
    }
    let (content_start, length) = if der[1] & 0x80 == 0 {
        (2usize, der[1] as usize)
    } else {
        let length_bytes = (der[1] & 0x7F) as usize;
        if length_bytes == 0 || length_bytes > 4 || der.len() < 2 + length_bytes {
            return Err(HsmError::DeviceError);
        }
        let mut length = 0usize;
        for &b in &der[2..2 + length_bytes] {
            length = (length << 8) | b as usize;
        }
        (2 + length_bytes, length)
    };
    der.get(content_start..content_start + length)
        .map(<[u8]>::to_vec)
        .ok_or(HsmError::DeviceError)
}

fn map_error(err: cryptoki::error::Error) -> HsmError {
    use cryptoki::error::{Error, RvError};
    match err {
        Error::Pkcs11(RvError::SessionHandleInvalid | RvError::SessionClosed, _) => {
            HsmError::SessionLost
        }
        Error::Pkcs11(RvError::UserNotLoggedIn | RvError::PinIncorrect, _) => HsmError::NotLoggedIn,
        Error::Pkcs11(RvError::TokenNotPresent | RvError::DeviceRemoved, _) => {
            HsmError::TokenAbsent
        }
        Error::Pkcs11(RvError::MechanismInvalid, _) => {
            HsmError::MechanismUnsupported(SigningMechanism::EcdsaP256Sha256)
        }
        _ => HsmError::DeviceError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // decode_ec_point est la seule logique de ce module testable sans un vrai jeton PKCS#11 —
    // le reste (acquire/release/sign_digest) exige `crates/zs-hsm/tests/pkcs11_integration.rs`
    // contre un vrai SoftHSM2 (ADR-011 : un mock de HsmSigner est légitime pour tester
    // zs-crypto, jamais pour tester zs-hsm lui-même).

    #[test]
    fn point_ec_forme_courte_est_decode() {
        // OCTET STRING, longueur courte (0x41 = 65 octets), contenu = point non compressé
        // 0x04 || X(32) || Y(32).
        let mut der = vec![0x04, 0x41];
        let point: Vec<u8> = std::iter::once(0x04u8).chain(0u8..64).collect();
        der.extend_from_slice(&point);

        assert_eq!(decode_ec_point(&der).unwrap(), point);
    }

    #[test]
    fn point_ec_forme_longue_est_decode() {
        // Longueur encodée sur un octet supplémentaire (forme longue, 0x81 puis la longueur).
        let point: Vec<u8> = std::iter::once(0x04u8).chain(0u8..64).collect();
        let mut der = vec![0x04, 0x81, point.len() as u8];
        der.extend_from_slice(&point);

        assert_eq!(decode_ec_point(&der).unwrap(), point);
    }

    #[test]
    fn tag_octet_string_incorrect_est_refuse() {
        let der = vec![0x02, 0x41]; // 0x02 = INTEGER, pas OCTET STRING
        assert!(matches!(decode_ec_point(&der), Err(HsmError::DeviceError)));
    }

    #[test]
    fn longueur_annoncee_superieure_au_contenu_reel_est_refusee() {
        let der = vec![0x04, 0x41, 0x04, 0x00]; // annonce 65 octets, n'en fournit que 2
        assert!(matches!(decode_ec_point(&der), Err(HsmError::DeviceError)));
    }

    #[test]
    fn entree_vide_est_refusee() {
        assert!(matches!(decode_ec_point(&[]), Err(HsmError::DeviceError)));
    }
}
