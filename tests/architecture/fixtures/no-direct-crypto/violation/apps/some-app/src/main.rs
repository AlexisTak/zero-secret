// Violation : import crypto direct hors zs-crypto.
use p256::ecdsa::SigningKey;

fn main() {
    let _ = SigningKey::random(&mut rand_core::OsRng);
}
