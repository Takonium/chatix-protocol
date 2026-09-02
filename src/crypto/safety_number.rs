/// Safety numbers — human-verifiable fingerprints for E2E identity keys.
///
/// Nothing else in this crate lets two users confirm out-of-band that they
/// actually have each other's real `E2ePublicKey`, rather than one a
/// malicious or compromised server substituted during the first contact
/// between them. This module gives each client a deterministic way to turn
/// a pair of identities into the same short numeric code, which the two
/// users can then compare through a channel the server doesn't control
/// (in person, a phone call, a QR scan, etc.) — if it matches, both sides
/// hold the same keys.
///
/// The algorithm follows numeric-fingerprint design
/// (iterated hash of identifier + public key, truncated to a 60-digit
/// decimal code), adapted to use SHA-256 instead of SHA-512 since SHA-256
/// is already this crate's only hash dependency and 256 bits is far more
/// than the 30-digit truncated output below can ever expose anyway.
///
/// Rendering the resulting string as a QR code, or any other presentation
/// concern, is left to the client application — this module only produces
/// the deterministic bytes/digits to compare.
use sha2::{Digest, Sha256};

use crate::crypto::e2e::E2ePublicKey;
use crate::error::ProtocolError;

/// Number of extra hash rounds applied on top of the initial digest.
///
/// Its purpose is to slow down brute-force search over the truncated 30-digit
/// display form (an attacker trying to find a second keypair whose fingerprint
/// collides with a target's) — it does not add meaningful protection against
/// finding a preimage of the full 32-byte digest, which is already
/// infeasible, so this is about fidelity to a well-audited design more than
/// closing a gap this crate would otherwise have.
const FINGERPRINT_ITERATIONS: usize = 5200;

/// Length of one party's fingerprint digest, in bytes.
const FINGERPRINT_LEN: usize = 32;

/// How many of the 32 fingerprint bytes get turned into decimal digits.
/// 30 bytes split into 6 five-byte chunks gives 6 five-digit groups (30
/// digits) per party; the remaining 2 bytes are discarded, matching
const DIGIT_SOURCE_LEN: usize = 30;

/// Computes one party's iterated fingerprint from their stable identifier
/// (e.g. username) and their full E2E public key bundle.
///
/// All three parts of `public_key` are hashed in, not just one — a
/// malicious server substituting the X25519 or ML-KEM key would let it
/// read messages meant for someone else, while substituting the ML-DSA key
/// would let it forge messages as that person, so a fingerprint that only
/// covered one field would miss the other attack.
pub fn compute_fingerprint(identifier: &str, public_key: &E2ePublicKey) -> [u8; FINGERPRINT_LEN] {
    let key_bytes = serialize_public_key(public_key);

    let mut digest: [u8; FINGERPRINT_LEN] = {
        let mut hasher = Sha256::new();
        hasher.update(identifier.as_bytes());
        hasher.update(&key_bytes);
        hasher.finalize().into()
    };

    // Re-hash the running digest together with the same identifier/key
    // suffix each round, so every round's output still depends on the
    // original inputs rather than drifting into a pure hash-chain that a
    // fixed starting digest alone would determine.
    for _ in 0..FINGERPRINT_ITERATIONS {
        let mut hasher = Sha256::new();
        hasher.update(digest);
        hasher.update(identifier.as_bytes());
        hasher.update(&key_bytes);
        digest = hasher.finalize().into();
    }

    digest
}

/// Computes the combined, human-comparable safety number for a
/// conversation between two identities.
///
/// The two fingerprints are ordered by identifier (not by who's "local")
/// before being combined, so `safety_number(alice, bob) ==
/// safety_number(bob, alice)` — both users compute and see the exact same
/// string, which is what makes comparing it out-of-band meaningful.
///
/// Returns 60 decimal digits grouped in 12 blocks of 5, space-separated.
pub fn safety_number(
    local_id: &str,
    local_key: &E2ePublicKey,
    remote_id: &str,
    remote_key: &E2ePublicKey,
) -> String {
    let local_fingerprint = compute_fingerprint(local_id, local_key);
    let remote_fingerprint = compute_fingerprint(remote_id, remote_key);

    let (first, second) = if local_id <= remote_id {
        (local_fingerprint, remote_fingerprint)
    } else {
        (remote_fingerprint, local_fingerprint)
    };

    let mut groups = digit_groups(&first);
    groups.extend(digit_groups(&second));
    groups.join(" ")
}

/// Compares a freshly-fetched `E2ePublicKey` against the one previously
/// pinned for the same identity. Returns an error if they differ.
///
/// This does not defend against a malicious server substituting a key on
/// *first* contact — that is what `safety_number` and its out-of-band
/// comparison exist for. It defends against a substitution happening
/// *after* the client has already pinned a key: silently accepting a
/// changed key here would let a compromised server perform a
/// mid-conversation key-substitution attack without either user noticing.
pub fn verify_key_unchanged(
    identifier: &str,
    pinned: &E2ePublicKey,
    fetched: &E2ePublicKey,
) -> Result<(), ProtocolError> {
    if pinned == fetched {
        Ok(())
    } else {
        Err(ProtocolError::IdentityKeyChanged {
            identifier: identifier.to_string(),
        })
    }
}

/// Concatenates an identity's public key fields into a fixed-size byte
/// string suitable for hashing. Every field has a fixed length, so simple
/// concatenation is unambiguous — no length prefixes are needed.
fn serialize_public_key(public_key: &E2ePublicKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        public_key.x25519_public.len()
            + public_key.ml_kem_ek.len()
            + public_key.dsa_verifying_key.len(),
    );
    out.extend_from_slice(&public_key.x25519_public);
    out.extend_from_slice(&public_key.ml_kem_ek);
    out.extend_from_slice(&public_key.dsa_verifying_key);
    out
}

/// Splits a fingerprint into six 5-digit decimal groups:
/// the first 30 bytes in 5-byte chunks, each chunk read as a big-endian
/// 40-bit integer and reduced mod 100000.
fn digit_groups(fingerprint: &[u8; FINGERPRINT_LEN]) -> Vec<String> {
    fingerprint[..DIGIT_SOURCE_LEN]
        .chunks(5)
        .map(|chunk| {
            // Place the 5 chunk bytes as the low 5 bytes of a big-endian
            // u64 so from_be_bytes can parse them as one integer.
            let mut buf = [0u8; 8];
            buf[3..].copy_from_slice(chunk);
            let value = u64::from_be_bytes(buf) % 100_000;
            format!("{value:05}")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::e2e::generate_e2e_keypair;

    #[test]
    fn safety_number_is_symmetric() {
        let (_alice_sk, alice_pk) = generate_e2e_keypair().unwrap();
        let (_bob_sk, bob_pk) = generate_e2e_keypair().unwrap();

        let from_alice = safety_number("alice", &alice_pk, "bob", &bob_pk);
        let from_bob = safety_number("bob", &bob_pk, "alice", &alice_pk);

        assert_eq!(from_alice, from_bob);
    }

    #[test]
    fn safety_number_changes_if_a_public_key_is_swapped() {
        // This is the actual property the feature exists to guarantee: if
        // a server substitutes either party's key, the safety number the
        // two users compare out-of-band must no longer match.
        let (_alice_sk, alice_pk) = generate_e2e_keypair().unwrap();
        let (_bob_sk, bob_pk) = generate_e2e_keypair().unwrap();
        let (_, imposter_pk) = generate_e2e_keypair().unwrap();

        let genuine = safety_number("alice", &alice_pk, "bob", &bob_pk);
        let tampered = safety_number("alice", &alice_pk, "bob", &imposter_pk);

        assert_ne!(genuine, tampered);
    }

    #[test]
    fn safety_number_changes_if_an_identifier_changes() {
        let (_alice_sk, alice_pk) = generate_e2e_keypair().unwrap();
        let (_bob_sk, bob_pk) = generate_e2e_keypair().unwrap();

        let original = safety_number("alice", &alice_pk, "bob", &bob_pk);
        let renamed = safety_number("alice2", &alice_pk, "bob", &bob_pk);

        assert_ne!(original, renamed);
    }

    #[test]
    fn safety_number_has_expected_shape() {
        let (_alice_sk, alice_pk) = generate_e2e_keypair().unwrap();
        let (_bob_sk, bob_pk) = generate_e2e_keypair().unwrap();

        let number = safety_number("alice", &alice_pk, "bob", &bob_pk);

        // 12 groups of 5 digits, space-separated: 60 digits + 11 spaces.
        assert_eq!(number.len(), 71);
        assert!(number.chars().all(|c| c.is_ascii_digit() || c == ' '));
        assert_eq!(number.split(' ').count(), 12);
    }

    #[test]
    fn verify_key_unchanged_accepts_the_same_key() {
        let (_alice_sk, alice_pk) = generate_e2e_keypair().unwrap();

        assert!(verify_key_unchanged("alice", &alice_pk, &alice_pk).is_ok());
    }

    #[test]
    fn verify_key_unchanged_rejects_an_imposter_key() {
        let (_alice_sk, alice_pk) = generate_e2e_keypair().unwrap();
        let (_, imposter_pk) = generate_e2e_keypair().unwrap();

        assert!(verify_key_unchanged("alice", &alice_pk, &imposter_pk).is_err());
    }

    #[test]
    fn verify_key_unchanged_error_identifies_the_affected_identity() {
        let (_alice_sk, alice_pk) = generate_e2e_keypair().unwrap();
        let (_, imposter_pk) = generate_e2e_keypair().unwrap();

        match verify_key_unchanged("alice", &alice_pk, &imposter_pk) {
            Err(ProtocolError::IdentityKeyChanged { identifier }) => {
                assert_eq!(identifier, "alice");
            }
            other => panic!("expected IdentityKeyChanged, got {other:?}"),
        }
    }
}
