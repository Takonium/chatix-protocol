/// Layer 2 – End-to-end encryption and signing helpers.
///
/// The server never holds keys for this layer; it only forwards opaque blobs.
/// The `content` field of `SendMessagePayload` / `DeliverMessagePayload` is always
/// the output of `encrypt_and_sign` and must be fed to `verify_and_decrypt` by the recipient.
///
/// # Scheme
///
/// Per-message key exchange (hybrid):
///   - Sender generates an ephemeral X25519 keypair.
///   - Sender encapsulates to recipient's long-term ML-KEM-768 encapsulation key.
///   - HKDF-SHA256(x25519_shared || kyber_shared) → AES-256-GCM content key.
///
/// Authentication:
///   - ML-DSA-65 signature over the entire blob (excluding the signature itself).
///
/// # Wire format of the content blob
///
/// ```text
/// [ sender_x25519_ek (32 B)
/// | ml_kem_ciphertext (1088 B)
/// | aes_nonce (12 B)
/// | aes_ciphertext_and_tag (plaintext_len + 16 B)
/// | ml_dsa_signature (3309 B) ]
/// ```
use hkdf::Hkdf;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey,
    Generate as DsaGenerate, Keypair,
    MlDsa65, Signature as DsaSignature,
    SigningKey, Signer, Verifier, VerifyingKey,
};
use ml_kem::{
    Ciphertext, Decapsulate, DecapsulationKey768, Encapsulate,
    EncapsulationKey768, KeyExport, MlKem768,
};
use ring::aead::{self, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::session::{ML_KEM_768_CT_SIZE, ML_KEM_768_EK_SIZE};
use crate::error::ProtocolError;

// ── Wire format constants ──────────────────────────────────────────────────

pub const NONCE_LEN: usize = 12;
pub const GCM_TAG_LEN: usize = 16;

/// ML-DSA-65 signature size in bytes (NIST FIPS 204 §5).
pub const ML_DSA_65_SIG_SIZE: usize = 3309;
/// ML-DSA-65 verifying key size in bytes.
pub const ML_DSA_65_VK_SIZE: usize = 1952;

// Offsets within the content blob.
const SENDER_X25519_END: usize = 32;
const ML_KEM_CT_END: usize = SENDER_X25519_END + ML_KEM_768_CT_SIZE;
const AES_NONCE_END: usize = ML_KEM_CT_END + NONCE_LEN;

/// Minimum blob length (empty plaintext): all fixed-size fields + GCM tag + signature.
pub const MIN_BLOB_LEN: usize = AES_NONCE_END + GCM_TAG_LEN + ML_DSA_65_SIG_SIZE;

// ── Key pair types ─────────────────────────────────────────────────────────

/// All secret key material for one E2E identity. Store securely; never log or transmit.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct E2eSecretKey {
    /// Long-term X25519 private key (32 B).
    pub x25519_secret: [u8; 32],
    /// ML-KEM-768 decapsulation key seed (64 B).
    pub ml_kem_seed: [u8; 64],
    /// ML-DSA-65 signing key seed (32 B).
    pub dsa_signing_seed: [u8; 32],
}

/// All public key material for one E2E identity. Safe to distribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E2ePublicKey {
    /// Long-term X25519 public key (32 B).
    pub x25519_public: [u8; 32],
    /// ML-KEM-768 encapsulation key (1184 B).
    pub ml_kem_ek: [u8; ML_KEM_768_EK_SIZE],
    /// ML-DSA-65 verifying key (1952 B).
    pub dsa_verifying_key: [u8; ML_DSA_65_VK_SIZE],
}

/// Generates a fresh E2E identity key pair.
pub fn generate_e2e_keypair() -> Result<(E2eSecretKey, E2ePublicKey), ProtocolError> {
    use ring::rand::SecureRandom;
    let mut rng = rand_core::OsRng;
    let ring_rng = ring::rand::SystemRandom::new();

    // X25519 long-term keypair.
    let x25519_secret = StaticSecret::random_from_rng(&mut rng);
    let x25519_public: [u8; 32] = PublicKey::from(&x25519_secret).to_bytes();
    let x25519_secret_bytes: [u8; 32] = x25519_secret.to_bytes();

    // ML-KEM-768: derive from a random 64-byte seed so the seed can be stored compactly.
    let mut ml_kem_seed = [0u8; 64];
    ring_rng.fill(&mut ml_kem_seed).map_err(|_| ProtocolError::CryptoError)?;
    let seed_arr = ml_kem::Seed::try_from(ml_kem_seed.as_slice())
        .map_err(|_| ProtocolError::CryptoError)?;
    let ml_kem_dk = DecapsulationKey768::from_seed(seed_arr);
    let ml_kem_ek_obj = ml_kem_dk.encapsulation_key();
    let ek_encoded = ml_kem_ek_obj.to_bytes();
    let ek_slice: &[u8] = ek_encoded.as_ref();
    if ek_slice.len() != ML_KEM_768_EK_SIZE {
        return Err(ProtocolError::CryptoError);
    }
    let mut ml_kem_ek = [0u8; ML_KEM_768_EK_SIZE];
    ml_kem_ek.copy_from_slice(ek_slice);

    // ML-DSA-65 signing keypair.
    let dsa_sk = SigningKey::<MlDsa65>::generate();
    let dsa_seed = dsa_sk.to_seed(); // Seed = Array<u8, U32>
    let dsa_seed_slice: &[u8] = dsa_seed.as_ref();
    let mut dsa_signing_seed = [0u8; 32];
    dsa_signing_seed.copy_from_slice(dsa_seed_slice);

    let dsa_vk = dsa_sk.verifying_key();
    let vk_encoded = dsa_vk.encode(); // EncodedVerifyingKey<MlDsa65>
    let vk_slice: &[u8] = vk_encoded.as_ref();
    if vk_slice.len() != ML_DSA_65_VK_SIZE {
        return Err(ProtocolError::CryptoError);
    }
    let mut dsa_verifying_key = [0u8; ML_DSA_65_VK_SIZE];
    dsa_verifying_key.copy_from_slice(vk_slice);

    Ok((
        E2eSecretKey {
            x25519_secret: x25519_secret_bytes,
            ml_kem_seed,
            dsa_signing_seed,
        },
        E2ePublicKey {
            x25519_public,
            ml_kem_ek,
            dsa_verifying_key,
        },
    ))
}

// ── Core operations ────────────────────────────────────────────────────────

/// Encrypts `plaintext` for the recipient and signs the blob with the sender's key.
///
/// - `recipient_x25519_pk`: recipient's 32-byte X25519 public key
/// - `recipient_ml_kem_ek`: recipient's 1184-byte ML-KEM-768 encapsulation key
/// - `sender_signing_seed`: sender's 32-byte ML-DSA-65 signing key seed
pub fn encrypt_and_sign(
    plaintext: &[u8],
    recipient_x25519_pk: &[u8; 32],
    recipient_ml_kem_ek: &[u8; ML_KEM_768_EK_SIZE],
    sender_signing_seed: &[u8; 32],
) -> Result<Vec<u8>, ProtocolError> {
    let mut rng = rand_core::OsRng;

    // ── Key exchange ──
    let sender_ephemeral = EphemeralSecret::random_from_rng(&mut rng);
    let sender_x25519_pk: [u8; 32] = PublicKey::from(&sender_ephemeral).to_bytes();
    let recipient_pk = PublicKey::from(*recipient_x25519_pk);
    let x25519_shared = sender_ephemeral.diffie_hellman(&recipient_pk);

    let ek_arr = ml_kem::array::Array::try_from(recipient_ml_kem_ek.as_slice())
        .map_err(|_| ProtocolError::CryptoError)?;
    let ek = EncapsulationKey768::new(&ek_arr).map_err(|_| ProtocolError::CryptoError)?;
    let (ct, kyber_shared) = ek.encapsulate();
    let ct_bytes: &[u8] = ct.as_ref();
    let mut ml_kem_ct = [0u8; ML_KEM_768_CT_SIZE];
    ml_kem_ct.copy_from_slice(ct_bytes);

    // ── Derive content key and encrypt ──
    let mut content_key = derive_e2e_key(x25519_shared.as_bytes(), kyber_shared.as_ref())?;
    let nonce_bytes = random_nonce()?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let sealing_key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &content_key).map_err(|_| ProtocolError::CryptoError)?,
    );
    let mut ciphertext = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut ciphertext)
        .map_err(|_| ProtocolError::CryptoError)?;
    content_key.zeroize();

    // ── Assemble unsigned blob ──
    let mut blob = Vec::with_capacity(AES_NONCE_END + ciphertext.len() + ML_DSA_65_SIG_SIZE);
    blob.extend_from_slice(&sender_x25519_pk);
    blob.extend_from_slice(&ml_kem_ct);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    // ── Sign the blob ──
    let dsa_seed_arr = ml_dsa::Seed::try_from(sender_signing_seed.as_slice())
        .map_err(|_| ProtocolError::CryptoError)?;
    let dsa_sk = SigningKey::<MlDsa65>::from_seed(&dsa_seed_arr);
    let signature: DsaSignature<MlDsa65> = dsa_sk.sign(&blob);
    let sig_encoded = signature.encode();
    blob.extend_from_slice(sig_encoded.as_ref());

    Ok(blob)
}

/// Verifies the sender's signature and decrypts the blob.
///
/// - `recipient_x25519_sk`: recipient's 32-byte X25519 private key
/// - `recipient_ml_kem_seed`: recipient's 64-byte ML-KEM-768 decapsulation key seed
/// - `sender_verifying_key`: sender's 1952-byte ML-DSA-65 verifying key
pub fn verify_and_decrypt(
    blob: &[u8],
    recipient_x25519_sk: &[u8; 32],
    recipient_ml_kem_seed: &[u8; 64],
    sender_verifying_key: &[u8; ML_DSA_65_VK_SIZE],
) -> Result<Vec<u8>, ProtocolError> {
    if blob.len() < MIN_BLOB_LEN {
        return Err(ProtocolError::CryptoError);
    }

    // ── Split signed part and signature ──
    let (signed_part, sig_bytes) = blob.split_at(blob.len() - ML_DSA_65_SIG_SIZE);

    // ── Verify signature before touching any crypto state ──
    let vk_arr = EncodedVerifyingKey::<MlDsa65>::try_from(sender_verifying_key.as_slice())
        .map_err(|_| ProtocolError::CryptoError)?;
    let dsa_vk = VerifyingKey::<MlDsa65>::decode(&vk_arr);

    let sig_arr = EncodedSignature::<MlDsa65>::try_from(sig_bytes)
        .map_err(|_| ProtocolError::CryptoError)?;
    let signature = DsaSignature::<MlDsa65>::decode(&sig_arr)
        .ok_or(ProtocolError::CryptoError)?;
    dsa_vk
        .verify(signed_part, &signature)
        .map_err(|_| ProtocolError::CryptoError)?;

    // ── Parse key exchange material ──
    let sender_x25519_pk: [u8; 32] = signed_part[..SENDER_X25519_END]
        .try_into()
        .map_err(|_| ProtocolError::CryptoError)?;
    let ml_kem_ct_bytes = &signed_part[SENDER_X25519_END..ML_KEM_CT_END];
    let aes_nonce_bytes: [u8; NONCE_LEN] = signed_part[ML_KEM_CT_END..AES_NONCE_END]
        .try_into()
        .map_err(|_| ProtocolError::CryptoError)?;
    let aes_ct = &signed_part[AES_NONCE_END..];

    // ── Key exchange – recipient side ──
    let recipient_sk = StaticSecret::from(*recipient_x25519_sk);
    let sender_pk = PublicKey::from(sender_x25519_pk);
    let x25519_shared = recipient_sk.diffie_hellman(&sender_pk);

    let ml_kem_seed_arr = ml_kem::Seed::try_from(recipient_ml_kem_seed.as_slice())
        .map_err(|_| ProtocolError::CryptoError)?;
    let ml_kem_dk = DecapsulationKey768::from_seed(ml_kem_seed_arr);

    let ct_arr = ml_kem::array::Array::try_from(ml_kem_ct_bytes)
        .map_err(|_| ProtocolError::CryptoError)?;
    let ct = Ciphertext::<MlKem768>::from(ct_arr);
    let kyber_shared = ml_kem_dk.decapsulate(&ct);

    // ── Derive content key and decrypt ──
    let mut content_key = derive_e2e_key(x25519_shared.as_bytes(), kyber_shared.as_ref())?;
    let nonce = Nonce::assume_unique_for_key(aes_nonce_bytes);
    let opening_key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &content_key).map_err(|_| ProtocolError::CryptoError)?,
    );
    let mut buf = aes_ct.to_vec();
    let plaintext = opening_key
        .open_in_place(nonce, aead::Aad::empty(), &mut buf)
        .map_err(|_| ProtocolError::CryptoError)?;
    content_key.zeroize();

    Ok(plaintext.to_vec())
}

// ── Internal helpers ───────────────────────────────────────────────────────

fn derive_e2e_key(x25519_shared: &[u8], kyber_shared: &[u8]) -> Result<[u8; 32], ProtocolError> {
    let mut ikm = Vec::with_capacity(x25519_shared.len() + kyber_shared.len());
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(kyber_shared);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut key = [0u8; 32];
    hk.expand(b"chatix-e2e-content-v1", &mut key)
        .map_err(|_| ProtocolError::CryptoError)?;
    ikm.zeroize();
    Ok(key)
}

fn random_nonce() -> Result<[u8; NONCE_LEN], ProtocolError> {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce).map_err(|_| ProtocolError::CryptoError)?;
    Ok(nonce)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e2e_roundtrip() {
        let (recipient_sk, recipient_pk) = generate_e2e_keypair().unwrap();
        let (sender_sk, sender_pk) = generate_e2e_keypair().unwrap();

        let plaintext = b"hello end-to-end";
        let blob = encrypt_and_sign(
            plaintext,
            &recipient_pk.x25519_public,
            &recipient_pk.ml_kem_ek,
            &sender_sk.dsa_signing_seed,
        )
        .unwrap();

        let recovered = verify_and_decrypt(
            &blob,
            &recipient_sk.x25519_secret,
            &recipient_sk.ml_kem_seed,
            &sender_pk.dsa_verifying_key,
        )
        .unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (recipient_sk, recipient_pk) = generate_e2e_keypair().unwrap();
        let (sender_sk, sender_pk) = generate_e2e_keypair().unwrap();

        let mut blob = encrypt_and_sign(
            b"secret",
            &recipient_pk.x25519_public,
            &recipient_pk.ml_kem_ek,
            &sender_sk.dsa_signing_seed,
        )
        .unwrap();

        // Flip a bit in the AES ciphertext region.
        blob[AES_NONCE_END] ^= 0xff;

        assert!(verify_and_decrypt(
            &blob,
            &recipient_sk.x25519_secret,
            &recipient_sk.ml_kem_seed,
            &sender_pk.dsa_verifying_key,
        )
        .is_err());
    }

    #[test]
    fn wrong_verifying_key_is_rejected() {
        let (recipient_sk, recipient_pk) = generate_e2e_keypair().unwrap();
        let (sender_sk, _) = generate_e2e_keypair().unwrap();
        let (_, imposter_pk) = generate_e2e_keypair().unwrap();

        let blob = encrypt_and_sign(
            b"secret",
            &recipient_pk.x25519_public,
            &recipient_pk.ml_kem_ek,
            &sender_sk.dsa_signing_seed,
        )
        .unwrap();

        assert!(verify_and_decrypt(
            &blob,
            &recipient_sk.x25519_secret,
            &recipient_sk.ml_kem_seed,
            &imposter_pk.dsa_verifying_key,
        )
        .is_err());
    }

    #[test]
    fn blob_minimum_size_matches_constant() {
        let (recipient_sk, recipient_pk) = generate_e2e_keypair().unwrap();
        let (sender_sk, _) = generate_e2e_keypair().unwrap();

        let blob = encrypt_and_sign(
            b"",
            &recipient_pk.x25519_public,
            &recipient_pk.ml_kem_ek,
            &sender_sk.dsa_signing_seed,
        )
        .unwrap();

        assert_eq!(blob.len(), MIN_BLOB_LEN);
        // Also verify the hardcoded signature size by checking the sig region parses.
        let sig_slice = &blob[blob.len() - ML_DSA_65_SIG_SIZE..];
        let sig_arr = EncodedSignature::<MlDsa65>::try_from(sig_slice).unwrap();
        assert!(DsaSignature::<MlDsa65>::decode(&sig_arr).is_some());
    }
}
