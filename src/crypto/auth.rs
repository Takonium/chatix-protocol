/// Layer 0 – Device identity authentication.
///
/// Proves that the party sending `AuthResponsePayload` controls the private
/// key matching a long-term ML-DSA-65 identity key, *for this specific
/// transport session*.
///
/// # Why the transcript is part of the signed message
///
/// Signing only the server's nonce (as earlier drafts of this protocol did)
/// is not enough: an active on-path attacker can terminate two separate
/// transport sessions — one with the real client, one with the real server —
/// and simply relay the nonce and the resulting signature between them,
/// since neither is bound to which session it belongs to.
///
/// Instead, each side independently computes a transcript hash from the
/// exact `ClientHelloPayload` and `ServerHelloPayload` bytes it sent or
/// received, and the client signs `transcript_hash || nonce`. If an attacker
/// is relaying between two different sessions, the two transcripts differ
/// (different ephemeral keys on at least one side), so a signature valid for
/// one session's transcript fails verification against the other's — the
/// attacker cannot complete the relay without the client's private key.
///
/// This authenticates the client to the server and binds that proof to the
/// session. The server's identity is authenticated the other way around,
/// by `sign_server_hello`/`verify_server_hello` below: the server signs its
/// `ServerHello` material with a long-term ML-DSA-65 key that client
/// deployments pin in advance (out-of-band, e.g. shipped in the client
/// build), rather than trusting a certificate authority. Key distribution
/// and rotation for that pinned key are outside this crate's scope — it
/// only provides the sign/verify primitives.
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Generate as DsaGenerate, Keypair, MlDsa65,
    Signature as DsaSignature, Signer, SigningKey, Verifier, VerifyingKey,
};
use sha2::{Digest, Sha256};

use crate::crypto::e2e::{ML_DSA_65_SIG_SIZE, ML_DSA_65_VK_SIZE};
use crate::crypto::session::ML_KEM_768_CT_SIZE;
use crate::error::ProtocolError;

/// Size of the handshake transcript hash (SHA-256 output).
pub const TRANSCRIPT_LEN: usize = 32;
/// Size of the server-issued auth nonce (must match `AuthChallengePayload::nonce`).
pub const NONCE_LEN: usize = 32;

/// Computes the handshake transcript hash from the raw encoded
/// `ClientHelloPayload` and `ServerHelloPayload` bytes exchanged on this
/// connection. Call this identically on both sides — the caller is
/// responsible for feeding in the *exact* bytes it sent/received on the
/// wire (before any decode/re-encode round trip) so both sides agree
/// whenever there is no tamperer in between.
pub fn compute_handshake_transcript(
    client_hello_bytes: &[u8],
    server_hello_bytes: &[u8],
) -> [u8; TRANSCRIPT_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(client_hello_bytes);
    hasher.update(server_hello_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; TRANSCRIPT_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Generates a fresh ML-DSA-65 identity keypair.
///
/// Deliberately a separate keypair from the E2E messaging identity
/// (`crypto::e2e::generate_e2e_keypair`) — key separation by purpose means
/// compromising one does not automatically compromise the other. There is
/// nothing client-specific about this function: it's used both for a
/// client's per-device auth identity and for a server's long-term pinned
/// identity — the two differ only in how the caller stores and distributes
/// the resulting key, not in how the key itself is generated.
pub fn generate_auth_identity() -> Result<([u8; 32], [u8; ML_DSA_65_VK_SIZE]), ProtocolError> {
    let sk = SigningKey::<MlDsa65>::generate();

    let seed = sk.to_seed();
    let seed_slice: &[u8] = seed.as_ref();
    let mut signing_seed = [0u8; 32];
    signing_seed.copy_from_slice(seed_slice);

    let vk = sk.verifying_key();
    let vk_encoded = vk.encode();
    let vk_slice: &[u8] = vk_encoded.as_ref();
    if vk_slice.len() != ML_DSA_65_VK_SIZE {
        return Err(ProtocolError::CryptoError);
    }
    let mut verifying_key = [0u8; ML_DSA_65_VK_SIZE];
    verifying_key.copy_from_slice(vk_slice);

    Ok((signing_seed, verifying_key))
}

/// Signs `transcript_hash || nonce` with the device's ML-DSA-65 identity key.
/// This is the value that goes in `AuthResponsePayload::signature`.
pub fn sign_auth_response(
    transcript_hash: &[u8; TRANSCRIPT_LEN],
    nonce: &[u8; NONCE_LEN],
    signing_seed: &[u8; 32],
) -> Result<[u8; ML_DSA_65_SIG_SIZE], ProtocolError> {
    let message = auth_message(transcript_hash, nonce);

    let seed_arr =
        ml_dsa::Seed::try_from(signing_seed.as_slice()).map_err(|_| ProtocolError::CryptoError)?;
    let sk = SigningKey::<MlDsa65>::from_seed(&seed_arr);
    let signature: DsaSignature<MlDsa65> = sk.sign(&message);
    let encoded = signature.encode();
    let slice: &[u8] = encoded.as_ref();
    if slice.len() != ML_DSA_65_SIG_SIZE {
        return Err(ProtocolError::CryptoError);
    }
    let mut out = [0u8; ML_DSA_65_SIG_SIZE];
    out.copy_from_slice(slice);
    Ok(out)
}

/// Verifies `AuthResponsePayload::signature` against the transcript hash the
/// *verifier* independently computed for this session, the nonce it issued,
/// and the claimed public key. Returns `Ok(())` only if all three match.
pub fn verify_auth_response(
    transcript_hash: &[u8; TRANSCRIPT_LEN],
    nonce: &[u8; NONCE_LEN],
    verifying_key: &[u8; ML_DSA_65_VK_SIZE],
    signature: &[u8; ML_DSA_65_SIG_SIZE],
) -> Result<(), ProtocolError> {
    let message = auth_message(transcript_hash, nonce);

    let vk_arr = EncodedVerifyingKey::<MlDsa65>::try_from(verifying_key.as_slice())
        .map_err(|_| ProtocolError::CryptoError)?;
    let vk = VerifyingKey::<MlDsa65>::decode(&vk_arr);

    let sig_arr = EncodedSignature::<MlDsa65>::try_from(signature.as_slice())
        .map_err(|_| ProtocolError::CryptoError)?;
    let sig = DsaSignature::<MlDsa65>::decode(&sig_arr).ok_or(ProtocolError::CryptoError)?;

    vk.verify(&message, &sig)
        .map_err(|_| ProtocolError::CryptoError)
}

fn auth_message(transcript_hash: &[u8; TRANSCRIPT_LEN], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut message = Vec::with_capacity(TRANSCRIPT_LEN + NONCE_LEN);
    message.extend_from_slice(transcript_hash);
    message.extend_from_slice(nonce);
    message
}

/// Builds the message the server's long-term identity key signs as proof
/// that it — not an impersonator — produced this `ServerHello`.
///
/// Hashing `client_hello_bytes` first (rather than concatenating it
/// directly) keeps the signed message a small, fixed shape regardless of
/// how long the client's hello turns out to be, mirroring
/// `compute_handshake_transcript`. Including it at all binds the signature
/// to *this* client's handshake: a signature captured from one connection
/// cannot be presented as proof for a different one, because the hash
/// would not match. The server's own ephemeral key material
/// (`server_x25519_public_key`, `server_ml_kem_ciphertext`) is included
/// directly — it's already fixed-size, so there's no ambiguity to hash away.
fn server_hello_message(
    client_hello_bytes: &[u8],
    server_x25519_public_key: &[u8; 32],
    server_ml_kem_ciphertext: &[u8; ML_KEM_768_CT_SIZE],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(client_hello_bytes);
    let client_hello_hash = hasher.finalize();

    let mut message = Vec::with_capacity(TRANSCRIPT_LEN + 32 + ML_KEM_768_CT_SIZE);
    message.extend_from_slice(&client_hello_hash);
    message.extend_from_slice(server_x25519_public_key);
    message.extend_from_slice(server_ml_kem_ciphertext);
    message
}

/// Signs `ServerHello` material with the server's long-term ML-DSA-65
/// identity key. This is the value that goes in `ServerHelloPayload::signature`.
///
/// `client_hello_bytes` must be the *exact* bytes the server received on
/// the wire, before any decode/re-encode round trip — same caution as
/// `compute_handshake_transcript`.
pub fn sign_server_hello(
    client_hello_bytes: &[u8],
    server_x25519_public_key: &[u8; 32],
    server_ml_kem_ciphertext: &[u8; ML_KEM_768_CT_SIZE],
    signing_seed: &[u8; 32],
) -> Result<[u8; ML_DSA_65_SIG_SIZE], ProtocolError> {
    let message = server_hello_message(
        client_hello_bytes,
        server_x25519_public_key,
        server_ml_kem_ciphertext,
    );

    let seed_arr =
        ml_dsa::Seed::try_from(signing_seed.as_slice()).map_err(|_| ProtocolError::CryptoError)?;
    let sk = SigningKey::<MlDsa65>::from_seed(&seed_arr);
    let signature: DsaSignature<MlDsa65> = sk.sign(&message);
    let encoded = signature.encode();
    let slice: &[u8] = encoded.as_ref();
    if slice.len() != ML_DSA_65_SIG_SIZE {
        return Err(ProtocolError::CryptoError);
    }
    let mut out = [0u8; ML_DSA_65_SIG_SIZE];
    out.copy_from_slice(slice);
    Ok(out)
}

/// Verifies `ServerHelloPayload::signature` against the client's own pinned
/// copy of the server's verifying key. Returns `Ok(())` only if the
/// signature matches this exact handshake's `client_hello_bytes` and the
/// received `ServerHello` ephemeral key material.
///
/// `pinned_verifying_key` is expected to come from the client's own
/// configuration (shipped with the client, not read off the wire) — that's
/// what makes this pinning rather than trust-on-first-use.
pub fn verify_server_hello(
    client_hello_bytes: &[u8],
    server_x25519_public_key: &[u8; 32],
    server_ml_kem_ciphertext: &[u8; ML_KEM_768_CT_SIZE],
    pinned_verifying_key: &[u8; ML_DSA_65_VK_SIZE],
    signature: &[u8; ML_DSA_65_SIG_SIZE],
) -> Result<(), ProtocolError> {
    let message = server_hello_message(
        client_hello_bytes,
        server_x25519_public_key,
        server_ml_kem_ciphertext,
    );

    let vk_arr = EncodedVerifyingKey::<MlDsa65>::try_from(pinned_verifying_key.as_slice())
        .map_err(|_| ProtocolError::CryptoError)?;
    let vk = VerifyingKey::<MlDsa65>::decode(&vk_arr);

    let sig_arr = EncodedSignature::<MlDsa65>::try_from(signature.as_slice())
        .map_err(|_| ProtocolError::CryptoError)?;
    let sig = DsaSignature::<MlDsa65>::decode(&sig_arr).ok_or(ProtocolError::CryptoError)?;

    vk.verify(&message, &sig)
        .map_err(|_| ProtocolError::CryptoError)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_transcript(tag: u8) -> [u8; TRANSCRIPT_LEN] {
        compute_handshake_transcript(&[tag], &[tag.wrapping_add(1)])
    }

    #[test]
    fn auth_roundtrip_succeeds() {
        let (seed, vk) = generate_auth_identity().unwrap();
        let transcript = sample_transcript(1);
        let nonce = [0x42u8; NONCE_LEN];

        let sig = sign_auth_response(&transcript, &nonce, &seed).unwrap();
        assert!(verify_auth_response(&transcript, &nonce, &vk, &sig).is_ok());
    }

    #[test]
    fn wrong_transcript_is_rejected() {
        // Simulates a relayed AuthResponse: the verifier's own transcript
        // (computed from the handshake *it* actually participated in)
        // differs from the one the signer used.
        let (seed, vk) = generate_auth_identity().unwrap();
        let signer_transcript = sample_transcript(1);
        let verifier_transcript = sample_transcript(2);
        let nonce = [0x42u8; NONCE_LEN];

        let sig = sign_auth_response(&signer_transcript, &nonce, &seed).unwrap();
        assert!(verify_auth_response(&verifier_transcript, &nonce, &vk, &sig).is_err());
    }

    #[test]
    fn wrong_nonce_is_rejected() {
        let (seed, vk) = generate_auth_identity().unwrap();
        let transcript = sample_transcript(1);

        let sig = sign_auth_response(&transcript, &[0x11u8; NONCE_LEN], &seed).unwrap();
        assert!(verify_auth_response(&transcript, &[0x22u8; NONCE_LEN], &vk, &sig).is_err());
    }

    #[test]
    fn wrong_verifying_key_is_rejected() {
        let (seed, _vk) = generate_auth_identity().unwrap();
        let (_, imposter_vk) = generate_auth_identity().unwrap();
        let transcript = sample_transcript(1);
        let nonce = [0x42u8; NONCE_LEN];

        let sig = sign_auth_response(&transcript, &nonce, &seed).unwrap();
        assert!(verify_auth_response(&transcript, &nonce, &imposter_vk, &sig).is_err());
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (seed, vk) = generate_auth_identity().unwrap();
        let transcript = sample_transcript(1);
        let nonce = [0x42u8; NONCE_LEN];

        let mut sig = sign_auth_response(&transcript, &nonce, &seed).unwrap();
        sig[0] ^= 0xFF;
        assert!(verify_auth_response(&transcript, &nonce, &vk, &sig).is_err());
    }

    #[test]
    fn server_hello_roundtrip_succeeds() {
        let (seed, pinned_vk) = generate_auth_identity().unwrap();
        let client_hello_bytes = b"client-hello-wire-bytes";
        let server_x25519_pk = [0x11u8; 32];
        let server_ml_kem_ct = [0x22u8; ML_KEM_768_CT_SIZE];

        let sig = sign_server_hello(
            client_hello_bytes,
            &server_x25519_pk,
            &server_ml_kem_ct,
            &seed,
        )
        .unwrap();
        assert!(
            verify_server_hello(
                client_hello_bytes,
                &server_x25519_pk,
                &server_ml_kem_ct,
                &pinned_vk,
                &sig,
            )
            .is_ok()
        );
    }

    #[test]
    fn server_hello_wrong_client_hello_is_rejected() {
        // A signature captured from one handshake must not verify against
        // a different client_hello — otherwise a captured ServerHello could
        // be replayed to convince a different client it's talking to the
        // real, pinned server.
        let (seed, pinned_vk) = generate_auth_identity().unwrap();
        let server_x25519_pk = [0x11u8; 32];
        let server_ml_kem_ct = [0x22u8; ML_KEM_768_CT_SIZE];

        let sig = sign_server_hello(
            b"client-hello-from-session-a",
            &server_x25519_pk,
            &server_ml_kem_ct,
            &seed,
        )
        .unwrap();

        assert!(
            verify_server_hello(
                b"client-hello-from-session-b",
                &server_x25519_pk,
                &server_ml_kem_ct,
                &pinned_vk,
                &sig,
            )
            .is_err()
        );
    }

    #[test]
    fn server_hello_wrong_pinned_key_is_rejected() {
        // Simulates an impersonator without the real server's private key:
        // even a structurally valid signature must fail against the
        // client's actual pinned key.
        let (seed, _real_vk) = generate_auth_identity().unwrap();
        let (_, imposter_vk) = generate_auth_identity().unwrap();
        let client_hello_bytes = b"client-hello-wire-bytes";
        let server_x25519_pk = [0x11u8; 32];
        let server_ml_kem_ct = [0x22u8; ML_KEM_768_CT_SIZE];

        let sig = sign_server_hello(
            client_hello_bytes,
            &server_x25519_pk,
            &server_ml_kem_ct,
            &seed,
        )
        .unwrap();

        assert!(
            verify_server_hello(
                client_hello_bytes,
                &server_x25519_pk,
                &server_ml_kem_ct,
                &imposter_vk,
                &sig,
            )
            .is_err()
        );
    }

    #[test]
    fn server_hello_tampered_signature_is_rejected() {
        let (seed, pinned_vk) = generate_auth_identity().unwrap();
        let client_hello_bytes = b"client-hello-wire-bytes";
        let server_x25519_pk = [0x11u8; 32];
        let server_ml_kem_ct = [0x22u8; ML_KEM_768_CT_SIZE];

        let mut sig = sign_server_hello(
            client_hello_bytes,
            &server_x25519_pk,
            &server_ml_kem_ct,
            &seed,
        )
        .unwrap();
        sig[0] ^= 0xFF;

        assert!(
            verify_server_hello(
                client_hello_bytes,
                &server_x25519_pk,
                &server_ml_kem_ct,
                &pinned_vk,
                &sig,
            )
            .is_err()
        );
    }
}
