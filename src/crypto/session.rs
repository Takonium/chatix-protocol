/// Layer 1 – Transport session key derivation.
///
/// Hybrid key exchange: X25519 (classical) + ML-KEM-768 (post-quantum, FIPS 203).
/// Both shared secrets are combined via HKDF-SHA256 so that breaking either
/// algorithm alone is insufficient to compromise the session.
///
/// Flow:
///   1. Client calls `ClientHandshakeState::generate()` and embeds the returned
///      public material in `ClientHelloPayload`.
///   2. Server calls `ServerHandshakeState::respond()` with the client's public keys
///      → derives `SessionKeys` immediately and embeds its own public material in
///      `ServerHelloPayload`.
///   3. Client calls `state.derive_session_keys()` with the server's public material
///      → derives the identical `SessionKeys`.
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::ProtocolError;

use ml_kem::{
    kem::Kem,
    Ciphertext, Decapsulate, Encapsulate, KeyExport,
    DecapsulationKey768, EncapsulationKey768, MlKem768,
};

pub const ML_KEM_768_EK_SIZE: usize = 1184;
pub const ML_KEM_768_CT_SIZE: usize = 1088;

/// Symmetric keys for an established session.
///
/// `client_to_server` is used by the client to encrypt and by the server to decrypt.
/// `server_to_client` is the reverse direction.
/// Both are derived from the same IKM with distinct labels to prevent
/// cross-direction key reuse attacks.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub client_to_server: [u8; 32],
    pub server_to_client: [u8; 32],
}

/// Client-side handshake state. Holds ephemeral secrets until the server responds.
pub struct ClientHandshakeState {
    x25519_secret: EphemeralSecret,
    ml_kem_dk: Option<DecapsulationKey768>,
    /// X25519 ephemeral public key — embed in `ClientHelloPayload`.
    pub x25519_public: [u8; 32],
    /// ML-KEM-768 encapsulation key bytes — embed in `ClientHelloPayload`.
    pub ml_kem_ek: [u8; ML_KEM_768_EK_SIZE],
}

impl ClientHandshakeState {
    pub fn generate() -> Result<Self, ProtocolError> {
        let mut rng = rand_core::OsRng;

        let x25519_secret = EphemeralSecret::random_from_rng(&mut rng);
        let x25519_public: [u8; 32] = PublicKey::from(&x25519_secret).to_bytes();

        let (ml_kem_dk, ml_kem_ek) = MlKem768::generate_keypair();

        let ek_bytes = ml_kem_ek.to_bytes();
        let ek_slice: &[u8] = ek_bytes.as_ref();
        if ek_slice.len() != ML_KEM_768_EK_SIZE {
            return Err(ProtocolError::CryptoError);
        }
        let mut ml_kem_ek_arr = [0u8; ML_KEM_768_EK_SIZE];
        ml_kem_ek_arr.copy_from_slice(ek_slice);

        Ok(Self {
            x25519_secret,
            ml_kem_dk: Some(ml_kem_dk),
            x25519_public,
            ml_kem_ek: ml_kem_ek_arr,
        })
    }

    /// Completes the handshake using the server's public material from `ServerHelloPayload`.
    pub fn derive_session_keys(
        mut self,
        server_x25519_pk: [u8; 32],
        ml_kem_ciphertext: &[u8; ML_KEM_768_CT_SIZE],
    ) -> Result<SessionKeys, ProtocolError> {
        let server_pk = PublicKey::from(server_x25519_pk);
        let x25519_shared = self.x25519_secret.diffie_hellman(&server_pk);

        let dk = self.ml_kem_dk.take().ok_or(ProtocolError::CryptoError)?;

        // Reconstruct the typed ciphertext from raw bytes.
        let ct_arr = ml_kem::array::Array::try_from(ml_kem_ciphertext.as_slice())
            .map_err(|_| ProtocolError::CryptoError)?;
        let ct = Ciphertext::<MlKem768>::from(ct_arr);

        let kyber_shared = dk.decapsulate(&ct);

        derive_keys(x25519_shared.as_bytes(), kyber_shared.as_ref())
    }
}

/// Server-side handshake output.
pub struct ServerHandshakeState {
    /// Server's X25519 ephemeral public key — embed in `ServerHelloPayload`.
    pub x25519_public: [u8; 32],
    /// ML-KEM-768 ciphertext — embed in `ServerHelloPayload`.
    pub ml_kem_ciphertext: [u8; ML_KEM_768_CT_SIZE],
    /// Session keys, ready immediately after construction.
    pub session_keys: SessionKeys,
}

impl ServerHandshakeState {
    /// Called when the server receives a `ClientHelloPayload`.
    pub fn respond(
        client_x25519_pk: [u8; 32],
        client_ml_kem_ek: &[u8; ML_KEM_768_EK_SIZE],
    ) -> Result<Self, ProtocolError> {
        let mut rng = rand_core::OsRng;

        let server_secret = EphemeralSecret::random_from_rng(&mut rng);
        let server_public: [u8; 32] = PublicKey::from(&server_secret).to_bytes();

        let client_pk = PublicKey::from(client_x25519_pk);
        let x25519_shared = server_secret.diffie_hellman(&client_pk);

        // Reconstruct the client's encapsulation key from bytes.
        let ek_arr = ml_kem::array::Array::try_from(client_ml_kem_ek.as_slice())
            .map_err(|_| ProtocolError::CryptoError)?;
        let ek = EncapsulationKey768::new(&ek_arr).map_err(|_| ProtocolError::CryptoError)?;

        let (ct, kyber_shared) = ek.encapsulate();

        let ct_bytes: &[u8] = ct.as_ref();
        if ct_bytes.len() != ML_KEM_768_CT_SIZE {
            return Err(ProtocolError::CryptoError);
        }
        let mut ml_kem_ciphertext = [0u8; ML_KEM_768_CT_SIZE];
        ml_kem_ciphertext.copy_from_slice(ct_bytes);

        let session_keys = derive_keys(x25519_shared.as_bytes(), kyber_shared.as_ref())?;

        Ok(Self {
            x25519_public: server_public,
            ml_kem_ciphertext,
            session_keys,
        })
    }
}

/// Derives two 32-byte session keys from the combined X25519 and ML-KEM shared secrets.
///
/// Using two separate HKDF labels guarantees that even if one direction's key is
/// exposed, the other direction remains secure.
fn derive_keys(x25519_shared: &[u8], kyber_shared: &[u8]) -> Result<SessionKeys, ProtocolError> {
    let mut ikm = Vec::with_capacity(x25519_shared.len() + kyber_shared.len());
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(kyber_shared);

    let hk = Hkdf::<Sha256>::new(None, &ikm);

    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];

    hk.expand(b"chatix-c2s-v1", &mut c2s)
        .map_err(|_| ProtocolError::CryptoError)?;
    hk.expand(b"chatix-s2c-v1", &mut s2c)
        .map_err(|_| ProtocolError::CryptoError)?;

    ikm.zeroize();

    Ok(SessionKeys {
        client_to_server: c2s,
        server_to_client: s2c,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_derivation_matches() {
        let client_state = ClientHandshakeState::generate().unwrap();

        let x25519_pub = client_state.x25519_public;
        let ml_kem_ek = client_state.ml_kem_ek;

        let server_state = ServerHandshakeState::respond(x25519_pub, &ml_kem_ek).unwrap();

        let client_keys = client_state
            .derive_session_keys(server_state.x25519_public, &server_state.ml_kem_ciphertext)
            .unwrap();

        assert_eq!(
            client_keys.client_to_server,
            server_state.session_keys.client_to_server
        );
        assert_eq!(
            client_keys.server_to_client,
            server_state.session_keys.server_to_client
        );
    }

    #[test]
    fn c2s_and_s2c_keys_differ() {
        let client_state = ClientHandshakeState::generate().unwrap();
        let server_state =
            ServerHandshakeState::respond(client_state.x25519_public, &client_state.ml_kem_ek)
                .unwrap();
        assert_ne!(
            server_state.session_keys.client_to_server,
            server_state.session_keys.server_to_client
        );
    }
}