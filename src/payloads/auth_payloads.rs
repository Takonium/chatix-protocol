use super::common::{decode_sized_bytes, encode_sized_bytes, require_fully_consumed};
use crate::crypto::e2e::{ML_DSA_65_SIG_SIZE, ML_DSA_65_VK_SIZE};
use std::io::{self, Error, ErrorKind};

/// Server → Client: random nonce the client must sign, together with the
/// handshake transcript, to prove its identity (see `crypto::auth`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallengePayload {
    pub nonce: [u8; 32],
}

impl AuthChallengePayload {
    pub fn encode(&self) -> Vec<u8> {
        self.nonce.to_vec()
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "auth_challenge must be exactly 32 bytes",
            ));
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(bytes);
        Ok(Self { nonce })
    }
}

/// Client → Server: ML-DSA-65 identity proof.
///
/// - `public_key`: ML-DSA-65 verifying key (identity anchor)
/// - `signature`: ML-DSA-65 signature over `transcript_hash || nonce` — see
///   `crypto::auth::sign_auth_response` / `verify_auth_response`. Signing
///   only the nonce is not sufficient: it does not bind the proof to this
///   specific transport session, so it does not protect against a relayed
///   handshake between two different sessions.
/// - `attestation_token`: optional Android Key Attestation certificate chain (best-effort;
///   absent on F-Droid / custom ROM builds — server must accept empty)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponsePayload {
    pub public_key: [u8; ML_DSA_65_VK_SIZE],
    pub signature: [u8; ML_DSA_65_SIG_SIZE],
    pub attestation_token: Vec<u8>,
}

impl AuthResponsePayload {
    const FIXED: usize = ML_DSA_65_VK_SIZE + ML_DSA_65_SIG_SIZE;

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let att = encode_sized_bytes(&self.attestation_token)?;
        let mut out = Vec::with_capacity(Self::FIXED + att.len());
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&att);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < Self::FIXED + 4 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "auth_response too short",
            ));
        }

        let public_key: [u8; ML_DSA_65_VK_SIZE] = bytes[..ML_DSA_65_VK_SIZE]
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid public key"))?;

        let signature: [u8; ML_DSA_65_SIG_SIZE] = bytes[ML_DSA_65_VK_SIZE..Self::FIXED]
            .try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid signature"))?;

        let (attestation_token, att_consumed) = decode_sized_bytes(&bytes[Self::FIXED..])?;

        require_fully_consumed(bytes, Self::FIXED + att_consumed, "auth_response")?;

        Ok(Self {
            public_key,
            signature,
            attestation_token,
        })
    }
}

/// Server → Client: auth accepted; connection promoted to Established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthAcceptPayload;

impl AuthAcceptPayload {
    pub fn encode(&self) -> Vec<u8> {
        vec![]
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if !bytes.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "auth_accept payload must be empty",
            ));
        }
        Ok(Self)
    }
}

/// Server → Client: auth rejected.
///
/// Generic response — intentionally carries no reason to avoid leaking information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRejectPayload;

impl AuthRejectPayload {
    pub fn encode(&self) -> Vec<u8> {
        vec![]
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if !bytes.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "auth_reject payload must be empty",
            ));
        }
        Ok(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_challenge_roundtrip() {
        let p = AuthChallengePayload {
            nonce: [0xABu8; 32],
        };
        let enc = p.encode();
        assert_eq!(enc.len(), 32);
        let dec = AuthChallengePayload::decode(&enc).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn auth_response_roundtrip_with_attestation() {
        let p = AuthResponsePayload {
            public_key: [0x01u8; ML_DSA_65_VK_SIZE],
            signature: [0x02u8; ML_DSA_65_SIG_SIZE],
            attestation_token: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let enc = p.encode().unwrap();
        let dec = AuthResponsePayload::decode(&enc).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn auth_response_roundtrip_empty_attestation() {
        let p = AuthResponsePayload {
            public_key: [0x03u8; ML_DSA_65_VK_SIZE],
            signature: [0x04u8; ML_DSA_65_SIG_SIZE],
            attestation_token: vec![],
        };
        let enc = p.encode().unwrap();
        let dec = AuthResponsePayload::decode(&enc).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn auth_response_uses_real_ml_dsa_65_signature() {
        // End-to-end through the actual crypto layer, not just placeholder
        // bytes: generates a real identity, signs a real transcript+nonce,
        // and checks the wire payload verifies.
        use crate::crypto::auth::{
            compute_handshake_transcript, generate_auth_identity, sign_auth_response,
            verify_auth_response,
        };

        let (seed, verifying_key) = generate_auth_identity().unwrap();
        let transcript = compute_handshake_transcript(b"client-hello-bytes", b"server-hello-bytes");
        let nonce = [0x7Eu8; 32];

        let signature = sign_auth_response(&transcript, &nonce, &seed).unwrap();
        let p = AuthResponsePayload {
            public_key: verifying_key,
            signature,
            attestation_token: vec![],
        };

        let enc = p.encode().unwrap();
        let dec = AuthResponsePayload::decode(&enc).unwrap();

        assert!(verify_auth_response(&transcript, &nonce, &dec.public_key, &dec.signature).is_ok());
    }

    #[test]
    fn auth_accept_rejects_nonempty() {
        assert!(AuthAcceptPayload::decode(&[0]).is_err());
    }

    #[test]
    fn auth_reject_rejects_nonempty() {
        assert!(AuthRejectPayload::decode(&[0]).is_err());
    }
}
