use super::common::{decode_sized_string, encode_sized_string, require_fully_consumed};
use crate::crypto::session::{ML_KEM_768_CT_SIZE, ML_KEM_768_EK_SIZE};
use std::io::{self, Error, ErrorKind};

/// Sent by the client to initiate the handshake.
///
/// Carries the client's identity and the public key material needed for the
/// hybrid X25519 + ML-KEM-768 session key exchange (Layer 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloPayload {
    pub client_id: String,
    /// Client's ephemeral X25519 public key (32 bytes).
    pub x25519_public_key: [u8; 32],
    /// Client's ML-KEM-768 encapsulation key (1184 bytes).
    pub ml_kem_ek: [u8; ML_KEM_768_EK_SIZE],
}

impl ClientHelloPayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let id = encode_sized_string(&self.client_id)?;
        let mut out = Vec::with_capacity(id.len() + 32 + ML_KEM_768_EK_SIZE);
        out.extend_from_slice(&id);
        out.extend_from_slice(&self.x25519_public_key);
        out.extend_from_slice(&self.ml_kem_ek);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (client_id, consumed) = decode_sized_string(bytes)?;
        let after_id = &bytes[consumed..];

        if after_id.len() < 32 + ML_KEM_768_EK_SIZE {
            return Err(Error::new(ErrorKind::InvalidData, "client_hello too short for key material"));
        }

        let x25519_public_key: [u8; 32] = after_id[..32].try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid x25519 key length"))?;

        let mut ml_kem_ek = [0u8; ML_KEM_768_EK_SIZE];
        ml_kem_ek.copy_from_slice(&after_id[32..32 + ML_KEM_768_EK_SIZE]);

        require_fully_consumed(bytes, consumed + 32 + ML_KEM_768_EK_SIZE, "client_hello")?;

        Ok(Self { client_id, x25519_public_key, ml_kem_ek })
    }
}

/// Sent by the server in response to ClientHello.
///
/// Carries the server's X25519 public key and the ML-KEM ciphertext from
/// which the client can recover the Kyber shared secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHelloPayload {
    pub server_id: String,
    /// Server's ephemeral X25519 public key (32 bytes).
    pub x25519_public_key: [u8; 32],
    /// ML-KEM-768 ciphertext (1088 bytes); client decapsulates this.
    pub ml_kem_ciphertext: [u8; ML_KEM_768_CT_SIZE],
}

impl ServerHelloPayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let id = encode_sized_string(&self.server_id)?;
        let mut out = Vec::with_capacity(id.len() + 32 + ML_KEM_768_CT_SIZE);
        out.extend_from_slice(&id);
        out.extend_from_slice(&self.x25519_public_key);
        out.extend_from_slice(&self.ml_kem_ciphertext);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (server_id, consumed) = decode_sized_string(bytes)?;
        let after_id = &bytes[consumed..];

        if after_id.len() < 32 + ML_KEM_768_CT_SIZE {
            return Err(Error::new(ErrorKind::InvalidData, "server_hello too short for key material"));
        }

        let x25519_public_key: [u8; 32] = after_id[..32].try_into()
            .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid x25519 key length"))?;

        let mut ml_kem_ciphertext = [0u8; ML_KEM_768_CT_SIZE];
        ml_kem_ciphertext.copy_from_slice(&after_id[32..32 + ML_KEM_768_CT_SIZE]);

        require_fully_consumed(bytes, consumed + 32 + ML_KEM_768_CT_SIZE, "server_hello")?;

        Ok(Self { server_id, x25519_public_key, ml_kem_ciphertext })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientFinishPayload {
    pub ready: bool,
}

impl ClientFinishPayload {
    pub fn encode(&self) -> Vec<u8> {
        vec![if self.ready { 1 } else { 0 }]
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != 1 {
            return Err(Error::new(ErrorKind::InvalidData, "client_finish payload must be exactly 1 byte"));
        }
        let ready = decode_bool(bytes[0], "client_finish ready")?;
        Ok(Self { ready })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAcceptPayload {
    pub accepted: bool,
}

impl ServerAcceptPayload {
    pub fn encode(&self) -> Vec<u8> {
        vec![if self.accepted { 1 } else { 0 }]
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != 1 {
            return Err(Error::new(ErrorKind::InvalidData, "server_accept payload must be exactly 1 byte"));
        }
        let accepted = decode_bool(bytes[0], "server_accept accepted")?;
        Ok(Self { accepted })
    }
}

fn decode_bool(value: u8, field_name: &str) -> io::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::new(
            ErrorKind::InvalidData,
            format!("{field_name} must be encoded as 0 or 1"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_roundtrip() {
        let payload = ClientHelloPayload {
            client_id: "device-abc".to_string(),
            x25519_public_key: [0x01u8; 32],
            ml_kem_ek: [0x02u8; ML_KEM_768_EK_SIZE],
        };
        let encoded = payload.encode().unwrap();
        let decoded = ClientHelloPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn server_hello_roundtrip() {
        let payload = ServerHelloPayload {
            server_id: "chatix-server-1".to_string(),
            x25519_public_key: [0xAAu8; 32],
            ml_kem_ciphertext: [0xBBu8; ML_KEM_768_CT_SIZE],
        };
        let encoded = payload.encode().unwrap();
        let decoded = ServerHelloPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn client_hello_rejects_truncated_key_material() {
        // Only client_id, no key bytes
        let id_only = encode_sized_string("dev").unwrap();
        assert!(ClientHelloPayload::decode(&id_only).is_err());
    }

    #[test]
    fn client_finish_rejects_non_canonical_boolean() {
        assert!(ClientFinishPayload::decode(&[2]).is_err());
    }

    #[test]
    fn server_accept_rejects_non_canonical_boolean() {
        assert!(ServerAcceptPayload::decode(&[255]).is_err());
    }
}