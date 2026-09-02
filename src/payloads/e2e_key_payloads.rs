use super::common::{
    decode_bool, decode_sized_string, encode_sized_string, require_fully_consumed,
};
use crate::crypto::e2e::{E2ePublicKey, ML_DSA_65_VK_SIZE};
use crate::crypto::session::ML_KEM_768_EK_SIZE;
use std::io::{self, Error, ErrorKind};

/// Fixed encoded size of an `E2ePublicKey` bundle on the wire: all three
/// fields are fixed-size, so no length prefixes are needed (same convention
/// as the key portion of `ClientHelloPayload`).
const E2E_PUBLIC_KEY_SIZE: usize = 32 + ML_KEM_768_EK_SIZE + ML_DSA_65_VK_SIZE;

fn encode_e2e_public_key(key: &E2ePublicKey, out: &mut Vec<u8>) {
    out.extend_from_slice(&key.x25519_public);
    out.extend_from_slice(&key.ml_kem_ek);
    out.extend_from_slice(&key.dsa_verifying_key);
}

fn decode_e2e_public_key(bytes: &[u8]) -> io::Result<E2ePublicKey> {
    if bytes.len() < E2E_PUBLIC_KEY_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "e2e public key bundle too short",
        ));
    }

    let x25519_public: [u8; 32] = bytes[..32]
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid x25519 key length"))?;

    let ml_kem_end = 32 + ML_KEM_768_EK_SIZE;
    let mut ml_kem_ek = [0u8; ML_KEM_768_EK_SIZE];
    ml_kem_ek.copy_from_slice(&bytes[32..ml_kem_end]);

    let mut dsa_verifying_key = [0u8; ML_DSA_65_VK_SIZE];
    dsa_verifying_key.copy_from_slice(&bytes[ml_kem_end..E2E_PUBLIC_KEY_SIZE]);

    Ok(E2ePublicKey {
        x25519_public,
        ml_kem_ek,
        dsa_verifying_key,
    })
}

/// Sent by the client (Established state) to publish its E2E (Layer 2)
/// identity key bundle, so other clients can look it up via
/// FetchE2eKeyPayload and start exchanging messages through
/// `crypto::e2e::encrypt_and_sign`. Analogous to how `ClientHelloPayload`
/// carries the client's Layer 1 transport keys, but for the long-term Layer
/// 2 identity instead of an ephemeral one.
///
/// The server only ever stores and forwards this bundle; it has no way to
/// use these keys itself, since `crypto::e2e` operations require the
/// matching private key material the server never sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishE2eKeyPayload {
    pub key: E2ePublicKey,
}

impl PublishE2eKeyPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(E2E_PUBLIC_KEY_SIZE);
        encode_e2e_public_key(&self.key, &mut out);
        out
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let key = decode_e2e_public_key(bytes)?;
        require_fully_consumed(bytes, E2E_PUBLIC_KEY_SIZE, "publish_e2e_key")?;
        Ok(Self { key })
    }
}

/// Sent by the server in response to PublishE2eKeyPayload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishE2eKeyResultPayload {
    pub success: bool,
    pub message: String,
}

impl PublishE2eKeyResultPayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let message = encode_sized_string(&self.message)?;
        let mut out = Vec::with_capacity(1 + message.len());
        out.push(if self.success { 1 } else { 0 });
        out.extend_from_slice(&message);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "publish_e2e_key_result payload too short",
            ));
        }
        let success = decode_bool(bytes[0], "publish_e2e_key_result success")?;
        let (message, consumed) = decode_sized_string(&bytes[1..])?;
        require_fully_consumed(bytes, 1 + consumed, "publish_e2e_key_result")?;
        Ok(Self { success, message })
    }
}

/// Sent by the client to fetch another user's E2E (Layer 2) identity key
/// bundle, previously published via PublishE2eKeyPayload. The server looks
/// up `target_username` and responds with E2eKeyResponsePayload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchE2eKeyPayload {
    pub target_username: String,
}

impl FetchE2eKeyPayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        encode_sized_string(&self.target_username)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (target_username, consumed) = decode_sized_string(bytes)?;
        require_fully_consumed(bytes, consumed, "fetch_e2e_key")?;
        Ok(Self { target_username })
    }
}

/// Status codes for E2eKeyResponsePayload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum E2eKeyStatus {
    Found = 0,
    NotFound = 1,
}

impl E2eKeyStatus {
    fn from_u8(v: u8) -> io::Result<Self> {
        match v {
            0 => Ok(Self::Found),
            1 => Ok(Self::NotFound),
            _ => Err(Error::new(ErrorKind::InvalidData, "unknown e2e_key status")),
        }
    }
}

/// Sent by the server in response to FetchE2eKeyPayload.
///
/// `key` is `None` when `username` has never published an E2E key bundle —
/// in that case the key material is omitted from the wire entirely rather
/// than sent as zeroed placeholder bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct E2eKeyResponsePayload {
    pub username: String,
    pub key: Option<E2ePublicKey>,
}

impl E2eKeyResponsePayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = encode_sized_string(&self.username)?;
        match &self.key {
            Some(key) => {
                out.push(E2eKeyStatus::Found as u8);
                encode_e2e_public_key(key, &mut out);
            }
            None => out.push(E2eKeyStatus::NotFound as u8),
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (username, consumed) = decode_sized_string(bytes)?;
        let rest = &bytes[consumed..];
        if rest.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "e2e_key_response missing status byte",
            ));
        }
        let status = E2eKeyStatus::from_u8(rest[0])?;
        match status {
            E2eKeyStatus::Found => {
                let key = decode_e2e_public_key(&rest[1..])?;
                require_fully_consumed(
                    bytes,
                    consumed + 1 + E2E_PUBLIC_KEY_SIZE,
                    "e2e_key_response",
                )?;
                Ok(Self {
                    username,
                    key: Some(key),
                })
            }
            E2eKeyStatus::NotFound => {
                require_fully_consumed(bytes, consumed + 1, "e2e_key_response")?;
                Ok(Self {
                    username,
                    key: None,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> E2ePublicKey {
        E2ePublicKey {
            x25519_public: [0x01u8; 32],
            ml_kem_ek: [0x02u8; ML_KEM_768_EK_SIZE],
            dsa_verifying_key: [0x03u8; ML_DSA_65_VK_SIZE],
        }
    }

    #[test]
    fn publish_e2e_key_roundtrip() {
        let payload = PublishE2eKeyPayload { key: sample_key() };
        let encoded = payload.encode();
        assert_eq!(encoded.len(), E2E_PUBLIC_KEY_SIZE);
        let decoded = PublishE2eKeyPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn publish_e2e_key_matches_expected_wire_size() {
        // 32 (x25519) + 1184 (ML-KEM-768 ek) + 1952 (ML-DSA-65 vk) = 3168.
        assert_eq!(E2E_PUBLIC_KEY_SIZE, 3168);
    }

    #[test]
    fn publish_e2e_key_rejects_truncated_input() {
        let encoded = PublishE2eKeyPayload { key: sample_key() }.encode();
        assert!(PublishE2eKeyPayload::decode(&encoded[..encoded.len() - 1]).is_err());
    }

    #[test]
    fn publish_e2e_key_rejects_trailing_bytes() {
        let mut encoded = PublishE2eKeyPayload { key: sample_key() }.encode();
        encoded.push(0);
        assert!(PublishE2eKeyPayload::decode(&encoded).is_err());
    }

    #[test]
    fn publish_e2e_key_result_roundtrip_success() {
        let payload = PublishE2eKeyResultPayload {
            success: true,
            message: "ok".to_string(),
        };
        let encoded = payload.encode().unwrap();
        let decoded = PublishE2eKeyResultPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn publish_e2e_key_result_roundtrip_failure() {
        let payload = PublishE2eKeyResultPayload {
            success: false,
            message: "not authenticated".to_string(),
        };
        let encoded = payload.encode().unwrap();
        let decoded = PublishE2eKeyResultPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn publish_e2e_key_result_rejects_non_canonical_boolean() {
        let mut encoded = PublishE2eKeyResultPayload {
            success: true,
            message: String::new(),
        }
        .encode()
        .unwrap();
        encoded[0] = 2;
        assert!(PublishE2eKeyResultPayload::decode(&encoded).is_err());
    }

    #[test]
    fn publish_e2e_key_result_rejects_empty_payload() {
        assert!(PublishE2eKeyResultPayload::decode(&[]).is_err());
    }

    #[test]
    fn fetch_e2e_key_roundtrip() {
        let payload = FetchE2eKeyPayload {
            target_username: "bob".to_string(),
        };
        let decoded = FetchE2eKeyPayload::decode(&payload.encode().unwrap()).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn fetch_e2e_key_rejects_trailing_bytes() {
        let mut encoded = FetchE2eKeyPayload {
            target_username: "bob".to_string(),
        }
        .encode()
        .unwrap();
        encoded.push(0);
        assert!(FetchE2eKeyPayload::decode(&encoded).is_err());
    }

    #[test]
    fn e2e_key_response_roundtrip_found() {
        let payload = E2eKeyResponsePayload {
            username: "alice".to_string(),
            key: Some(sample_key()),
        };
        let encoded = payload.encode().unwrap();
        let decoded = E2eKeyResponsePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn e2e_key_response_matches_expected_max_wire_size() {
        // 130 (2-byte len prefix + up to 128-byte username) + 1 (status) +
        // 3168 (key bundle) = 3299.
        let payload = E2eKeyResponsePayload {
            username: "a".repeat(128),
            key: Some(sample_key()),
        };
        let encoded = payload.encode().unwrap();
        assert_eq!(encoded.len(), 3299);
    }

    #[test]
    fn e2e_key_response_roundtrip_not_found() {
        let payload = E2eKeyResponsePayload {
            username: "ghost".to_string(),
            key: None,
        };
        let encoded = payload.encode().unwrap();
        let decoded = E2eKeyResponsePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn e2e_key_response_rejects_unknown_status() {
        let mut encoded = E2eKeyResponsePayload {
            username: "alice".to_string(),
            key: None,
        }
        .encode()
        .unwrap();
        *encoded.last_mut().unwrap() = 7;
        assert!(E2eKeyResponsePayload::decode(&encoded).is_err());
    }

    #[test]
    fn e2e_key_response_rejects_missing_status_byte() {
        let encoded = encode_sized_string("alice").unwrap();
        assert!(E2eKeyResponsePayload::decode(&encoded).is_err());
    }

    #[test]
    fn e2e_key_response_rejects_truncated_key_material() {
        let encoded = E2eKeyResponsePayload {
            username: "alice".to_string(),
            key: Some(sample_key()),
        }
        .encode()
        .unwrap();
        assert!(E2eKeyResponsePayload::decode(&encoded[..encoded.len() - 1]).is_err());
    }

    #[test]
    fn e2e_key_response_rejects_trailing_bytes_after_not_found() {
        let mut encoded = E2eKeyResponsePayload {
            username: "ghost".to_string(),
            key: None,
        }
        .encode()
        .unwrap();
        encoded.push(0);
        assert!(E2eKeyResponsePayload::decode(&encoded).is_err());
    }
}
