use super::common::{decode_bool, decode_sized_string, encode_sized_string, require_fully_consumed};
use std::io::{self, Error, ErrorKind};

/// Sent by the client (in the Established state) to claim a username for its
/// device-bound identity (the routing key derived from the auth public key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterDevicePayload {
    pub username: String,
}

impl RegisterDevicePayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        encode_sized_string(&self.username)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (username, consumed) = decode_sized_string(bytes)?;
        require_fully_consumed(bytes, consumed, "register_device")?;
        Ok(Self { username })
    }
}

/// Sent by the server in response to RegisterDevicePayload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterResponsePayload {
    pub success: bool,
    pub message: String,
}

impl RegisterResponsePayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let message = encode_sized_string(&self.message)?;
        let mut out = Vec::with_capacity(1 + message.len());
        out.push(if self.success { 1 } else { 0 });
        out.extend_from_slice(&message);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() {
            return Err(Error::new(ErrorKind::InvalidData, "register_response payload too short"));
        }
        let success = decode_bool(bytes[0], "register_response success")?;
        let (message, consumed) = decode_sized_string(&bytes[1..])?;
        require_fully_consumed(bytes, 1 + consumed, "register_response")?;
        Ok(Self { success, message })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_device_roundtrip() {
        let payload = RegisterDevicePayload { username: "alice".to_string() };
        let encoded = payload.encode().unwrap();
        let decoded = RegisterDevicePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn register_device_rejects_trailing_bytes() {
        let mut encoded = RegisterDevicePayload { username: "bob".to_string() }.encode().unwrap();
        encoded.push(0);
        assert!(RegisterDevicePayload::decode(&encoded).is_err());
    }

    #[test]
    fn register_response_roundtrip_success() {
        let payload = RegisterResponsePayload { success: true, message: "ok".to_string() };
        let encoded = payload.encode().unwrap();
        let decoded = RegisterResponsePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn register_response_roundtrip_failure() {
        let payload = RegisterResponsePayload { success: false, message: "username taken".to_string() };
        let encoded = payload.encode().unwrap();
        let decoded = RegisterResponsePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn register_response_rejects_non_canonical_boolean() {
        let mut encoded = RegisterResponsePayload { success: true, message: String::new() }.encode().unwrap();
        encoded[0] = 2;
        assert!(RegisterResponsePayload::decode(&encoded).is_err());
    }

    #[test]
    fn register_response_rejects_empty_payload() {
        assert!(RegisterResponsePayload::decode(&[]).is_err());
    }
}
