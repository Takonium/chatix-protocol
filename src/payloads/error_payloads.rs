use super::common::{decode_sized_string, encode_sized_string, require_fully_consumed};
use std::io;

#[derive(Debug, Clone)]
pub struct ErrorPayload {
    pub message: String,
}

impl ErrorPayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        encode_sized_string(&self.message)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (message, consumed) = decode_sized_string(bytes)?;
        require_fully_consumed(bytes, consumed, "error")?;

        Ok(Self { message })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_payload_roundtrip() {
        let payload = ErrorPayload {
            message: "protocol violation".to_string(),
        };

        let encoded = payload.encode().unwrap();
        let decoded = ErrorPayload::decode(&encoded).unwrap();

        assert_eq!(decoded.message, payload.message);
    }

    #[test]
    fn error_payload_rejects_trailing_bytes() {
        let mut encoded = ErrorPayload {
            message: "bad".to_string(),
        }
        .encode()
        .unwrap();
        encoded.push(0);

        assert!(ErrorPayload::decode(&encoded).is_err());
    }
}