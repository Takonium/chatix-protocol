use super::common::{decode_sized_string, encode_sized_string, require_fully_consumed};
use std::io::{self, Error, ErrorKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloPayload {
    pub client_id: String,
}

impl ClientHelloPayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        encode_sized_string(&self.client_id)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (client_id, consumed) = decode_sized_string(bytes)?;

        require_fully_consumed(bytes, consumed, "client_hello")?;

        Ok(Self { client_id })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHelloPayload {
    pub client_id: String,
}

impl ServerHelloPayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        encode_sized_string(&self.client_id)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (client_id, consumed) = decode_sized_string(bytes)?;

        require_fully_consumed(bytes, consumed, "server_hello")?;

        Ok(Self { client_id })
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
            return Err(Error::new(
                ErrorKind::InvalidData,
                "client_finish payload must be exactly 1 byte",
            ));
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
            return Err(Error::new(
                ErrorKind::InvalidData,
                "server_accept payload must be exactly 1 byte",
            ));
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
    fn hello_payload_roundtrip() {
        let payload = ClientHelloPayload {
            client_id: "device_1".to_string(),
        };

        let encoded = payload.encode().unwrap();
        let decoded = ClientHelloPayload::decode(&encoded).unwrap();

        assert_eq!(decoded, payload);
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