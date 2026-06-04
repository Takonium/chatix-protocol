use super::common::{decode_sized_string, encode_sized_string, require_fully_consumed};
use std::io::{self, Error, ErrorKind};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Normal = 0,
    ProtocolError = 1,
    Timeout = 2,
    ServerShutdown = 3,
    ClientRequest = 4,
}

impl CloseReason {
    pub fn from_u8(value: u8) -> io::Result<Self> {
        match value {
            0 => Ok(Self::Normal),
            1 => Ok(Self::ProtocolError),
            2 => Ok(Self::Timeout),
            3 => Ok(Self::ServerShutdown),
            4 => Ok(Self::ClientRequest),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                format!("unknown close reason: {}", value),
            )),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosePayload {
    pub reason: CloseReason,
    pub message: String,
}

impl ClosePayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(1 + 2 + self.message.len());
        out.push(self.reason.as_u8());

        let msg_bytes = encode_sized_string(&self.message)?;
        out.extend_from_slice(&msg_bytes);

        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "close payload too short",
            ));
        }

        let reason = CloseReason::from_u8(bytes[0])?;
        let (message, consumed) = decode_sized_string(&bytes[1..])?;
        require_fully_consumed(bytes, 1 + consumed, "close")?;

        Ok(Self { reason, message })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_payload_roundtrip() {
        let payload = ClosePayload {
            reason: CloseReason::ClientRequest,
            message: "done".to_string(),
        };

        let encoded = payload.encode().unwrap();
        let decoded = ClosePayload::decode(&encoded).unwrap();

        assert_eq!(decoded, payload);
    }

    #[test]
    fn close_payload_rejects_trailing_bytes() {
        let mut encoded = ClosePayload {
            reason: CloseReason::ProtocolError,
            message: "bad frame".to_string(),
        }
        .encode()
        .unwrap();
        encoded.push(0);

        assert!(ClosePayload::decode(&encoded).is_err());
    }
}