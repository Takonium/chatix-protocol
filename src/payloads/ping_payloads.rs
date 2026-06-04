use std::io::{self, Error, ErrorKind};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingPayload {
    pub timestamp: u64,
}

impl PingPayload {
    pub fn encode(&self) -> Vec<u8> {
        self.timestamp.to_be_bytes().to_vec()
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != 8 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "invalid ping payload length: expected 8, got {}",
                    bytes.len()
                ),
            ));
        }

        let timestamp =
            u64::from_be_bytes(bytes.try_into().map_err(|_| {
                Error::new(ErrorKind::InvalidData, "failed to decode ping payload")
            })?);

        Ok(Self { timestamp })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PongPayload {
    pub timestamp: u64,
}

impl PongPayload {
    pub fn encode(&self) -> Vec<u8> {
        self.timestamp.to_be_bytes().to_vec()
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != 8 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "invalid pong payload length: expected 8, got {}",
                    bytes.len()
                ),
            ));
        }

        let timestamp =
            u64::from_be_bytes(bytes.try_into().map_err(|_| {
                Error::new(ErrorKind::InvalidData, "failed to decode pong payload")
            })?);

        Ok(Self { timestamp })
    }
}