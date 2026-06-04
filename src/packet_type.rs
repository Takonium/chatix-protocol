use std::io::{self, Error, ErrorKind};

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    ClientHello = 1,
    ServerHello = 2,
    ClientFinish = 3,
    ServerAccept = 4,

    Ping = 10,
    Pong = 11,

    SendMessage = 20,
    DeliverMessage = 21,

    Error = 254,
    Close = 255,
}

impl PacketType {
    pub fn from_u8(value: u8) -> io::Result<Self> {
        match value {
            1 => Ok(Self::ClientHello),
            2 => Ok(Self::ServerHello),
            3 => Ok(Self::ClientFinish),
            4 => Ok(Self::ServerAccept),
            10 => Ok(Self::Ping),
            11 => Ok(Self::Pong),
            20 => Ok(Self::SendMessage),
            21 => Ok(Self::DeliverMessage),
            254 => Ok(Self::Error),
            255 => Ok(Self::Close),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                format!("unknown packet type: {}", value),
            )),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns the maximum allowed payload size for this packet type
    pub fn max_payload_size(self) -> u32 {
        match self {
            Self::ClientHello | Self::ServerHello => 256, // Client IDs should be short
            Self::ClientFinish | Self::ServerAccept => 1, // Just a boolean flag
            Self::Ping | Self::Pong => 16,                // Just a timestamp (u64)
            Self::SendMessage | Self::DeliverMessage => 65536, // 64 KiB for messages
            Self::Error => 1024,                          // 1 KiB for error messages
            Self::Close => 1024,                          // 1 KiB for close reason
        }
    }

    /// Validates that the payload size is within acceptable limits
    pub fn validate_payload_size(self, payload_len: u32) -> io::Result<()> {
        let max_size = self.max_payload_size();
        if payload_len > max_size {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "payload size {} exceeds maximum {} for packet type {:?}",
                    payload_len, max_size, self
                ),
            ));
        }
        Ok(())
    }
}