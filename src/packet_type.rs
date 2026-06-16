use crate::error::ProtocolError;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    // Handshake (1–19)
    ClientHello = 1,
    ServerHello = 2,
    ClientFinish = 3,
    ServerAccept = 4,

    // Auth (5–8)
    AuthChallenge = 5,
    AuthResponse = 6,
    AuthAccept = 7,
    AuthReject = 8,

    // Control (20–39)
    Ping = 20,
    Pong = 21,

    // Messaging (40–79)
    SendMessage = 40,
    DeliverMessage = 41,

    // Close / Error (240–255)
    Error = 254,
    Close = 255,
}

impl PacketType {
    pub fn from_u8(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::ClientHello),
            2 => Ok(Self::ServerHello),
            3 => Ok(Self::ClientFinish),
            4 => Ok(Self::ServerAccept),
            5 => Ok(Self::AuthChallenge),
            6 => Ok(Self::AuthResponse),
            7 => Ok(Self::AuthAccept),
            8 => Ok(Self::AuthReject),
            20 => Ok(Self::Ping),
            21 => Ok(Self::Pong),
            40 => Ok(Self::SendMessage),
            41 => Ok(Self::DeliverMessage),
            254 => Ok(Self::Error),
            255 => Ok(Self::Close),
            other => Err(ProtocolError::UnknownPacketType(other)),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn max_payload_size(self) -> u32 {
        match self {
            // client_id + x25519 pubkey (32 B) + ML-KEM-768 ek (1184 B)
            Self::ClientHello => 1300,
            // server_id + x25519 pubkey (32 B) + ML-KEM-768 ciphertext (1088 B)
            Self::ServerHello => 1200,
            Self::ClientFinish | Self::ServerAccept => 1,
            // 32-byte nonce
            Self::AuthChallenge => 32,
            // 32 pk + 64 sig + 4 len-prefix + up to 4096 attestation chain
            Self::AuthResponse => 4200,
            // empty payloads
            Self::AuthAccept | Self::AuthReject => 0,
            Self::Ping | Self::Pong => 8,
            Self::SendMessage | Self::DeliverMessage => 65536,
            Self::Error | Self::Close => 1024,
        }
    }

    pub fn validate_payload_size(self, payload_len: u32) -> Result<(), ProtocolError> {
        let max = self.max_payload_size();
        if payload_len > max {
            Err(ProtocolError::PayloadTooLarge {
                size: payload_len,
                max,
            })
        } else {
            Ok(())
        }
    }
}