use crate::crypto::e2e::{ML_DSA_65_SIG_SIZE, ML_DSA_65_VK_SIZE};
use crate::crypto::session::{ML_KEM_768_CT_SIZE, ML_KEM_768_EK_SIZE};
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
    RegisterDevice = 22,
    RegisterResponse = 23,
    QueryAccountStatus = 24,
    AccountStatusResponse = 25,
    SendFriendRequest = 26,
    FriendRequestResult = 27,
    IncomingFriendRequest = 28,
    FriendRequestDecision = 29,
    RemoveFriend = 30,
    RemoveFriendResult = 31,
    FriendRemovedNotification = 32,
    FriendStatusUpdate = 33,
    SendTypingIndicator = 34,
    PublishE2eKey = 35,
    PublishE2eKeyResult = 36,
    FetchE2eKey = 37,
    E2eKeyResponse = 38,

    // Messaging (40–79)
    SendMessage = 40,
    DeliverMessage = 41,
    FetchQueuedMessages = 42,
    QueuedMessageDelivery = 43,
    AckQueuedMessage = 44,
    MessageStatusUpdate = 45,
    DeliveryReceipt = 46,

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
            22 => Ok(Self::RegisterDevice),
            23 => Ok(Self::RegisterResponse),
            24 => Ok(Self::QueryAccountStatus),
            25 => Ok(Self::AccountStatusResponse),
            26 => Ok(Self::SendFriendRequest),
            27 => Ok(Self::FriendRequestResult),
            28 => Ok(Self::IncomingFriendRequest),
            29 => Ok(Self::FriendRequestDecision),
            30 => Ok(Self::RemoveFriend),
            31 => Ok(Self::RemoveFriendResult),
            32 => Ok(Self::FriendRemovedNotification),
            33 => Ok(Self::FriendStatusUpdate),
            34 => Ok(Self::SendTypingIndicator),
            35 => Ok(Self::PublishE2eKey),
            36 => Ok(Self::PublishE2eKeyResult),
            37 => Ok(Self::FetchE2eKey),
            38 => Ok(Self::E2eKeyResponse),
            40 => Ok(Self::SendMessage),
            41 => Ok(Self::DeliverMessage),
            42 => Ok(Self::FetchQueuedMessages),
            43 => Ok(Self::QueuedMessageDelivery),
            44 => Ok(Self::AckQueuedMessage),
            45 => Ok(Self::MessageStatusUpdate),
            46 => Ok(Self::DeliveryReceipt),
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
            // server_id (headroom for the sized-string prefix + up to ~78
            // bytes of id) + x25519 pubkey (32 B) + ML-KEM-768 ciphertext
            // (1088 B) + ML-DSA-65 signature over the server's identity
            // proof (3309 B)
            Self::ServerHello => (32 + ML_KEM_768_CT_SIZE + ML_DSA_65_SIG_SIZE + 80) as u32,
            Self::ClientFinish | Self::ServerAccept => 1,
            // 32-byte nonce
            Self::AuthChallenge => 32,
            // ML-DSA-65 pk + sig + 4-byte len-prefix + up to 4096-byte attestation chain
            Self::AuthResponse => (ML_DSA_65_VK_SIZE + ML_DSA_65_SIG_SIZE + 4 + 4096) as u32,
            // empty payloads
            Self::AuthAccept | Self::AuthReject => 0,
            Self::Ping | Self::Pong => 8,
            Self::SendMessage | Self::DeliverMessage => 65536,
            // 2-byte len prefix + up to 128-byte username
            Self::RegisterDevice => 130,
            // 1-byte success flag + 2-byte len prefix + up to 256-byte message
            Self::RegisterResponse => 259,
            // empty request payload
            Self::QueryAccountStatus => 0,
            // 1-byte is_banned + 2-byte len prefix + up to 256-byte ban_reason
            // + 1-byte subscription_active + 8-byte expiry timestamp
            Self::AccountStatusResponse => 268,
            // 2-byte len prefix + up to 128-byte username
            Self::SendFriendRequest | Self::IncomingFriendRequest => 130,
            // 1-byte status
            Self::FriendRequestResult => 1,
            // 2-byte len prefix + up to 128-byte username + 1-byte accepted
            Self::FriendRequestDecision => 131,
            // 2-byte len prefix + up to 128-byte username
            Self::RemoveFriend | Self::FriendRemovedNotification | Self::SendTypingIndicator => 130,
            // 1-byte status
            Self::RemoveFriendResult => 1,
            // 2-byte len prefix + up to 128-byte username + 1-byte status + 8-byte timestamp
            Self::FriendStatusUpdate => 139,
            // x25519 pubkey (32 B) + ML-KEM-768 ek (1184 B) + ML-DSA-65 vk (1952 B), no
            // length prefixes needed since every field is fixed size
            Self::PublishE2eKey => (32 + ML_KEM_768_EK_SIZE + ML_DSA_65_VK_SIZE) as u32,
            // 1-byte success flag + 2-byte len prefix + up to 256-byte message
            Self::PublishE2eKeyResult => 259,
            // 2-byte len prefix + up to 128-byte username
            Self::FetchE2eKey => 130,
            // 2-byte len prefix + up to 128-byte username + 1-byte status +
            // (only when Found) x25519 pubkey (32 B) + ML-KEM-768 ek (1184 B) + ML-DSA-65 vk (1952 B)
            Self::E2eKeyResponse => (130 + 1 + 32 + ML_KEM_768_EK_SIZE + ML_DSA_65_VK_SIZE) as u32,
            // 8-byte message_id + 1-byte status
            Self::MessageStatusUpdate => 9,
            // 8-byte message_id
            Self::DeliveryReceipt => 8,
            // empty request payload
            Self::FetchQueuedMessages => 0,
            // 8-byte queue_id + sender_id + content, same size class as DeliverMessage
            Self::QueuedMessageDelivery => 65536,
            // 8-byte queue_id
            Self::AckQueuedMessage => 8,
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

    /// Which side of the connection is allowed to send this packet type.
    ///
    /// Derived from each payload's own doc comments (see `payloads/`), which
    /// already say "Sent by the client..." / "Sent by the server..." for
    /// every type. `ConnectionState::validate_incoming` uses this to reject
    /// a packet type arriving from a direction it could never legitimately
    /// come from, on top of the existing per-phase checks.
    pub fn direction(self) -> Direction {
        match self {
            Self::ClientHello
            | Self::ClientFinish
            | Self::AuthResponse
            | Self::SendMessage
            | Self::RegisterDevice
            | Self::QueryAccountStatus
            | Self::SendFriendRequest
            | Self::FriendRequestDecision
            | Self::RemoveFriend
            | Self::SendTypingIndicator
            | Self::FetchQueuedMessages
            | Self::AckQueuedMessage
            | Self::DeliveryReceipt
            | Self::PublishE2eKey
            | Self::FetchE2eKey => Direction::ClientToServer,

            Self::ServerHello
            | Self::ServerAccept
            | Self::AuthChallenge
            | Self::AuthAccept
            | Self::AuthReject
            | Self::DeliverMessage
            | Self::RegisterResponse
            | Self::AccountStatusResponse
            | Self::FriendRequestResult
            | Self::IncomingFriendRequest
            | Self::RemoveFriendResult
            | Self::FriendRemovedNotification
            | Self::FriendStatusUpdate
            | Self::QueuedMessageDelivery
            | Self::MessageStatusUpdate
            | Self::PublishE2eKeyResult
            | Self::E2eKeyResponse => Direction::ServerToClient,

            // Keepalives and connection teardown can originate from either side.
            Self::Ping | Self::Pong | Self::Close | Self::Error => Direction::Bidirectional,
        }
    }
}

/// Which side of a connection a packet type is allowed to be sent from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
    /// Either side may send this type (keepalives, teardown).
    Bidirectional,
}
