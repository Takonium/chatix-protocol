use crate::error::ProtocolError;
use crate::packet_type::PacketType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    AwaitingClientHello,
    AwaitingClientFinish,
    AwaitingAuth,
    Established,
    Closing,
}

impl ConnectionState {
    /// Returns an error if the packet type is not allowed in the current state.
    pub fn validate_incoming(self, packet_type: PacketType) -> Result<(), ProtocolError> {
        let allowed = match self {
            Self::AwaitingClientHello => matches!(packet_type, PacketType::ClientHello),
            Self::AwaitingClientFinish => {
                matches!(packet_type, PacketType::ClientFinish | PacketType::Error)
            }
            // Only the auth response is accepted before identity is proven.
            Self::AwaitingAuth => {
                matches!(packet_type, PacketType::AuthResponse | PacketType::Error)
            }
            Self::Established => matches!(
                packet_type,
                PacketType::Ping
                    | PacketType::Pong
                    | PacketType::SendMessage
                    | PacketType::DeliverMessage
                    | PacketType::Close
                    | PacketType::Error
            ),
            // No valid incoming packets once we are closing.
            Self::Closing => false,
        };

        if allowed {
            Ok(())
        } else {
            Err(ProtocolError::InvalidStateTransition)
        }
    }

    /// Advances the state machine based on the received packet type.
    /// Call only after `validate_incoming` has succeeded.
    pub fn advance(self, packet_type: PacketType) -> Self {
        match (self, packet_type) {
            (Self::AwaitingClientHello, PacketType::ClientHello) => Self::AwaitingClientFinish,
            (Self::AwaitingClientFinish, PacketType::ClientFinish) => Self::AwaitingAuth,
            (Self::AwaitingAuth, PacketType::AuthResponse) => Self::Established,
            // Any Error or Close packet from either side moves to Closing.
            (_, PacketType::Close | PacketType::Error) => Self::Closing,
            (state, _) => state,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_happy_path() {
        let s = ConnectionState::AwaitingClientHello;
        assert!(s.validate_incoming(PacketType::ClientHello).is_ok());
        let s = s.advance(PacketType::ClientHello);
        assert_eq!(s, ConnectionState::AwaitingClientFinish);

        assert!(s.validate_incoming(PacketType::ClientFinish).is_ok());
        let s = s.advance(PacketType::ClientFinish);
        assert_eq!(s, ConnectionState::AwaitingAuth);

        assert!(s.validate_incoming(PacketType::AuthResponse).is_ok());
        let s = s.advance(PacketType::AuthResponse);
        assert_eq!(s, ConnectionState::Established);
    }

    #[test]
    fn rejects_message_before_handshake() {
        let s = ConnectionState::AwaitingClientHello;
        assert!(s.validate_incoming(PacketType::SendMessage).is_err());
    }

    #[test]
    fn rejects_message_before_auth() {
        let s = ConnectionState::AwaitingAuth;
        assert!(s.validate_incoming(PacketType::SendMessage).is_err());
        assert!(s.validate_incoming(PacketType::Ping).is_err());
    }

    #[test]
    fn error_packet_always_closes() {
        let s = ConnectionState::Established;
        let s = s.advance(PacketType::Error);
        assert_eq!(s, ConnectionState::Closing);
    }

    #[test]
    fn closing_rejects_all() {
        let s = ConnectionState::Closing;
        assert!(s.validate_incoming(PacketType::Ping).is_err());
        assert!(s.validate_incoming(PacketType::Close).is_err());
    }
}