use crate::error::ProtocolError;
use crate::packet_type::{Direction, PacketType};

/// Which end of the connection this state machine is tracking.
///
/// The handshake is asymmetric — the client waits on more distinct
/// server messages (`ServerHello`, then `ServerAccept`, then
/// `AuthChallenge`, then `AuthAccept`/`AuthReject`) than the server waits
/// on from the client, so the two roles need different state sequences
/// during the handshake even though they converge on the same
/// `Established`/`Closing` states afterward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    // Server-side handshake states: what the server is waiting to receive.
    AwaitingClientHello,
    AwaitingClientFinish,
    AwaitingAuth,

    // Client-side handshake states: what the client is waiting to receive.
    AwaitingServerHello,
    AwaitingServerAccept,
    AwaitingAuthChallenge,
    AwaitingAuthResult,

    Established,
    Closing,
}

impl ConnectionState {
    /// The state a fresh connection starts in, for the given role.
    pub fn initial(role: Role) -> Self {
        match role {
            Role::Server => Self::AwaitingClientHello,
            Role::Client => Self::AwaitingServerHello,
        }
    }

    /// Returns an error if the packet type is not allowed in the current
    /// state, either because it's the wrong phase of the handshake or
    /// because this role could never legitimately receive it (e.g. a
    /// client should never receive `SendMessage`, which only ever
    /// travels client → server).
    pub fn validate_incoming(
        self,
        role: Role,
        packet_type: PacketType,
    ) -> Result<(), ProtocolError> {
        let direction_allowed = matches!(
            (role, packet_type.direction()),
            (
                Role::Client,
                Direction::ServerToClient | Direction::Bidirectional
            ) | (
                Role::Server,
                Direction::ClientToServer | Direction::Bidirectional
            )
        );
        if !direction_allowed {
            return Err(ProtocolError::InvalidStateTransition);
        }

        let allowed = match self {
            Self::AwaitingClientHello => matches!(packet_type, PacketType::ClientHello),
            Self::AwaitingClientFinish => {
                matches!(packet_type, PacketType::ClientFinish | PacketType::Error)
            }
            // Only the auth response is accepted before identity is proven.
            Self::AwaitingAuth => {
                matches!(packet_type, PacketType::AuthResponse | PacketType::Error)
            }

            Self::AwaitingServerHello => {
                matches!(packet_type, PacketType::ServerHello | PacketType::Error)
            }
            Self::AwaitingServerAccept => {
                matches!(packet_type, PacketType::ServerAccept | PacketType::Error)
            }
            Self::AwaitingAuthChallenge => {
                matches!(packet_type, PacketType::AuthChallenge | PacketType::Error)
            }
            Self::AwaitingAuthResult => matches!(
                packet_type,
                PacketType::AuthAccept | PacketType::AuthReject | PacketType::Error
            ),

            Self::Established => matches!(
                packet_type,
                PacketType::Ping
                    | PacketType::Pong
                    | PacketType::SendMessage
                    | PacketType::DeliverMessage
                    | PacketType::MessageStatusUpdate
                    | PacketType::DeliveryReceipt
                    | PacketType::RegisterDevice
                    | PacketType::RegisterResponse
                    | PacketType::QueryAccountStatus
                    | PacketType::AccountStatusResponse
                    | PacketType::FetchQueuedMessages
                    | PacketType::QueuedMessageDelivery
                    | PacketType::AckQueuedMessage
                    | PacketType::SendFriendRequest
                    | PacketType::FriendRequestResult
                    | PacketType::IncomingFriendRequest
                    | PacketType::FriendRequestDecision
                    | PacketType::RemoveFriend
                    | PacketType::RemoveFriendResult
                    | PacketType::FriendRemovedNotification
                    | PacketType::FriendStatusUpdate
                    | PacketType::SendTypingIndicator
                    | PacketType::PublishE2eKey
                    | PacketType::PublishE2eKeyResult
                    | PacketType::FetchE2eKey
                    | PacketType::E2eKeyResponse
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

            (Self::AwaitingServerHello, PacketType::ServerHello) => Self::AwaitingServerAccept,
            (Self::AwaitingServerAccept, PacketType::ServerAccept) => Self::AwaitingAuthChallenge,
            (Self::AwaitingAuthChallenge, PacketType::AuthChallenge) => Self::AwaitingAuthResult,
            // Unlike AwaitingAuth above (server side), the client sees
            // AuthAccept and AuthReject as two distinct packet types, so
            // the state machine can resolve accept/reject itself instead
            // of leaving it entirely to the caller.
            (Self::AwaitingAuthResult, PacketType::AuthAccept) => Self::Established,
            (Self::AwaitingAuthResult, PacketType::AuthReject) => Self::Closing,

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
        let s = ConnectionState::initial(Role::Server);
        assert!(
            s.validate_incoming(Role::Server, PacketType::ClientHello)
                .is_ok()
        );
        let s = s.advance(PacketType::ClientHello);
        assert_eq!(s, ConnectionState::AwaitingClientFinish);

        assert!(
            s.validate_incoming(Role::Server, PacketType::ClientFinish)
                .is_ok()
        );
        let s = s.advance(PacketType::ClientFinish);
        assert_eq!(s, ConnectionState::AwaitingAuth);

        assert!(
            s.validate_incoming(Role::Server, PacketType::AuthResponse)
                .is_ok()
        );
        let s = s.advance(PacketType::AuthResponse);
        assert_eq!(s, ConnectionState::Established);
    }

    #[test]
    fn client_handshake_happy_path() {
        let s = ConnectionState::initial(Role::Client);
        assert_eq!(s, ConnectionState::AwaitingServerHello);

        assert!(
            s.validate_incoming(Role::Client, PacketType::ServerHello)
                .is_ok()
        );
        let s = s.advance(PacketType::ServerHello);
        assert_eq!(s, ConnectionState::AwaitingServerAccept);

        assert!(
            s.validate_incoming(Role::Client, PacketType::ServerAccept)
                .is_ok()
        );
        let s = s.advance(PacketType::ServerAccept);
        assert_eq!(s, ConnectionState::AwaitingAuthChallenge);

        assert!(
            s.validate_incoming(Role::Client, PacketType::AuthChallenge)
                .is_ok()
        );
        let s = s.advance(PacketType::AuthChallenge);
        assert_eq!(s, ConnectionState::AwaitingAuthResult);

        assert!(
            s.validate_incoming(Role::Client, PacketType::AuthAccept)
                .is_ok()
        );
        let s = s.advance(PacketType::AuthAccept);
        assert_eq!(s, ConnectionState::Established);
    }

    #[test]
    fn client_closes_on_auth_reject() {
        let s = ConnectionState::AwaitingAuthResult;
        assert!(
            s.validate_incoming(Role::Client, PacketType::AuthReject)
                .is_ok()
        );
        let s = s.advance(PacketType::AuthReject);
        assert_eq!(s, ConnectionState::Closing);
    }

    #[test]
    fn rejects_message_before_handshake() {
        let s = ConnectionState::AwaitingClientHello;
        assert!(
            s.validate_incoming(Role::Server, PacketType::SendMessage)
                .is_err()
        );
    }

    #[test]
    fn rejects_message_before_auth() {
        let s = ConnectionState::AwaitingAuth;
        assert!(
            s.validate_incoming(Role::Server, PacketType::SendMessage)
                .is_err()
        );
        assert!(s.validate_incoming(Role::Server, PacketType::Ping).is_err());
    }

    #[test]
    fn allows_delivery_tracking_packets_once_established() {
        let s = ConnectionState::Established;
        assert!(
            s.validate_incoming(Role::Server, PacketType::MessageStatusUpdate)
                .is_err()
        ); // wrong direction: server never receives this
        assert!(
            s.validate_incoming(Role::Client, PacketType::MessageStatusUpdate)
                .is_ok()
        );
        assert!(
            s.validate_incoming(Role::Server, PacketType::DeliveryReceipt)
                .is_ok()
        );
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
        assert!(s.validate_incoming(Role::Server, PacketType::Ping).is_err());
        assert!(
            s.validate_incoming(Role::Server, PacketType::Close)
                .is_err()
        );
    }

    #[test]
    fn server_rejects_server_to_client_packet_while_established() {
        // A server should never legitimately receive DeliverMessage — that
        // type only ever travels server -> client.
        let s = ConnectionState::Established;
        assert!(
            s.validate_incoming(Role::Server, PacketType::DeliverMessage)
                .is_err()
        );
    }

    #[test]
    fn client_rejects_client_to_server_packet_while_established() {
        // A client should never legitimately receive SendMessage — that
        // type only ever travels client -> server.
        let s = ConnectionState::Established;
        assert!(
            s.validate_incoming(Role::Client, PacketType::SendMessage)
                .is_err()
        );
    }

    #[test]
    fn both_roles_accept_bidirectional_packets_while_established() {
        let s = ConnectionState::Established;
        assert!(s.validate_incoming(Role::Server, PacketType::Ping).is_ok());
        assert!(s.validate_incoming(Role::Client, PacketType::Ping).is_ok());
        assert!(s.validate_incoming(Role::Server, PacketType::Close).is_ok());
        assert!(s.validate_incoming(Role::Client, PacketType::Close).is_ok());
    }
}
