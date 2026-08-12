use super::common::{decode_bool, decode_sized_string, encode_sized_string, require_fully_consumed};
use std::io::{self, Error, ErrorKind};

// ── Friend request ─────────────────────────────────────────────────────────

/// Sent by the client to request a friendship with another user by username.
/// The server looks up the username and either forwards an IncomingFriendRequest
/// to the target or responds with FriendRequestResult(UserNotFound).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendFriendRequestPayload {
    pub target_username: String,
}

impl SendFriendRequestPayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        encode_sized_string(&self.target_username)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (target_username, consumed) = decode_sized_string(bytes)?;
        require_fully_consumed(bytes, consumed, "send_friend_request")?;
        Ok(Self { target_username })
    }
}

/// Status codes for FriendRequestResultPayload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FriendRequestStatus {
    Accepted = 0,
    Rejected = 1,
    UserNotFound = 2,
}

impl FriendRequestStatus {
    fn from_u8(v: u8) -> io::Result<Self> {
        match v {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::Rejected),
            2 => Ok(Self::UserNotFound),
            _ => Err(Error::new(ErrorKind::InvalidData, "unknown friend_request status")),
        }
    }
}

/// Sent by the server to the original requester to report the outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendRequestResultPayload {
    pub status: FriendRequestStatus,
}

impl FriendRequestResultPayload {
    pub fn encode(&self) -> Vec<u8> {
        vec![self.status as u8]
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != 1 {
            return Err(Error::new(ErrorKind::InvalidData, "friend_request_result must be exactly 1 byte"));
        }
        let status = FriendRequestStatus::from_u8(bytes[0])?;
        Ok(Self { status })
    }
}

/// Sent by the server to the target user to notify them of an incoming request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingFriendRequestPayload {
    pub sender_username: String,
}

impl IncomingFriendRequestPayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        encode_sized_string(&self.sender_username)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (sender_username, consumed) = decode_sized_string(bytes)?;
        require_fully_consumed(bytes, consumed, "incoming_friend_request")?;
        Ok(Self { sender_username })
    }
}

/// Sent by the target user back to the server to accept or reject the request.
/// `sender_username` identifies which pending request this decision is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendRequestDecisionPayload {
    pub sender_username: String,
    pub accepted: bool,
}

impl FriendRequestDecisionPayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = encode_sized_string(&self.sender_username)?;
        out.push(if self.accepted { 1 } else { 0 });
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (sender_username, consumed) = decode_sized_string(bytes)?;
        if bytes.len() != consumed + 1 {
            return Err(Error::new(ErrorKind::InvalidData, "friend_request_decision payload length mismatch"));
        }
        let accepted = decode_bool(bytes[consumed], "friend_request_decision accepted")?;
        Ok(Self { sender_username, accepted })
    }
}

// ── Friend removal ─────────────────────────────────────────────────────────

/// Sent by the client to remove a friend by username.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveFriendPayload {
    pub friend_username: String,
}

impl RemoveFriendPayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        encode_sized_string(&self.friend_username)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (friend_username, consumed) = decode_sized_string(bytes)?;
        require_fully_consumed(bytes, consumed, "remove_friend")?;
        Ok(Self { friend_username })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RemoveFriendStatus {
    Success = 0,
    /// The specified username was not in the caller's friend list.
    NotFound = 1,
}

impl RemoveFriendStatus {
    fn from_u8(v: u8) -> io::Result<Self> {
        match v {
            0 => Ok(Self::Success),
            1 => Ok(Self::NotFound),
            _ => Err(Error::new(ErrorKind::InvalidData, "unknown remove_friend status")),
        }
    }
}

/// Sent by the server in response to RemoveFriendPayload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveFriendResultPayload {
    pub status: RemoveFriendStatus,
}

impl RemoveFriendResultPayload {
    pub fn encode(&self) -> Vec<u8> {
        vec![self.status as u8]
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != 1 {
            return Err(Error::new(ErrorKind::InvalidData, "remove_friend_result must be exactly 1 byte"));
        }
        let status = RemoveFriendStatus::from_u8(bytes[0])?;
        Ok(Self { status })
    }
}

/// Sent by the server to the user who was removed, identifying who removed them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendRemovedNotificationPayload {
    pub removed_by_username: String,
}

impl FriendRemovedNotificationPayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        encode_sized_string(&self.removed_by_username)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (removed_by_username, consumed) = decode_sized_string(bytes)?;
        require_fully_consumed(bytes, consumed, "friend_removed_notification")?;
        Ok(Self { removed_by_username })
    }
}

// ── Friend status ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FriendStatus {
    Online = 0,
    Offline = 1,
    /// Friend is currently composing a message to this user.
    IsTyping = 2,
}

impl FriendStatus {
    fn from_u8(v: u8) -> io::Result<Self> {
        match v {
            0 => Ok(Self::Online),
            1 => Ok(Self::Offline),
            2 => Ok(Self::IsTyping),
            _ => Err(Error::new(ErrorKind::InvalidData, "unknown friend_status value")),
        }
    }
}

/// Pushed by the server whenever a friend's status changes.
/// `last_seen` is a Unix timestamp (seconds); only meaningful when status is Offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendStatusUpdatePayload {
    pub friend_username: String,
    pub status: FriendStatus,
    pub last_seen: u64,
}

impl FriendStatusUpdatePayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut out = encode_sized_string(&self.friend_username)?;
        out.push(self.status as u8);
        out.extend_from_slice(&self.last_seen.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (friend_username, consumed) = decode_sized_string(bytes)?;
        let rest = &bytes[consumed..];
        if rest.len() != 9 {
            return Err(Error::new(ErrorKind::InvalidData, "friend_status_update missing status/last_seen fields"));
        }
        let status = FriendStatus::from_u8(rest[0])?;
        let last_seen = u64::from_be_bytes(rest[1..9].try_into().map_err(|_| {
            Error::new(ErrorKind::InvalidData, "failed to decode friend_status_update last_seen")
        })?);
        Ok(Self { friend_username, status, last_seen })
    }
}

/// Sent by the client to signal that it is composing a message.
/// The server forwards this as FriendStatusUpdate(IsTyping) to the recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendTypingIndicatorPayload {
    pub recipient_username: String,
}

impl SendTypingIndicatorPayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        encode_sized_string(&self.recipient_username)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (recipient_username, consumed) = decode_sized_string(bytes)?;
        require_fully_consumed(bytes, consumed, "send_typing_indicator")?;
        Ok(Self { recipient_username })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_friend_request_roundtrip() {
        let p = SendFriendRequestPayload { target_username: "bob".to_string() };
        let decoded = SendFriendRequestPayload::decode(&p.encode().unwrap()).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn send_friend_request_rejects_trailing_bytes() {
        let mut enc = SendFriendRequestPayload { target_username: "bob".to_string() }.encode().unwrap();
        enc.push(0);
        assert!(SendFriendRequestPayload::decode(&enc).is_err());
    }

    #[test]
    fn friend_request_result_roundtrip_all_statuses() {
        for status in [FriendRequestStatus::Accepted, FriendRequestStatus::Rejected, FriendRequestStatus::UserNotFound] {
            let p = FriendRequestResultPayload { status };
            let decoded = FriendRequestResultPayload::decode(&p.encode()).unwrap();
            assert_eq!(decoded, p);
        }
    }

    #[test]
    fn friend_request_result_rejects_unknown_status() {
        assert!(FriendRequestResultPayload::decode(&[3]).is_err());
    }

    #[test]
    fn friend_request_result_rejects_wrong_length() {
        assert!(FriendRequestResultPayload::decode(&[]).is_err());
        assert!(FriendRequestResultPayload::decode(&[0, 0]).is_err());
    }

    #[test]
    fn incoming_friend_request_roundtrip() {
        let p = IncomingFriendRequestPayload { sender_username: "alice".to_string() };
        let decoded = IncomingFriendRequestPayload::decode(&p.encode().unwrap()).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn friend_request_decision_roundtrip_accept() {
        let p = FriendRequestDecisionPayload { sender_username: "alice".to_string(), accepted: true };
        let decoded = FriendRequestDecisionPayload::decode(&p.encode().unwrap()).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn friend_request_decision_roundtrip_reject() {
        let p = FriendRequestDecisionPayload { sender_username: "alice".to_string(), accepted: false };
        let decoded = FriendRequestDecisionPayload::decode(&p.encode().unwrap()).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn friend_request_decision_rejects_non_canonical_bool() {
        let mut enc = FriendRequestDecisionPayload { sender_username: "alice".to_string(), accepted: true }
            .encode()
            .unwrap();
        *enc.last_mut().unwrap() = 7;
        assert!(FriendRequestDecisionPayload::decode(&enc).is_err());
    }

    #[test]
    fn friend_request_decision_rejects_missing_bool() {
        let enc = SendFriendRequestPayload { target_username: "alice".to_string() }.encode().unwrap();
        assert!(FriendRequestDecisionPayload::decode(&enc).is_err());
    }

    #[test]
    fn remove_friend_roundtrip() {
        let p = RemoveFriendPayload { friend_username: "bob".to_string() };
        let decoded = RemoveFriendPayload::decode(&p.encode().unwrap()).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn remove_friend_result_roundtrip_all_statuses() {
        for status in [RemoveFriendStatus::Success, RemoveFriendStatus::NotFound] {
            let p = RemoveFriendResultPayload { status };
            let decoded = RemoveFriendResultPayload::decode(&p.encode()).unwrap();
            assert_eq!(decoded, p);
        }
    }

    #[test]
    fn remove_friend_result_rejects_unknown_status() {
        assert!(RemoveFriendResultPayload::decode(&[5]).is_err());
    }

    #[test]
    fn friend_removed_notification_roundtrip() {
        let p = FriendRemovedNotificationPayload { removed_by_username: "alice".to_string() };
        let decoded = FriendRemovedNotificationPayload::decode(&p.encode().unwrap()).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn friend_status_update_roundtrip_all_statuses() {
        for status in [FriendStatus::Online, FriendStatus::Offline, FriendStatus::IsTyping] {
            let p = FriendStatusUpdatePayload { friend_username: "carol".to_string(), status, last_seen: 1_700_000_000 };
            let decoded = FriendStatusUpdatePayload::decode(&p.encode().unwrap()).unwrap();
            assert_eq!(decoded, p);
        }
    }

    #[test]
    fn friend_status_update_rejects_unknown_status() {
        let p = FriendStatusUpdatePayload { friend_username: "carol".to_string(), status: FriendStatus::Online, last_seen: 0 };
        let mut enc = p.encode().unwrap();
        // status byte is right after the username string
        let username_len = 2 + "carol".len();
        enc[username_len] = 9;
        assert!(FriendStatusUpdatePayload::decode(&enc).is_err());
    }

    #[test]
    fn friend_status_update_rejects_truncated_payload() {
        let p = FriendStatusUpdatePayload { friend_username: "carol".to_string(), status: FriendStatus::Online, last_seen: 0 };
        let enc = p.encode().unwrap();
        assert!(FriendStatusUpdatePayload::decode(&enc[..enc.len() - 1]).is_err());
    }

    #[test]
    fn send_typing_indicator_roundtrip() {
        let p = SendTypingIndicatorPayload { recipient_username: "dave".to_string() };
        let decoded = SendTypingIndicatorPayload::decode(&p.encode().unwrap()).unwrap();
        assert_eq!(decoded, p);
    }
}