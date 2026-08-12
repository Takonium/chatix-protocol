use super::common::{decode_bool, decode_sized_string, encode_sized_string, require_fully_consumed};
use std::io::{self, Error, ErrorKind};

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
}