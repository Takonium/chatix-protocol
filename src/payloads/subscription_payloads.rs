use super::common::require_fully_consumed;
use std::io::{self, Error, ErrorKind};

/// Sent by the client (in the Established state) to ask the server for its
/// current subscription status. Carries no fields — the server identifies
/// the caller from the already-authenticated connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuerySubscriptionStatusPayload;

impl QuerySubscriptionStatusPayload {
    pub fn encode(&self) -> Vec<u8> {
        Vec::new()
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        require_fully_consumed(bytes, 0, "query_subscription_status")?;
        Ok(Self)
    }
}

/// Sent by the server in response to QuerySubscriptionStatusPayload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionStatusResponsePayload {
    pub is_active: bool,
    /// Unix timestamp (seconds) when the subscription expires. Meaningless
    /// when `is_active` is false.
    pub expiry_timestamp: u64,
}

impl SubscriptionStatusResponsePayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9);
        out.push(if self.is_active { 1 } else { 0 });
        out.extend_from_slice(&self.expiry_timestamp.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != 9 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("invalid subscription_status_response length: expected 9, got {}", bytes.len()),
            ));
        }
        let is_active = decode_bool(bytes[0], "subscription_status_response is_active")?;
        let expiry_timestamp = u64::from_be_bytes(bytes[1..9].try_into().map_err(|_| {
            Error::new(ErrorKind::InvalidData, "failed to decode subscription_status_response timestamp")
        })?);
        Ok(Self { is_active, expiry_timestamp })
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
    fn query_subscription_status_roundtrip() {
        let payload = QuerySubscriptionStatusPayload;
        let encoded = payload.encode();
        let decoded = QuerySubscriptionStatusPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn query_subscription_status_rejects_nonempty_payload() {
        assert!(QuerySubscriptionStatusPayload::decode(&[0]).is_err());
    }

    #[test]
    fn subscription_status_response_roundtrip() {
        let payload = SubscriptionStatusResponsePayload { is_active: true, expiry_timestamp: 1_900_000_000 };
        let encoded = payload.encode();
        let decoded = SubscriptionStatusResponsePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn subscription_status_response_rejects_wrong_length() {
        assert!(SubscriptionStatusResponsePayload::decode(&[0, 1, 2]).is_err());
    }

    #[test]
    fn subscription_status_response_rejects_non_canonical_boolean() {
        let mut encoded = SubscriptionStatusResponsePayload { is_active: false, expiry_timestamp: 0 }.encode();
        encoded[0] = 7;
        assert!(SubscriptionStatusResponsePayload::decode(&encoded).is_err());
    }
}
