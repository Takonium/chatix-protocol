use super::common::{decode_bool, decode_sized_string, encode_sized_string, require_fully_consumed};
use std::io::{self, Error, ErrorKind};

/// Sent by the client (in the Established state, after registration) to ask
/// the server for this device's account status. Carries no fields — the
/// server identifies the caller from the already-authenticated connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryAccountStatusPayload;

impl QueryAccountStatusPayload {
    pub fn encode(&self) -> Vec<u8> {
        Vec::new()
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        require_fully_consumed(bytes, 0, "query_account_status")?;
        Ok(Self)
    }
}

/// Sent by the server in response to QueryAccountStatusPayload.
///
/// `ban_reason` is only meaningful when `is_banned` is true, and may be empty
/// if the server has no reason on file. Unlike AuthRejectPayload (generic by
/// design, to avoid leaking anything during the anonymous handshake), this is
/// returned only to the already-authenticated owner of the account, so it's
/// fine for it to be informative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountStatusResponsePayload {
    pub is_banned: bool,
    pub ban_reason: String,
    pub subscription_active: bool,
    /// Unix timestamp (seconds) when the subscription expires. Meaningless
    /// when `subscription_active` is false.
    pub subscription_expiry_timestamp: u64,
}

impl AccountStatusResponsePayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let ban_reason = encode_sized_string(&self.ban_reason)?;
        let mut out = Vec::with_capacity(1 + ban_reason.len() + 1 + 8);
        out.push(if self.is_banned { 1 } else { 0 });
        out.extend_from_slice(&ban_reason);
        out.push(if self.subscription_active { 1 } else { 0 });
        out.extend_from_slice(&self.subscription_expiry_timestamp.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() {
            return Err(Error::new(ErrorKind::InvalidData, "account_status_response payload too short"));
        }
        let is_banned = decode_bool(bytes[0], "account_status_response is_banned")?;
        let (ban_reason, consumed) = decode_sized_string(&bytes[1..])?;

        let rest = &bytes[1 + consumed..];
        if rest.len() != 9 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "account_status_response missing subscription fields",
            ));
        }
        let subscription_active = decode_bool(rest[0], "account_status_response subscription_active")?;
        let subscription_expiry_timestamp = u64::from_be_bytes(rest[1..9].try_into().map_err(|_| {
            Error::new(ErrorKind::InvalidData, "failed to decode account_status_response expiry")
        })?);

        require_fully_consumed(bytes, 1 + consumed + 9, "account_status_response")?;

        Ok(Self { is_banned, ban_reason, subscription_active, subscription_expiry_timestamp })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_account_status_roundtrip() {
        let payload = QueryAccountStatusPayload;
        let encoded = payload.encode();
        let decoded = QueryAccountStatusPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn query_account_status_rejects_nonempty_payload() {
        assert!(QueryAccountStatusPayload::decode(&[0]).is_err());
    }

    #[test]
    fn account_status_response_roundtrip_not_banned() {
        let payload = AccountStatusResponsePayload {
            is_banned: false,
            ban_reason: String::new(),
            subscription_active: true,
            subscription_expiry_timestamp: 1_900_000_000,
        };
        let encoded = payload.encode().unwrap();
        let decoded = AccountStatusResponsePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn account_status_response_roundtrip_banned_with_reason() {
        let payload = AccountStatusResponsePayload {
            is_banned: true,
            ban_reason: "spam".to_string(),
            subscription_active: false,
            subscription_expiry_timestamp: 0,
        };
        let encoded = payload.encode().unwrap();
        let decoded = AccountStatusResponsePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn account_status_response_rejects_empty_payload() {
        assert!(AccountStatusResponsePayload::decode(&[]).is_err());
    }

    #[test]
    fn account_status_response_rejects_non_canonical_boolean() {
        let mut encoded = AccountStatusResponsePayload {
            is_banned: false,
            ban_reason: String::new(),
            subscription_active: true,
            subscription_expiry_timestamp: 0,
        }
        .encode()
        .unwrap();
        encoded[0] = 7;
        assert!(AccountStatusResponsePayload::decode(&encoded).is_err());
    }

    #[test]
    fn account_status_response_rejects_trailing_bytes() {
        let mut encoded = AccountStatusResponsePayload {
            is_banned: false,
            ban_reason: String::new(),
            subscription_active: true,
            subscription_expiry_timestamp: 0,
        }
        .encode()
        .unwrap();
        encoded.push(0);
        assert!(AccountStatusResponsePayload::decode(&encoded).is_err());
    }

    #[test]
    fn account_status_response_rejects_truncated_subscription_fields() {
        let payload = AccountStatusResponsePayload {
            is_banned: false,
            ban_reason: String::new(),
            subscription_active: true,
            subscription_expiry_timestamp: 0,
        };
        let mut encoded = payload.encode().unwrap();
        encoded.truncate(encoded.len() - 1);
        assert!(AccountStatusResponsePayload::decode(&encoded).is_err());
    }
}
