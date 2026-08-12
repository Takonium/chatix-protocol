use super::common::{decode_sized_bytes, decode_sized_string, encode_sized_bytes, encode_sized_string, require_fully_consumed};
use std::io::{self, Error, ErrorKind};

/// Sent by the client (in the Established state) to drain any messages the
/// server queued while the client was offline. Carries no fields — the
/// server identifies the caller from the already-authenticated connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchQueuedMessagesPayload;

impl FetchQueuedMessagesPayload {
    pub fn encode(&self) -> Vec<u8> {
        Vec::new()
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        require_fully_consumed(bytes, 0, "fetch_queued_messages")?;
        Ok(Self)
    }
}

/// Sent by the server for each message it had queued for this client.
/// `queue_id` identifies the row server-side so the client can ack it via AckQueuedMessage.
/// `message_id` is the original sender's ID, used for DeliveryReceipt so the
/// server can notify the sender that their offline message was delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedMessageDeliveryPayload {
    pub queue_id: u64,
    pub message_id: u64,
    pub sender_id: String,
    pub content: Vec<u8>,
}

impl QueuedMessageDeliveryPayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let sender = encode_sized_string(&self.sender_id)?;
        let content = encode_sized_bytes(&self.content)?;

        let mut out = Vec::with_capacity(16 + sender.len() + content.len());
        out.extend_from_slice(&self.queue_id.to_be_bytes());
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&sender);
        out.extend_from_slice(&content);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < 16 {
            return Err(Error::new(ErrorKind::InvalidData, "queued_message_delivery too short for ids"));
        }
        let queue_id = u64::from_be_bytes(bytes[..8].try_into().map_err(|_| {
            Error::new(ErrorKind::InvalidData, "failed to decode queued_message_delivery queue_id")
        })?);
        let message_id = u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| {
            Error::new(ErrorKind::InvalidData, "failed to decode queued_message_delivery message_id")
        })?);

        let (sender_id, sender_consumed) = decode_sized_string(&bytes[16..])?;
        let (content, content_consumed) = decode_sized_bytes(&bytes[16 + sender_consumed..])?;
        let consumed = 16usize
            .checked_add(sender_consumed)
            .and_then(|n| n.checked_add(content_consumed))
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "queued_message_delivery length overflow"))?;

        require_fully_consumed(bytes, consumed, "queued_message_delivery")?;

        Ok(Self { queue_id, message_id, sender_id, content })
    }
}

/// Sent by the client to confirm receipt of a QueuedMessageDeliveryPayload —
/// the server only deletes the queued row once this arrives, so a dropped
/// connection mid-delivery doesn't lose the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckQueuedMessagePayload {
    pub queue_id: u64,
}

impl AckQueuedMessagePayload {
    pub fn encode(&self) -> Vec<u8> {
        self.queue_id.to_be_bytes().to_vec()
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != 8 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("invalid ack_queued_message length: expected 8, got {}", bytes.len()),
            ));
        }
        let queue_id = u64::from_be_bytes(bytes.try_into().map_err(|_| {
            Error::new(ErrorKind::InvalidData, "failed to decode ack_queued_message queue_id")
        })?);
        Ok(Self { queue_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_queued_messages_roundtrip() {
        let payload = FetchQueuedMessagesPayload;
        let encoded = payload.encode();
        let decoded = FetchQueuedMessagesPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn fetch_queued_messages_rejects_nonempty_payload() {
        assert!(FetchQueuedMessagesPayload::decode(&[0]).is_err());
    }

    #[test]
    fn queued_message_delivery_roundtrip_keeps_content_opaque() {
        let payload = QueuedMessageDeliveryPayload {
            queue_id: 42,
            message_id: 1001,
            sender_id: "alice".to_string(),
            content: vec![0, 159, 255, 42],
        };
        let encoded = payload.encode().unwrap();
        let decoded = QueuedMessageDeliveryPayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn queued_message_delivery_rejects_trailing_bytes() {
        let mut encoded = QueuedMessageDeliveryPayload {
            queue_id: 1,
            message_id: 2,
            sender_id: "bob".to_string(),
            content: vec![1, 2, 3],
        }
        .encode()
        .unwrap();
        encoded.push(0);
        assert!(QueuedMessageDeliveryPayload::decode(&encoded).is_err());
    }

    #[test]
    fn queued_message_delivery_rejects_truncated_ids() {
        assert!(QueuedMessageDeliveryPayload::decode(&[0, 1, 2]).is_err());
    }

    #[test]
    fn ack_queued_message_roundtrip() {
        let payload = AckQueuedMessagePayload { queue_id: 7 };
        let encoded = payload.encode();
        let decoded = AckQueuedMessagePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn ack_queued_message_rejects_wrong_length() {
        assert!(AckQueuedMessagePayload::decode(&[0, 1, 2]).is_err());
    }
}