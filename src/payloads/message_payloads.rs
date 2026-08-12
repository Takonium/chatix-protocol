use super::common::{
    decode_sized_bytes, decode_sized_string, encode_sized_bytes, encode_sized_string,
};
use std::io::{self, Error, ErrorKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendMessagePayload {
    /// Client-generated ID, unique per session. Used to track delivery status.
    pub message_id: u64,
    pub recipient_id: String,
    pub content: Vec<u8>,
}

impl SendMessagePayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let recipient = encode_sized_string(&self.recipient_id)?;
        let content = encode_sized_bytes(&self.content)?;

        let mut out = Vec::with_capacity(8 + recipient.len() + content.len());
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&recipient);
        out.extend_from_slice(&content);

        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < 8 {
            return Err(Error::new(ErrorKind::InvalidData, "send_message too short for message_id"));
        }
        let message_id = u64::from_be_bytes(bytes[..8].try_into().map_err(|_| {
            Error::new(ErrorKind::InvalidData, "failed to decode send_message message_id")
        })?);

        let (recipient_id, recipient_consumed) = decode_sized_string(&bytes[8..])?;
        let (content, content_consumed) = decode_sized_bytes(&bytes[8 + recipient_consumed..])?;
        let consumed = 8usize
            .checked_add(recipient_consumed)
            .and_then(|n| n.checked_add(content_consumed))
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "send_message length overflow"))?;

        if bytes.len() != consumed {
            return Err(Error::new(ErrorKind::InvalidData, "send_message payload length mismatch"));
        }

        Ok(Self { message_id, recipient_id, content })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliverMessagePayload {
    /// Same ID the sender placed in SendMessagePayload — used for DeliveryReceipt.
    pub message_id: u64,
    pub sender_id: String,
    pub content: Vec<u8>,
}

impl DeliverMessagePayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let sender = encode_sized_string(&self.sender_id)?;
        let content = encode_sized_bytes(&self.content)?;

        let mut out = Vec::with_capacity(8 + sender.len() + content.len());
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&sender);
        out.extend_from_slice(&content);

        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < 8 {
            return Err(Error::new(ErrorKind::InvalidData, "deliver_message too short for message_id"));
        }
        let message_id = u64::from_be_bytes(bytes[..8].try_into().map_err(|_| {
            Error::new(ErrorKind::InvalidData, "failed to decode deliver_message message_id")
        })?);

        let (sender_id, sender_consumed) = decode_sized_string(&bytes[8..])?;
        let (content, content_consumed) = decode_sized_bytes(&bytes[8 + sender_consumed..])?;
        let consumed = 8usize
            .checked_add(sender_consumed)
            .and_then(|n| n.checked_add(content_consumed))
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "deliver_message length overflow"))?;

        if bytes.len() != consumed {
            return Err(Error::new(ErrorKind::InvalidData, "deliver_message payload length mismatch"));
        }

        Ok(Self { message_id, sender_id, content })
    }
}

/// Status values for MessageStatusUpdatePayload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageStatus {
    /// Server received the message from the sender.
    SentToServer = 0,
    /// Recipient's client acknowledged receipt via DeliveryReceipt.
    Delivered = 1,
    /// Server could not deliver the message (e.g. recipient not found or rejected).
    Failed = 2,
}

impl MessageStatus {
    fn from_u8(v: u8) -> io::Result<Self> {
        match v {
            0 => Ok(Self::SentToServer),
            1 => Ok(Self::Delivered),
            2 => Ok(Self::Failed),
            _ => Err(Error::new(ErrorKind::InvalidData, "unknown message_status value")),
        }
    }
}

/// Sent by the server to the original sender to report a status change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageStatusUpdatePayload {
    pub message_id: u64,
    pub status: MessageStatus,
}

impl MessageStatusUpdatePayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9);
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.push(self.status as u8);
        out
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != 9 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("message_status_update must be 9 bytes, got {}", bytes.len()),
            ));
        }
        let message_id = u64::from_be_bytes(bytes[..8].try_into().map_err(|_| {
            Error::new(ErrorKind::InvalidData, "failed to decode message_status_update message_id")
        })?);
        let status = MessageStatus::from_u8(bytes[8])?;
        Ok(Self { message_id, status })
    }
}

/// Sent by the recipient to the server to confirm a message was received.
/// The server uses this to send MessageStatusUpdate(Delivered) to the original sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReceiptPayload {
    pub message_id: u64,
}

impl DeliveryReceiptPayload {
    pub fn encode(&self) -> Vec<u8> {
        self.message_id.to_be_bytes().to_vec()
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != 8 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("delivery_receipt must be 8 bytes, got {}", bytes.len()),
            ));
        }
        let message_id = u64::from_be_bytes(bytes.try_into().map_err(|_| {
            Error::new(ErrorKind::InvalidData, "failed to decode delivery_receipt message_id")
        })?);
        Ok(Self { message_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_message_roundtrip() {
        let payload = SendMessagePayload {
            message_id: 1001,
            recipient_id: "bob-1".to_string(),
            content: vec![0, 159, 255, 42],
        };
        let encoded = payload.encode().unwrap();
        let decoded = SendMessagePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn send_message_rejects_trailing_bytes() {
        let mut encoded = SendMessagePayload {
            message_id: 1,
            recipient_id: "bob".to_string(),
            content: vec![1, 2, 3],
        }
        .encode()
        .unwrap();
        encoded.push(0);
        assert!(SendMessagePayload::decode(&encoded).is_err());
    }

    #[test]
    fn send_message_rejects_truncated_message_id() {
        assert!(SendMessagePayload::decode(&[0, 1, 2]).is_err());
    }

    #[test]
    fn deliver_message_roundtrip() {
        let payload = DeliverMessagePayload {
            message_id: 9999,
            sender_id: "alice".to_string(),
            content: vec![7, 8, 9],
        };
        let encoded = payload.encode().unwrap();
        let decoded = DeliverMessagePayload::decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn message_status_update_roundtrip_all_statuses() {
        for status in [MessageStatus::SentToServer, MessageStatus::Delivered, MessageStatus::Failed] {
            let p = MessageStatusUpdatePayload { message_id: 42, status };
            let decoded = MessageStatusUpdatePayload::decode(&p.encode()).unwrap();
            assert_eq!(decoded, p);
        }
    }

    #[test]
    fn message_status_update_rejects_unknown_status() {
        let mut enc = MessageStatusUpdatePayload { message_id: 1, status: MessageStatus::Delivered }.encode();
        *enc.last_mut().unwrap() = 9;
        assert!(MessageStatusUpdatePayload::decode(&enc).is_err());
    }

    #[test]
    fn message_status_update_rejects_wrong_length() {
        assert!(MessageStatusUpdatePayload::decode(&[0u8; 8]).is_err());
        assert!(MessageStatusUpdatePayload::decode(&[0u8; 10]).is_err());
    }

    #[test]
    fn delivery_receipt_roundtrip() {
        let p = DeliveryReceiptPayload { message_id: 777 };
        let decoded = DeliveryReceiptPayload::decode(&p.encode()).unwrap();
        assert_eq!(decoded, p);
    }

    #[test]
    fn delivery_receipt_rejects_wrong_length() {
        assert!(DeliveryReceiptPayload::decode(&[0u8; 7]).is_err());
        assert!(DeliveryReceiptPayload::decode(&[0u8; 9]).is_err());
    }
}