use super::common::{
    decode_sized_bytes, decode_sized_string, encode_sized_bytes, encode_sized_string,
};
use std::io::{self, Error, ErrorKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendMessagePayload {
    pub recipient_id: String,
    pub content: Vec<u8>,
}
impl SendMessagePayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let recipient = encode_sized_string(&self.recipient_id)?;
        let content = encode_sized_bytes(&self.content)?;

        let mut out = Vec::with_capacity(recipient.len() + content.len());
        out.extend_from_slice(&recipient);
        out.extend_from_slice(&content);

        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (recipient_id, recipient_consumed) = decode_sized_string(bytes)?;
        let (content, content_consumed) = decode_sized_bytes(&bytes[recipient_consumed..])?;
        let consumed = recipient_consumed
            .checked_add(content_consumed)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "send_message length overflow"))?;

        if bytes.len() != consumed {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "send_message payload length mismatch",
            ));
        }

        Ok(Self {
            recipient_id,
            content,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliverMessagePayload {
    pub sender_id: String,
    pub content: Vec<u8>,
}

impl DeliverMessagePayload {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let sender = encode_sized_string(&self.sender_id)?;
        let content = encode_sized_bytes(&self.content)?;

        let mut out = Vec::with_capacity(sender.len() + content.len());
        out.extend_from_slice(&sender);
        out.extend_from_slice(&content);

        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let (sender_id, sender_consumed) = decode_sized_string(bytes)?;
        let (content, content_consumed) = decode_sized_bytes(&bytes[sender_consumed..])?;
        let consumed = sender_consumed
            .checked_add(content_consumed)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "deliver_message length overflow"))?;

        if bytes.len() != consumed {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "deliver_message payload length mismatch",
            ));
        }

        Ok(Self { sender_id, content })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_message_roundtrip_keeps_content_opaque() {
        let payload = SendMessagePayload {
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
            recipient_id: "bob".to_string(),
            content: vec![1, 2, 3],
        }
        .encode()
        .unwrap();
        encoded.push(0);

        assert!(SendMessagePayload::decode(&encoded).is_err());
    }

    #[test]
    fn deliver_message_roundtrip_keeps_content_opaque() {
        let payload = DeliverMessagePayload {
            sender_id: "alice".to_string(),
            content: vec![7, 8, 9],
        };

        let encoded = payload.encode().unwrap();
        let decoded = DeliverMessagePayload::decode(&encoded).unwrap();

        assert_eq!(decoded, payload);
    }
}