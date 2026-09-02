use ring::aead::{self, AES_256_GCM, LessSafeKey, Nonce, UnboundKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

use crate::crypto::e2e::GCM_TAG_LEN;
use crate::error::ProtocolError;
use crate::header::{CHATIX_HEADER_SIZE, PacketHeader, flags};
use crate::packet_type::PacketType;
use crate::raw_packet::RawPacket;

/// Stateful codec for a single connection.
///
/// Responsibilities:
///   - Validates and enforces monotonically increasing sequence numbers on inbound packets.
///   - Assigns monotonically increasing sequence numbers to outbound packets.
///   - Applies AES-256-GCM session-layer encryption once `establish_session` has been called.
///
/// Call `establish_session` immediately after the handshake completes.
/// The outbound/inbound key assignment depends on the caller's role:
///   - Client: `establish_session(keys.client_to_server, keys.server_to_client)`
///   - Server: `establish_session(keys.server_to_client, keys.client_to_server)`
pub struct PacketCodec {
    last_recv_seq: Option<u64>,
    next_send_seq: u64,
    session: Option<SessionCipher>,
}

struct SessionCipher {
    outbound_key: [u8; 32],
    inbound_key: [u8; 32],
}

impl Drop for SessionCipher {
    fn drop(&mut self) {
        self.outbound_key.zeroize();
        self.inbound_key.zeroize();
    }
}

impl PacketCodec {
    pub fn new() -> Self {
        Self {
            last_recv_seq: None,
            next_send_seq: 1,
            session: None,
        }
    }

    /// Activates session-layer encryption.
    ///
    /// `outbound_key` encrypts packets this side sends.
    /// `inbound_key` decrypts packets this side receives.
    pub fn establish_session(&mut self, outbound_key: [u8; 32], inbound_key: [u8; 32]) {
        self.session = Some(SessionCipher {
            outbound_key,
            inbound_key,
        });
    }

    pub async fn read_packet<R>(&mut self, reader: &mut R) -> Result<RawPacket, ProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        let mut header_bytes = [0u8; CHATIX_HEADER_SIZE];
        reader.read_exact(&mut header_bytes).await?;

        let mut header = PacketHeader::from_bytes(header_bytes);
        header.validate()?;

        // Once a session is established, every incoming packet must be
        // encrypted — there is no legitimate reason for a plaintext packet
        // to arrive after this point. Without this check, a network
        // attacker who cannot decrypt or forge anything could still inject
        // a plaintext packet with the ENCRYPTED flag simply left unset, and
        // this codec would hand it to the caller as if it were genuine,
        // fully bypassing the session's confidentiality and authenticity
        // guarantees for that packet.
        if self.session.is_some() && !header.is_encrypted() {
            return Err(ProtocolError::EncryptionRequired);
        }

        // Reject unknown packet types immediately.
        let packet_type = PacketType::from_u8(header.packet_type)?;

        // Enforce the per-packet-type payload ceiling, not just the global
        // MAX_PAYLOAD_LEN cap. Encrypted frames carry an extra GCM_TAG_LEN
        // bytes of ciphertext overhead over the plaintext limit.
        let max_for_type = if header.is_encrypted() {
            packet_type
                .max_payload_size()
                .saturating_add(GCM_TAG_LEN as u32)
        } else {
            packet_type.max_payload_size()
        };
        if header.payload_len > max_for_type {
            return Err(ProtocolError::PayloadTooLarge {
                size: header.payload_len,
                max: max_for_type,
            });
        }

        self.validate_sequence(header.sequence)?;

        let mut payload = vec![0u8; header.payload_len as usize];
        if header.payload_len > 0 {
            reader.read_exact(&mut payload).await?;
        }

        if header.is_encrypted() {
            let cipher = self.session.as_ref().ok_or(ProtocolError::CryptoError)?;

            // Nonce is derived from the sequence number — unique per packet as long as
            // sequence numbers are monotonically increasing.
            let nonce = seq_nonce(header.sequence);
            let key = UnboundKey::new(&AES_256_GCM, &cipher.inbound_key)
                .map_err(|_| ProtocolError::CryptoError)?;
            let opening_key = LessSafeKey::new(key);
            let plaintext_len = opening_key
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    aead::Aad::from(header_aad(header.packet_type, header.flags)),
                    &mut payload,
                )
                .map_err(|_| ProtocolError::CryptoError)?
                .len();
            payload.truncate(plaintext_len);

            // Correct the header length so callers see consistent plaintext length.
            header.payload_len = plaintext_len as u32;
        }

        Ok(RawPacket::new(header, payload))
    }

    pub async fn write_packet<W>(
        &mut self,
        writer: &mut W,
        packet_type: PacketType,
        mut flags: u8,
        mut payload: Vec<u8>,
    ) -> Result<(), ProtocolError>
    where
        W: AsyncWrite + Unpin,
    {
        let seq = self.next_send_seq;
        self.next_send_seq = self
            .next_send_seq
            .checked_add(1)
            .ok_or(ProtocolError::CryptoError)?;

        if let Some(ref cipher) = self.session {
            // Set ENCRYPTED before sealing (not after) so the AAD below
            // binds the exact flags byte the receiver will read off the
            // wire — sealing and opening must derive identical AAD from
            // identical header bytes for the tag to verify.
            flags |= flags::ENCRYPTED;

            let nonce = seq_nonce(seq);
            let key = UnboundKey::new(&AES_256_GCM, &cipher.outbound_key)
                .map_err(|_| ProtocolError::CryptoError)?;
            let sealing_key = LessSafeKey::new(key);
            sealing_key
                .seal_in_place_append_tag(
                    Nonce::assume_unique_for_key(nonce),
                    aead::Aad::from(header_aad(packet_type.as_u8(), flags)),
                    &mut payload,
                )
                .map_err(|_| ProtocolError::CryptoError)?;
        }

        let header = PacketHeader::new(packet_type.as_u8(), flags, payload.len() as u32, seq);

        writer.write_all(&header.to_bytes()).await?;
        writer.write_all(&payload).await?;
        writer.flush().await?;

        Ok(())
    }

    fn validate_sequence(&mut self, seq: u64) -> Result<(), ProtocolError> {
        if let Some(last) = self.last_recv_seq {
            if seq <= last {
                return Err(ProtocolError::SequenceViolation { got: seq, last });
            }
        }
        self.last_recv_seq = Some(seq);
        Ok(())
    }
}

impl Default for PacketCodec {
    fn default() -> Self {
        Self::new()
    }
}

/// Derives a 12-byte AES-GCM nonce from the packet sequence number.
///
/// The first 4 bytes are zero (reserved for future direction bits or similar).
/// Uniqueness is guaranteed by the monotonically increasing sequence number.
fn seq_nonce(seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// Additional authenticated data (AAD) bound into the AES-GCM tag for an
/// encrypted frame.
///
/// The packet header travels in the clear (it has to — the receiver needs
/// `packet_type` and `flags` before it can even locate, let alone decrypt,
/// the payload), so without this the AEAD tag would only protect the
/// payload bytes: an on-path attacker could take a legitimately-encrypted,
/// correctly-tagged packet and relabel its `packet_type` in transit,
/// causing the receiver to decrypt successfully (the ciphertext and tag
/// are untouched) and then misinterpret the payload as a different message
/// type than the sender intended — a type-confusion attack that costs the
/// attacker nothing cryptographically. Binding `packet_type` and `flags`
/// into the AAD makes any such relabeling invalidate the tag instead.
///
/// `sequence` doesn't need to be included here: it already determines the
/// AES-GCM nonce (`seq_nonce`), so tampering with it makes the receiver
/// derive the wrong nonce and fail to open the ciphertext regardless.
fn header_aad(packet_type: u8, flags: u8) -> [u8; 2] {
    [packet_type, flags]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::CHATIX_HEADER_LEN;
    use std::io::Cursor;

    /// Hand-builds a raw (unencrypted) frame: header + payload bytes.
    fn raw_frame(packet_type: u8, payload_len: u32, seq: u64) -> Vec<u8> {
        let header = PacketHeader::new(packet_type, 0, payload_len, seq);
        let mut bytes = header.to_bytes().to_vec();
        bytes.extend(std::iter::repeat(0xAA).take(payload_len as usize));
        bytes
    }

    #[tokio::test]
    async fn rejects_oversized_payload_for_packet_type() {
        // Ping (type 20) has a declared max of 8 bytes, well under the
        // global MAX_PAYLOAD_LEN — a codec that only checks the global
        // cap would wrongly accept this.
        let oversized = CHATIX_HEADER_LEN as u32; // arbitrary, > 8
        let frame = raw_frame(PacketType::Ping.as_u8(), oversized, 1);
        let mut cursor = Cursor::new(frame);
        let mut codec = PacketCodec::new();

        let result = codec.read_packet(&mut cursor).await;
        assert!(matches!(result, Err(ProtocolError::PayloadTooLarge { .. })));
    }

    #[tokio::test]
    async fn accepts_payload_within_packet_type_limit() {
        let frame = raw_frame(PacketType::Ping.as_u8(), 8, 1);
        let mut cursor = Cursor::new(frame);
        let mut codec = PacketCodec::new();

        let packet = codec.read_packet(&mut cursor).await.unwrap();
        assert_eq!(packet.header.payload_len, 8);
    }

    /// A pair of distinct 32-byte keys standing in for a real HKDF-derived
    /// `SessionKeys` pair, so tests don't need to run the full handshake.
    fn sample_session_keys() -> ([u8; 32], [u8; 32]) {
        ([0x11u8; 32], [0x22u8; 32])
    }

    #[tokio::test]
    async fn encrypted_roundtrip_succeeds() {
        let (key_a, key_b) = sample_session_keys();

        let mut sender = PacketCodec::new();
        sender.establish_session(key_a, key_b);

        let mut wire_bytes = Vec::new();
        let plaintext = b"PINGDATA".to_vec(); // 8 bytes: Ping's plaintext limit
        sender
            .write_packet(&mut wire_bytes, PacketType::Ping, 0, plaintext.clone())
            .await
            .unwrap();

        // Receiver's inbound key (key_a) must match the sender's outbound
        // key (key_a) for this to decrypt — same pairing convention
        // `establish_session`'s doc comment describes for client/server.
        let mut receiver = PacketCodec::new();
        receiver.establish_session(key_b, key_a);

        let mut cursor = Cursor::new(wire_bytes);
        let packet = receiver.read_packet(&mut cursor).await.unwrap();

        assert!(packet.header.is_encrypted());
        assert_eq!(packet.payload, plaintext);
    }

    #[tokio::test]
    async fn rejects_unencrypted_packet_once_session_established() {
        // Simulates a network attacker injecting a plaintext packet into a
        // connection that should be fully encrypted post-handshake — the
        // attacker has no key, but until this check existed, the codec
        // would still accept it as long as ENCRYPTED was left unset.
        let (key_a, key_b) = sample_session_keys();
        let mut receiver = PacketCodec::new();
        receiver.establish_session(key_b, key_a);

        let injected = raw_frame(PacketType::Ping.as_u8(), 8, 1); // flags = 0, not encrypted
        let mut cursor = Cursor::new(injected);

        let result = receiver.read_packet(&mut cursor).await;
        assert!(matches!(result, Err(ProtocolError::EncryptionRequired)));
    }

    #[tokio::test]
    async fn rejects_packet_with_tampered_packet_type_after_encryption() {
        // Demonstrates the header-AAD fix: DeliveryReceipt and
        // AckQueuedMessage both have an 8-byte plaintext shape, so relabeling
        // one as the other in transit must invalidate the AEAD tag rather
        // than silently letting the receiver misinterpret the payload.
        let (key_a, key_b) = sample_session_keys();

        let mut sender = PacketCodec::new();
        sender.establish_session(key_a, key_b);

        let mut wire_bytes = Vec::new();
        sender
            .write_packet(
                &mut wire_bytes,
                PacketType::DeliveryReceipt,
                0,
                vec![0u8; 8],
            )
            .await
            .unwrap();

        // Byte 5 of the header is packet_type (see PacketHeader::to_bytes).
        wire_bytes[5] = PacketType::AckQueuedMessage.as_u8();

        let mut receiver = PacketCodec::new();
        receiver.establish_session(key_b, key_a);

        let mut cursor = Cursor::new(wire_bytes);
        let result = receiver.read_packet(&mut cursor).await;
        assert!(matches!(result, Err(ProtocolError::CryptoError)));
    }
}
