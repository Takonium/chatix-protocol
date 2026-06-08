use ring::aead::{self, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

use crate::error::ProtocolError;
use crate::header::{PacketHeader, CHATIX_HEADER_SIZE, flags};
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
        self.session = Some(SessionCipher { outbound_key, inbound_key });
    }

    pub async fn read_packet<R>(&mut self, reader: &mut R) -> Result<RawPacket, ProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        let mut header_bytes = [0u8; CHATIX_HEADER_SIZE];
        reader.read_exact(&mut header_bytes).await?;

        let mut header = PacketHeader::from_bytes(header_bytes);
        header.validate()?;

        // Reject unknown packet types immediately.
        PacketType::from_u8(header.packet_type)?;

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
                    aead::Aad::empty(),
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
            let nonce = seq_nonce(seq);
            let key = UnboundKey::new(&AES_256_GCM, &cipher.outbound_key)
                .map_err(|_| ProtocolError::CryptoError)?;
            let sealing_key = LessSafeKey::new(key);
            sealing_key
                .seal_in_place_append_tag(
                    Nonce::assume_unique_for_key(nonce),
                    aead::Aad::empty(),
                    &mut payload,
                )
                .map_err(|_| ProtocolError::CryptoError)?;
            // Signal to the receiver that this frame is encrypted.
            flags |= flags::ENCRYPTED;
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
