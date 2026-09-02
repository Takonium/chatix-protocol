use crate::error::ProtocolError;

pub const CHATIX_MAGIC: [u8; 4] = *b"CHTX";
pub const CHATIX_VERSION: u8 = 1;
pub const CHATIX_HEADER_LEN: u8 = 24;
pub const CHATIX_HEADER_SIZE: usize = CHATIX_HEADER_LEN as usize;
pub const MAX_PAYLOAD_LEN: u32 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub packet_type: u8,
    pub flags: u8,
    pub header_len: u8,
    pub payload_len: u32,
    pub sequence: u64,
    pub reserved: u32,
}

impl PacketHeader {
    pub fn new(packet_type: u8, flags: u8, payload_len: u32, sequence: u64) -> Self {
        Self {
            magic: CHATIX_MAGIC,
            version: CHATIX_VERSION,
            packet_type,
            flags,
            header_len: CHATIX_HEADER_LEN,
            payload_len,
            sequence,
            reserved: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; CHATIX_HEADER_SIZE] {
        let mut out = [0u8; CHATIX_HEADER_SIZE];
        out[0..4].copy_from_slice(&self.magic);
        out[4] = self.version;
        out[5] = self.packet_type;
        out[6] = self.flags;
        out[7] = self.header_len;
        out[8..12].copy_from_slice(&self.payload_len.to_be_bytes());
        out[12..20].copy_from_slice(&self.sequence.to_be_bytes());
        out[20..24].copy_from_slice(&self.reserved.to_be_bytes());
        out
    }

    pub fn from_bytes(bytes: [u8; CHATIX_HEADER_SIZE]) -> Self {
        Self {
            magic: [bytes[0], bytes[1], bytes[2], bytes[3]],
            version: bytes[4],
            packet_type: bytes[5],
            flags: bytes[6],
            header_len: bytes[7],
            payload_len: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            sequence: u64::from_be_bytes([
                bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18],
                bytes[19],
            ]),
            reserved: u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.magic != CHATIX_MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }
        if self.version != CHATIX_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        if self.header_len != CHATIX_HEADER_LEN {
            return Err(ProtocolError::InvalidHeaderLength);
        }
        if self.payload_len > MAX_PAYLOAD_LEN {
            return Err(ProtocolError::PayloadTooLarge {
                size: self.payload_len,
                max: MAX_PAYLOAD_LEN,
            });
        }
        if self.reserved != 0 {
            return Err(ProtocolError::ReservedFieldNonZero);
        }
        Ok(())
    }

    pub fn is_encrypted(&self) -> bool {
        (self.flags & flags::ENCRYPTED) != 0
    }
}

/// Bits of `PacketHeader::flags`.
///
/// Only `ENCRYPTED` is defined: earlier drafts also reserved bits for
/// ack-required/is-response/has-error signaling, but nothing in this crate
/// ever set or read them — those concerns are already handled by dedicated
/// packet types instead (`AckQueuedMessage`/`DeliveryReceipt`,
/// `AuthAccept`/`AuthReject`, `Error`), so the unused bits were removed
/// rather than kept as an implemented-looking API that did nothing. The
/// remaining 7 bits of this byte are free for future use.
pub mod flags {
    pub const ENCRYPTED: u8 = 1 << 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        // Exercise more than one flag bit round-tripping, not just ENCRYPTED
        // alone — 0b0000_0010 stands in for one of the currently-unused
        // reserved bits.
        let header = PacketHeader::new(10, flags::ENCRYPTED | 0b0000_0010, 128, 42);
        let bytes = header.to_bytes();
        let decoded = PacketHeader::from_bytes(bytes);
        assert_eq!(header, decoded);
    }

    #[test]
    fn header_validation_ok() {
        let header = PacketHeader::new(1, 0, 64, 1);
        assert!(header.validate().is_ok());
    }

    #[test]
    fn header_validation_invalid_magic() {
        let mut header = PacketHeader::new(1, 0, 64, 1);
        header.magic = *b"NOPE";
        assert!(header.validate().is_err());
    }

    #[test]
    fn header_validation_invalid_version() {
        let mut header = PacketHeader::new(1, 0, 64, 1);
        header.version = 99;
        assert!(header.validate().is_err());
    }

    #[test]
    fn header_validation_payload_too_large() {
        let header = PacketHeader::new(1, 0, MAX_PAYLOAD_LEN + 1, 1);
        assert!(header.validate().is_err());
    }

    #[test]
    fn header_validation_reserved_nonzero() {
        let mut header = PacketHeader::new(1, 0, 64, 1);
        header.reserved = 1;
        assert!(header.validate().is_err());
    }
}
