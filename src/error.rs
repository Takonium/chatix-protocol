use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid magic bytes")]
    InvalidMagic,

    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("invalid header length")]
    InvalidHeaderLength,

    #[error("payload too large: {size} bytes (max {max})")]
    PayloadTooLarge { size: u32, max: u32 },

    #[error("reserved field must be zero")]
    ReservedFieldNonZero,

    #[error("unknown packet type: {0}")]
    UnknownPacketType(u8),

    #[error("invalid packet type for current connection state")]
    InvalidStateTransition,

    #[error("payload decode error in {packet}: {reason}")]
    PayloadDecode {
        packet: &'static str,
        reason: String,
    },

    #[error("sequence number violation: got {got}, last seen {last}")]
    SequenceViolation { got: u64, last: u64 },

    #[error("payload length mismatch")]
    PayloadLengthMismatch,

    #[error("cryptographic operation failed")]
    CryptoError,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}