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

    /// Returned by `PacketCodec::read_packet` when a session has been
    /// established but an incoming packet arrives without the `ENCRYPTED`
    /// flag set. Distinct from `CryptoError` (which means a decrypt/verify
    /// operation was attempted and failed) because here no cryptographic
    /// operation runs at all — the packet is rejected purely for violating
    /// the "once established, everything is encrypted" invariant, which is
    /// what stops a network attacker from injecting a plaintext, fully
    /// attacker-controlled packet into an otherwise-encrypted session.
    #[error("packet must be encrypted: a session is established but this packet was not")]
    EncryptionRequired,

    #[error("cryptographic operation failed")]
    CryptoError,

    #[error("identity key for '{identifier}' changed since it was last pinned")]
    IdentityKeyChanged { identifier: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
