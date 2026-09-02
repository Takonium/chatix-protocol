use super::header::PacketHeader;

#[derive(Debug, Clone)]
pub struct RawPacket {
    pub header: PacketHeader,
    pub payload: Vec<u8>,
}

impl RawPacket {
    pub fn new(header: PacketHeader, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }
}
