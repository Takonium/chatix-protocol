use super::header::PacketHeader;
use super::packet_type::PacketType;

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

#[derive(Debug, Clone)]
pub struct OutboundPacket {
    pub packet_type: PacketType,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl OutboundPacket {
    pub fn new(packet_type: PacketType, flags: u8, payload: Vec<u8>) -> Self {
        Self {
            packet_type,
            flags,
            payload,
        }
    }
}