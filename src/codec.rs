use std::io::{self, Error, ErrorKind};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{header::PacketHeader, raw_packet::RawPacket};

pub async fn read_packet<R>(reader: &mut R) -> io::Result<RawPacket>
where
    R: AsyncRead + Unpin,
{
    let mut header_bytes = [0u8; 24];
    reader.read_exact(&mut header_bytes).await?;

    let header = PacketHeader::from_bytes(header_bytes);
    header.validate()?;

    let mut payload = vec![0u8; header.payload_len as usize];

    if header.payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }

    Ok(RawPacket::new(header, payload))
}

pub async fn write_packet<W>(writer: &mut W, packet: &RawPacket) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if packet.payload.len() != packet.header.payload_len as usize {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "payload length mismatch",
        ));
    }

    writer.write_all(&packet.header.to_bytes()).await?;
    writer.write_all(&packet.payload).await?;
    writer.flush().await?;

    Ok(())
}