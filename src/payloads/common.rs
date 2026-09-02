use std::io::{self, Error, ErrorKind};
pub fn encode_sized_string(value: &str) -> io::Result<Vec<u8>> {
    let bytes = value.as_bytes();

    if bytes.len() > u16::MAX as usize {
        return Err(Error::new(ErrorKind::InvalidInput, "string too long"));
    }

    let mut out = Vec::with_capacity(2 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}

pub fn decode_sized_string(bytes: &[u8]) -> io::Result<(String, usize)> {
    if bytes.len() < 2 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "payload too short for string length",
        ));
    }

    let str_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    let end = 2usize
        .checked_add(str_len)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "string length overflow"))?;

    if bytes.len() < end {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "payload too short for string bytes",
        ));
    }

    let value = std::str::from_utf8(&bytes[2..end])
        .map_err(|_| Error::new(ErrorKind::InvalidData, "string is not valid UTF-8"))?
        .to_string();

    Ok((value, end))
}

#[allow(dead_code)]
pub fn encode_sized_bytes(bytes: &[u8]) -> io::Result<Vec<u8>> {
    if bytes.len() > u32::MAX as usize {
        return Err(Error::new(ErrorKind::InvalidInput, "bytes too long"));
    }

    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}

#[allow(dead_code)]
pub fn decode_sized_bytes(bytes: &[u8]) -> io::Result<(Vec<u8>, usize)> {
    if bytes.len() < 4 {
        return Err(Error::new(ErrorKind::InvalidData, "missing length"));
    }

    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let end = 4usize
        .checked_add(len)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "byte length overflow"))?;

    if bytes.len() < end {
        return Err(Error::new(ErrorKind::InvalidData, "not enough bytes"));
    }

    Ok((bytes[4..end].to_vec(), end))
}

pub fn require_fully_consumed(bytes: &[u8], consumed: usize, payload_name: &str) -> io::Result<()> {
    if bytes.len() != consumed {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("{payload_name} payload length mismatch"),
        ));
    }

    Ok(())
}

pub fn decode_bool(value: u8, field_name: &str) -> io::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::new(
            ErrorKind::InvalidData,
            format!("{field_name} must be encoded as 0 or 1"),
        )),
    }
}
