use crate::{Error, Result};
use serde_json::Value;

pub(crate) const MAX_MESSAGE_LEN: usize = 1_048_576;
const HEADER_LEN: usize = 4;
const LEN_MASK: u32 = 0x00ff_ffff;
const ID_MASK: u32 = 0x7f00_0000;
const ID_SHIFT: u32 = 24;
const EXTENDED: u32 = 0x8000_0000;

pub(crate) const BLOBMSG_ARRAY: u8 = 1;
pub(crate) const BLOBMSG_TABLE: u8 = 2;
pub(crate) const BLOBMSG_STRING: u8 = 3;
pub(crate) const BLOBMSG_INT64: u8 = 4;
pub(crate) const BLOBMSG_INT32: u8 = 5;
pub(crate) const BLOBMSG_INT8: u8 = 7;
pub(crate) const BLOBMSG_DOUBLE: u8 = 8;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Attr<'a> {
    pub id: u8,
    pub extended: bool,
    pub payload: &'a [u8],
    pub raw_len: usize,
    pub padded_len: usize,
}

pub(crate) fn align4(value: usize) -> Result<usize> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(Error::InvalidData("blob length overflow"))
}

pub(crate) fn parse_attr(bytes: &[u8]) -> Result<Attr<'_>> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::InvalidData("truncated blob attribute"));
    }
    let encoded = u32::from_be_bytes(bytes[..4].try_into().unwrap());
    let raw_len = (encoded & LEN_MASK) as usize;
    if raw_len < HEADER_LEN || raw_len > bytes.len() || raw_len > MAX_MESSAGE_LEN {
        return Err(Error::InvalidData("invalid blob attribute length"));
    }
    let padded_len = align4(raw_len)?;
    if padded_len > bytes.len() {
        return Err(Error::InvalidData("truncated blob padding"));
    }
    Ok(Attr {
        id: ((encoded & ID_MASK) >> ID_SHIFT) as u8,
        extended: encoded & EXTENDED != 0,
        payload: &bytes[HEADER_LEN..raw_len],
        raw_len,
        padded_len,
    })
}

pub(crate) fn parse_attr_list(mut bytes: &[u8]) -> Result<Vec<Attr<'_>>> {
    let mut attrs = Vec::new();
    while !bytes.is_empty() {
        let attr = parse_attr(bytes)?;
        if bytes[attr.raw_len..attr.padded_len]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(Error::InvalidData("non-zero blob padding"));
        }
        bytes = &bytes[attr.padded_len..];
        attrs.push(attr);
    }
    Ok(attrs)
}

pub(crate) fn encode_attr(id: u8, extended: bool, payload: &[u8]) -> Result<Vec<u8>> {
    if id > 0x7f {
        return Err(Error::InvalidData("blob attribute id exceeds 7 bits"));
    }
    let raw_len = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(Error::InvalidData("blob length overflow"))?;
    if raw_len > LEN_MASK as usize || raw_len > MAX_MESSAGE_LEN {
        return Err(Error::InvalidData("blob attribute is too large"));
    }
    let padded_len = align4(raw_len)?;
    let mut encoded = ((id as u32) << ID_SHIFT) | raw_len as u32;
    if extended {
        encoded |= EXTENDED;
    }
    let mut result = Vec::with_capacity(padded_len);
    result.extend_from_slice(&encoded.to_be_bytes());
    result.extend_from_slice(payload);
    result.resize(padded_len, 0);
    Ok(result)
}

pub(crate) fn encode_root(payload: &[u8]) -> Result<Vec<u8>> {
    encode_attr(0, false, payload)
}

pub(crate) fn encode_u32_attr(id: u8, value: u32) -> Result<Vec<u8>> {
    encode_attr(id, false, &value.to_be_bytes())
}

pub(crate) fn encode_string_attr(id: u8, value: &str) -> Result<Vec<u8>> {
    if value.as_bytes().contains(&0) {
        return Err(Error::InteriorNul);
    }
    let mut payload = Vec::with_capacity(value.len() + 1);
    payload.extend_from_slice(value.as_bytes());
    payload.push(0);
    encode_attr(id, false, &payload)
}

fn blobmsg_header(name: &str) -> Result<Vec<u8>> {
    if name.as_bytes().contains(&0) || name.len() > u16::MAX as usize {
        return Err(Error::InvalidData("invalid blobmsg field name"));
    }
    let header_len = align4(2 + name.len() + 1)?;
    let mut header = Vec::with_capacity(header_len);
    header.extend_from_slice(&(name.len() as u16).to_be_bytes());
    header.extend_from_slice(name.as_bytes());
    header.push(0);
    header.resize(header_len, 0);
    Ok(header)
}

pub(crate) fn encode_blobmsg_field(kind: u8, name: &str, data: &[u8]) -> Result<Vec<u8>> {
    let mut payload = blobmsg_header(name)?;
    payload.extend_from_slice(data);
    encode_attr(kind, true, &payload)
}

fn encode_json_fields(value: &Value, array: bool) -> Result<Vec<u8>> {
    let mut fields = Vec::new();
    match value {
        Value::Object(values) if !array => {
            for (name, value) in values {
                fields.extend_from_slice(&encode_json_field(name, value)?);
            }
        }
        Value::Array(values) if array => {
            for value in values {
                fields.extend_from_slice(&encode_json_field("", value)?);
            }
        }
        _ => return Err(Error::InvalidJson),
    }
    Ok(fields)
}

fn encode_json_field(name: &str, value: &Value) -> Result<Vec<u8>> {
    match value {
        Value::Null => encode_blobmsg_field(0, name, &[]),
        Value::Bool(value) => encode_blobmsg_field(BLOBMSG_INT8, name, &[*value as u8]),
        Value::String(value) => {
            if value.as_bytes().contains(&0) {
                return Err(Error::InteriorNul);
            }
            let mut data = value.as_bytes().to_vec();
            data.push(0);
            encode_blobmsg_field(BLOBMSG_STRING, name, &data)
        }
        Value::Number(value) => {
            if let Some(integer) = value.as_i64() {
                if let Ok(integer) = i32::try_from(integer) {
                    encode_blobmsg_field(BLOBMSG_INT32, name, &integer.to_be_bytes())
                } else {
                    encode_blobmsg_field(BLOBMSG_INT64, name, &integer.to_be_bytes())
                }
            } else if let Some(integer) = value.as_u64() {
                if let Ok(integer) = u32::try_from(integer) {
                    encode_blobmsg_field(BLOBMSG_INT32, name, &integer.to_be_bytes())
                } else {
                    encode_blobmsg_field(BLOBMSG_INT64, name, &integer.to_be_bytes())
                }
            } else {
                let number = value.as_f64().ok_or(Error::InvalidJson)?;
                encode_blobmsg_field(BLOBMSG_DOUBLE, name, &number.to_bits().to_be_bytes())
            }
        }
        Value::Array(_) => {
            encode_blobmsg_field(BLOBMSG_ARRAY, name, &encode_json_fields(value, true)?)
        }
        Value::Object(_) => {
            encode_blobmsg_field(BLOBMSG_TABLE, name, &encode_json_fields(value, false)?)
        }
    }
}

pub(crate) fn encode_json(value: &Value) -> Result<Vec<u8>> {
    let fields = match value {
        Value::Object(_) => encode_json_fields(value, false)?,
        Value::Array(_) => encode_json_fields(value, true)?,
        _ => return Err(Error::InvalidJson),
    };
    encode_root(&fields)
}

pub(crate) fn blobmsg_parts(attr: Attr<'_>) -> Result<(&str, &[u8])> {
    if !attr.extended || attr.payload.len() < 4 {
        return Err(Error::InvalidData("invalid blobmsg field"));
    }
    let name_len = u16::from_be_bytes(attr.payload[..2].try_into().unwrap()) as usize;
    let unpadded = 2usize
        .checked_add(name_len)
        .and_then(|value| value.checked_add(1))
        .ok_or(Error::InvalidData("blobmsg header overflow"))?;
    let header_len = align4(unpadded)?;
    if header_len > attr.payload.len()
        || attr.payload.get(2 + name_len) != Some(&0)
        || attr.payload[2..2 + name_len].contains(&0)
    {
        return Err(Error::InvalidData("invalid blobmsg field name"));
    }
    if attr.payload[unpadded..header_len]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::InvalidData("non-zero blobmsg header padding"));
    }
    let name = std::str::from_utf8(&attr.payload[2..2 + name_len])
        .map_err(|_| Error::InvalidData("blobmsg field name is not UTF-8"))?;
    Ok((name, &attr.payload[header_len..]))
}

pub(crate) fn find_string_field(payload: &[u8], wanted: &str) -> Result<Option<String>> {
    let mut found = None;
    for attr in parse_attr_list(payload)? {
        let (name, data) = blobmsg_parts(attr)?;
        if name != wanted {
            continue;
        }
        if found.is_some() || attr.id != BLOBMSG_STRING || data.last() != Some(&0) {
            return Err(Error::InvalidData("invalid or duplicate blobmsg string"));
        }
        let value = &data[..data.len() - 1];
        if value.contains(&0) {
            return Err(Error::InvalidData(
                "blobmsg string contains an interior NUL",
            ));
        }
        found = Some(
            std::str::from_utf8(value)
                .map_err(|_| Error::InvalidData("blobmsg string is not UTF-8"))?
                .to_owned(),
        );
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_round_trip_shape_is_valid_blobmsg() {
        let root = encode_json(&json!({
            "ok": true,
            "rate": 42,
            "name": "router",
            "clients": [{"ip": "192.0.2.1"}]
        }))
        .unwrap();
        let root = parse_attr(&root).unwrap();
        let fields = parse_attr_list(root.payload).unwrap();
        assert_eq!(fields.len(), 4);
        assert_eq!(
            find_string_field(root.payload, "name").unwrap(),
            Some("router".into())
        );
    }

    #[test]
    fn malformed_lengths_and_duplicate_fields_are_rejected() {
        assert!(parse_attr(&[0, 0, 0, 3]).is_err());
        let field = encode_blobmsg_field(BLOBMSG_STRING, "key", b"value\0").unwrap();
        let mut duplicate = field.clone();
        duplicate.extend_from_slice(&field);
        assert!(find_string_field(&duplicate, "key").is_err());
    }
}
