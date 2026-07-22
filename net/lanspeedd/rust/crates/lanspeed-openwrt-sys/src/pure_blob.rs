use crate::{codec, Error, Result};

pub struct BlobBuf {
    bytes: Vec<u8>,
}

impl BlobBuf {
    pub fn from_json(json: &str) -> Result<Self> {
        let value = serde_json::from_str(json).map_err(|_| Error::InvalidJson)?;
        Ok(Self {
            bytes: codec::encode_json(&value)?,
        })
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_json_and_scalar_roots() {
        assert!(BlobBuf::from_json("not-json").is_err());
        assert!(BlobBuf::from_json("7").is_err());
        assert!(BlobBuf::from_json(r#"{"ok":true}"#).is_ok());
    }
}
