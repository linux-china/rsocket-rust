use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::RSocketError;
use crate::utils::Writeable;

const MAX_ROUTING_TAG_LEN: usize = 0xFF;

#[derive(Debug, Clone)]
pub struct SecurityMetadata {
    auth_type: u8,
    authentication: Vec<String>,
}

pub struct SecurityMetadataBuilder {
    inner: SecurityMetadata,
}

impl SecurityMetadataBuilder {
    pub fn simple(mut self, username: &str, password: &str) -> Self {
        self.inner.auth_type = 0;
        self.push(String::from(username)).push(String::from(password))
    }

    pub fn bearer(mut self, token: &str) -> Self {
        self.inner.auth_type = 1;
        self.push(String::from(token))
    }

    pub fn push(mut self, tag: String) -> Self {
        assert!(
            tag.len() <= MAX_ROUTING_TAG_LEN,
            "exceeded maximum routing tag length!"
        );
        self.inner.authentication.push(tag);
        self
    }
    pub fn build(self) -> SecurityMetadata {
        self.inner
    }
}

impl SecurityMetadata {
    pub fn builder() -> SecurityMetadataBuilder {
        SecurityMetadataBuilder {
            inner: SecurityMetadata { auth_type: 0, authentication: vec![] },
        }
    }

    pub fn decode(bf: &mut BytesMut) -> crate::Result<SecurityMetadata> {
        let mut bu = SecurityMetadata::builder();
        let auth_type = bf.get_u8() & 0x7F;
        loop {
            match Self::decode_once(bf) {
                Ok(v) => match v {
                    Some(tag) => bu = bu.push(tag),
                    None => break,
                },
                Err(e) => return Err(e),
            }
        }
        Ok(bu.build())
    }

    fn decode_once(bf: &mut BytesMut) -> crate::Result<Option<String>> {
        if bf.is_empty() {
            return Ok(None);
        }
        let size = bf.get_u8() as usize;
        if bf.len() < size {
            return Err(RSocketError::WithDescription("require more bytes!".into()).into());
        }
        let tag = String::from_utf8(bf.split_to(size).to_vec())?;
        Ok(Some(tag))
    }
}

impl Writeable for SecurityMetadata {
    fn write_to(&self, bf: &mut BytesMut) {
        bf.put_u8(self.auth_type | 0x80);
        bf.put_slice(&self.authentication[0].as_bytes());
        for item in &self.authentication {
            let size = item.len() as u8;
            bf.put_u8(size);
            bf.put_slice(item.as_bytes());
        }
    }

    fn len(&self) -> usize {
        let mut n = 0;
        for tag in &self.authentication {
            n += 2 + tag.as_bytes().len();
        }
        n
    }
}
