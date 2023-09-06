use std::fmt;
use std::str;

#[rustfmt::skip]
use ct_codecs::{
    Error as CodecError,

    Base64,
    Hex,

    Encoder,
    Decoder
};

#[derive(PartialEq, Eq, Clone)]
pub struct Sha1;

#[derive(PartialEq, Eq, Clone)]
pub struct Sha256;

pub trait HashAlgo {
    const HASH_NAME: &'static str;

    type Output: AsRef<[u8]> + AsMut<[u8]> + Default + Sized + Eq;
}

impl HashAlgo for Sha1 {
    const HASH_NAME: &'static str = "Sha1";
    type Output = [u8; 20];
}

impl HashAlgo for Sha256 {
    const HASH_NAME: &'static str = "Sha256";
    type Output = [u8; 32];
}

#[derive(PartialEq, Eq, Clone)]
pub struct Hash<T: HashAlgo>(T::Output);

impl<T: HashAlgo> Hash<T> {
    pub fn from_bytes(digest: T::Output) -> Self {
        Self(digest)
    }
}

impl<T: HashAlgo> fmt::Debug for Hash<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tn = format!("Hash<{}>", T::HASH_NAME);
        #[rustfmt::skip]
        let hash_hex = Hex::encode_to_string(self.0.as_ref())
            .map_err(|_| fmt::Error)?;

        f.debug_tuple(&*tn).field(&hash_hex).finish()
    }
}

impl<T: HashAlgo> fmt::Display for Hash<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[rustfmt::skip]
        let hash_hex = Hex::encode_to_string(self.0.as_ref())
            .map_err(|_| fmt::Error)?;

        f.write_str(&hash_hex)
    }
}

impl<T: HashAlgo> str::FromStr for Hash<T> {
    type Err = CodecError;

    fn from_str(hash_base64: &str) -> Result<Self, Self::Err> {
        Self::from_base64(hash_base64)
    }
}

impl<T: HashAlgo> Hash<T> {
    #[inline]
    fn decode<D: Decoder>(hash: &str) -> Result<Self, CodecError> {
        let mut digest = T::Output::default();
        D::decode(digest.as_mut(), hash, None)?;
        Ok(Self(digest))
    }

    pub fn from_base64(hash_base64: &str) -> Result<Self, CodecError> {
        Self::decode::<Base64>(hash_base64)
    }

    pub fn from_hex(hash_hex: &str) -> Result<Self, CodecError> {
        Self::decode::<Hex>(hash_hex)
    }
}
