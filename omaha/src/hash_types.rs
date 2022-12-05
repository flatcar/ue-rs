use std::fmt;
use std::str;

use ct_codecs::{
    Error as CodecError,

    Base64,
    Hex,

    Encoder,
    Decoder
};


pub struct Sha1;
pub struct Sha256;

pub trait HashAlgo {
    const HASH_NAME: &'static str;

    type Output:
        AsRef<[u8]> + AsMut<[u8]> + Default + Sized + Eq;
}

impl HashAlgo for Sha1 {
    const HASH_NAME: &'static str = "Sha1";
    type Output = [u8; 20];
}

impl HashAlgo for Sha256 {
    const HASH_NAME: &'static str = "Sha256";
    type Output = [u8; 32];
}

#[derive(PartialEq, Eq)]
pub struct Hash<T: HashAlgo>(T::Output);

impl<T: HashAlgo> fmt::Debug for Hash<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tn = format!("Hash<{}>", T::HASH_NAME);
        let hash_hex = Hex::encode_to_string(self.0.as_ref())
            .map_err(|_| fmt::Error)?;

        f.debug_tuple(&tn)
            .field(&hash_hex)
            .finish()
    }
}

impl<T: HashAlgo> fmt::Display for Hash<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash_hex = Hex::encode_to_string(self.0.as_ref())
            .map_err(|_| fmt::Error)?;

        f.write_str(&hash_hex)
    }
}

impl<T: HashAlgo> str::FromStr for Hash<T> {
    type Err = CodecError;

    fn from_str(hash_base64: &str) -> Result<Self, Self::Err> {
        let mut digest = T::Output::default();
        Base64::decode(digest.as_mut(), hash_base64, None)?;
        Ok(Self(digest))
    }
}
