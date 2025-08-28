use std::str;
use sha2::Digest;

#[derive(Clone)]
pub struct Sha1(sha1::Sha1);

#[derive(Clone)]
pub struct Sha256(sha2::Sha256);

pub type Sha1Digest = <Sha1 as Hasher>::Output;

pub type Sha256Digest = <Sha256 as Hasher>::Output;

pub trait Hasher {
    const HASH_NAME: &'static str;

    type Output: AsRef<[u8]> + AsMut<[u8]> + Default + Sized + PartialEq + Eq + std::fmt::Debug;

    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Self::Output;
    fn try_from_hex_string(s: &str) -> Result<Self::Output, String>;
}

impl Hasher for Sha1 {
    const HASH_NAME: &'static str = "Sha1";
    type Output = [u8; 20];

    fn new() -> Self {
        Self(sha1::Sha1::new())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }

    fn finalize(self) -> Self::Output {
        self.0.finalize().into()
    }

    fn try_from_hex_string(s: &str) -> Result<Self::Output, String> {
        let bytes = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16)).collect::<Result<Vec<u8>, _>>().map_err(|e| e.to_string())?;

        match bytes.len() {
            20 => {
                let mut ret = [0u8; 20];
                ret.copy_from_slice(&bytes);
                Ok(ret)
            }
            _ => Err(format!("invalid digest length: {}", bytes.len())),
        }
    }
}

impl Hasher for Sha256 {
    const HASH_NAME: &'static str = "Sha256";
    type Output = [u8; 32];

    fn new() -> Self {
        Self(sha2::Sha256::new())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }

    fn finalize(self) -> Self::Output {
        self.0.finalize().into()
    }
    fn try_from_hex_string(s: &str) -> Result<Self::Output, String> {
        let bytes = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16)).collect::<Result<Vec<u8>, _>>().map_err(|e| e.to_string())?;

        match bytes.len() {
            32 => {
                let mut ret = [0u8; 32];
                ret.copy_from_slice(&bytes);
                Ok(ret)
            }
            _ => Err(format!("invalid digest length: {}", bytes.len())),
        }
    }
}
