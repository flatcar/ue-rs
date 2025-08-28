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
    const FINGERPRINT_SIZE: usize;

    // TODO: switch to syntax like `type Output = [u8; Self::FINGERPRINT_SIZE];`
    //       when Rust RFC #2532 (associated type defaults) stabilises
    type Output: AsRef<[u8]> + AsMut<[u8]> + Default + Sized + PartialEq + Eq + std::fmt::Debug;

    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Self::Output;
    fn try_from_hex_string(s: &str) -> Result<Self::Output, String>;
}

impl Hasher for Sha1 {
    const HASH_NAME: &'static str = "Sha1";
    const FINGERPRINT_SIZE: usize = 20;

    type Output = [u8; Self::FINGERPRINT_SIZE];

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
        try_from_hex_string::<Self>(s)
    }
}

impl Hasher for Sha256 {
    const HASH_NAME: &'static str = "Sha256";
    const FINGERPRINT_SIZE: usize = 32;

    type Output = [u8; Self::FINGERPRINT_SIZE];

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
        try_from_hex_string::<Self>(s)
    }
}

fn try_from_hex_string<T: Hasher>(s: &str) -> Result<T::Output, String> {
    let bytes = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16)).collect::<Result<Vec<u8>, _>>().map_err(|e| e.to_string())?;

    if bytes.len() == T::FINGERPRINT_SIZE {
        let mut ret = T::Output::default();
        ret.as_mut().copy_from_slice(&bytes);
        Ok(ret)
    } else {
        Err(format!("invalid digest length: {}", bytes.len()))
    }
}
