use std::str;
use sha2::Digest;
use crate::error::Error;
use crate::result::Result;

/// Wrapper struct around the SHA1 hashing algorithm from the `sha1` crate.
#[derive(Clone)]
pub struct Sha1(sha1::Sha1);

/// Wrapper struct around the SHA256 hashing algorithm from the `sha256` crate.
#[derive(Clone)]
pub struct Sha256(sha2::Sha256);

/// Fixed-size SHA1 digest type alias for [u8; 20].
pub type Sha1Digest = <Sha1 as Hasher>::Output;

/// Fixed-size SHA256 digest type alias for [u8; 32].
pub type Sha256Digest = <Sha256 as Hasher>::Output;

/// Trait for generic cryptographic hash algorithm and associated hashing logic.
pub trait Hasher {
    /// The name of the hashing algorithm; for logging/debugging purposes.
    const HASH_NAME: &'static str;

    /// The size of the digest of the hashing algorithm in bytes.
    const FINGERPRINT_SIZE: usize;

    // TODO: switch to syntax like `type Output = [u8; Self::FINGERPRINT_SIZE];`
    //       when Rust RFC #2532 (associated type defaults) stabilises
    /// The output type of the hashing algorithm (typically a [u8; N]).
    type Output: AsRef<[u8]> + AsMut<[u8]> + Default + Sized + PartialEq + Eq + std::fmt::Debug;

    /// Creates a new instance of the hasher.
    fn new() -> Self;

    /// Updates the hasher with the given bytes.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the hash and returns the digest.
    fn finalize(self) -> Self::Output;

    /// Construct a hash of the output format of the associated hashing
    /// algorithm using a provided string.
    fn try_from_hex_string(s: &str) -> Result<Self::Output>;
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

    fn try_from_hex_string(s: &str) -> Result<Self::Output> {
        try_from_hex_string::<Self>(s)
    }
}

pub(crate) mod sha1_from_str {
    use crate::{Hasher, Sha1, Sha1Digest};
    use crate::Result;

    #[inline]
    pub(crate) fn from_str(s: &str) -> Result<Sha1Digest> {
        <Sha1 as Hasher>::try_from_hex_string(s)
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
    fn try_from_hex_string(s: &str) -> Result<Self::Output> {
        try_from_hex_string::<Self>(s)
    }
}

pub(crate) mod sha256_from_str {
    use crate::{Hasher, Sha256, Sha256Digest};
    use crate::Result;

    #[inline]
    pub(crate) fn from_str(s: &str) -> Result<Sha256Digest> {
        <Sha256 as Hasher>::try_from_hex_string(s)
    }
}

/// Parse a hexadecimal string into the output of the generically typed hashing
/// algorithm.
fn try_from_hex_string<T: Hasher>(s: &str) -> Result<T::Output> {
    let bytes = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Error::TryFromHex)).collect::<Result<Vec<u8>>>()?;

    if bytes.len() == T::FINGERPRINT_SIZE {
        let mut ret = T::Output::default();
        ret.as_mut().copy_from_slice(&bytes);
        Ok(ret)
    } else {
        Err(Error::InvalidDigestLength {
            expected: T::FINGERPRINT_SIZE,
            actual: bytes.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::Hasher;
    use super::{Sha256, Sha1, try_from_hex_string};
    use sha1::Digest;

    const TEST_DATA: &[u8] = b"test string";

    #[test]
    fn sha1_new_finalize() {
        let exp: [u8; 20] = {
            let mut digest = sha1::Sha1::default();
            digest.update(TEST_DATA);
            digest.finalize().into()
        };

        let got = {
            let mut sha1 = Sha1::new();
            sha1.update(TEST_DATA);
            sha1.finalize()
        };

        assert_eq!(got, exp);
    }

    #[test]
    fn sha256_new_finalize() {
        let exp: [u8; 32] = {
            let mut digest = sha2::Sha256::default();
            digest.update(TEST_DATA);
            digest.finalize().into()
        };

        let got = {
            let mut sha256 = Sha256::new();
            sha256.update(TEST_DATA);
            sha256.finalize()
        };

        assert_eq!(got, exp);
    }

    #[test]
    fn try_from_hex_string_sha1() {
        let hex_string = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
        let exp_bytes = [170, 244, 198, 29, 220, 197, 232, 162, 218, 190, 222, 15, 59, 72, 44, 217, 174, 169, 67, 77];
        let sha1_digest = try_from_hex_string::<Sha1>(hex_string);

        assert!(sha1_digest.is_ok());
        assert_eq!(sha1_digest.unwrap(), exp_bytes);
    }

    #[test]
    fn try_from_hex_string_sha256() {
        let hex_string = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let exp_bytes = [44, 242, 77, 186, 95, 176, 163, 14, 38, 232, 59, 42, 197, 185, 226, 158, 27, 22, 30, 92, 31, 167, 66, 94, 115, 4, 51, 98, 147, 139, 152, 36];
        let sha256_digest = try_from_hex_string::<Sha256>(hex_string);

        assert!(sha256_digest.is_ok());
        assert_eq!(sha256_digest.unwrap(), exp_bytes);
    }
}
