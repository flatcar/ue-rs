use std::str;
use sha2::Digest;

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

/// Parse a hexadecimal string into the output of the generically typed hashing
/// algorithm.
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
