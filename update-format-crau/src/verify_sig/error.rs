#[derive(Debug)]
pub enum Error {
    DatabufNotSignedCorrectly,
    InvalidPkcs1v15Signature(rsa::signature::Error),
    CouldNotVerifySignature(rsa::signature::Error),
    ReadPrivateKey(std::io::Error),
    DeserialisePkcs1(rsa::pkcs1::Error),
    DeserialisePkcs8(rsa::pkcs8::Error),
    InvalidPrivateKeyType,
    ReadPublicKey(std::io::Error),
    DecodePublicKey(rsa::pkcs8::spki::Error),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::DatabufNotSignedCorrectly => write!(f, "databuf was not signed correctly"),
            Error::InvalidPkcs1v15Signature(err) => write!(f, "invalid pkcs1v15 signature: {err}"),
            Error::CouldNotVerifySignature(err) => write!(f, "failed to verify signature: {err}"),
            Error::ReadPrivateKey(err) => write!(f, "failed to read private key: {err}"),
            Error::DeserialisePkcs1(err) => write!(f, "failed to deserialise PKCS1 PEM: {err}"),
            Error::DeserialisePkcs8(err) => write!(f, "failed to deserialise PKCS8 PEM: {err}"),
            Error::InvalidPrivateKeyType => write!(f, "invalid private key type"),
            Error::ReadPublicKey(err) => write!(f, "failed to read public key: {err}"),
            Error::DecodePublicKey(err) => write!(f, "failed to decode public key: {err}"),
        }
    }
}
