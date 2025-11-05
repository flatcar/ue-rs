mod error;

pub(super) use error::Error;
pub(super) type Result<T> = std::result::Result<T, Error>;

use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::pkcs1v15;
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::signature::hazmat::PrehashVerifier;
use rsa::sha2::Sha256;
use std::{fs, str};

#[derive(Debug)]
pub enum KeyType {
    KeyTypeNone,
    KeyTypePkcs1,
    KeyTypePkcs8,
}

// Assume that we rely on RSA either PKCS1v1.5 or PKCS8,
// sha256 for the hash.

// Takes a data buffer and a private key, to sign the data
// with the private key and verify the data with the public key.
pub fn sign_rsa_pkcs(databuf: &[u8], private_key: RsaPrivateKey) -> Result<Vec<u8>> {
    let signing_key = pkcs1v15::SigningKey::<Sha256>::new(private_key);

    let signature = signing_key.sign(databuf);
    if signature.to_bytes().as_ref() == databuf {
        Err(Error::DatabufNotSignedCorrectly)
    } else {
        Ok(signature.to_vec())
    }
}

// Takes a data buffer, signature and a public key, to verify the data
// with the public key.
// As databuf is an in-memory buffer, the function has a limitation of max size
// of the input data, like a few GiB. Going over that, it could result in OOM.
pub fn verify_rsa_pkcs_buf(databuf: &[u8], signature: &[u8], public_key: RsaPublicKey) -> Result<()> {
    // Equivalent of:
    //   openssl rsautl -verify -pubin -key |public_key_path|
    //   - in |sig_data| -out |out_hash_data|

    let verifying_key = pkcs1v15::VerifyingKey::<Sha256>::new(public_key);

    verifying_key
        .verify(
            databuf,
            &pkcs1v15::Signature::try_from(signature).map_err(Error::InvalidPkcs1v15Signature)?,
        )
        .map_err(Error::CouldNotVerifySignature)
}

// Takes a data buffer, signature and a public key, to verify the data
// with the public key.
// In contrast to verify_rsa_pkcs_buf, the function takes a digest of an input
// buffer, so it does not have a limitation of max size of input data.
// It relies on RSA PrehashVerifier.
// TODO: consider migrating to RSA DigestVerifier.
pub fn verify_rsa_pkcs_prehash(digestbuf: &[u8], signature: &[u8], public_key: RsaPublicKey) -> Result<()> {
    let verifying_key = pkcs1v15::VerifyingKey::<Sha256>::new(public_key);

    verifying_key
        .verify_prehash(
            digestbuf,
            &pkcs1v15::Signature::try_from(signature).map_err(Error::InvalidPkcs1v15Signature)?,
        )
        .map_err(Error::CouldNotVerifySignature)
}

pub fn get_private_key_pkcs_pem(private_key_path: &str, key_type: KeyType) -> Result<RsaPrivateKey> {
    let private_key_buf = fs::read_to_string(private_key_path).map_err(Error::ReadPrivateKey)?;
    match key_type {
        KeyType::KeyTypePkcs1 => RsaPrivateKey::from_pkcs1_pem(private_key_buf.as_str()).map_err(Error::DeserialisePkcs1),
        KeyType::KeyTypePkcs8 => RsaPrivateKey::from_pkcs8_pem(private_key_buf.as_str()).map_err(Error::DeserialisePkcs8),
        KeyType::KeyTypeNone => Err(Error::InvalidPrivateKeyType),
    }
}

pub fn get_public_key_pkcs_pem(public_key_path: &str, key_type: KeyType) -> Result<RsaPublicKey> {
    let public_key_buf = fs::read_to_string(public_key_path).map_err(Error::ReadPublicKey)?;
    match key_type {
        KeyType::KeyTypePkcs1 => RsaPublicKey::from_pkcs1_pem(public_key_buf.as_str()).map_err(Error::DeserialisePkcs1),
        KeyType::KeyTypePkcs8 => RsaPublicKey::from_public_key_pem(public_key_buf.as_str()).map_err(Error::DecodePublicKey),
        KeyType::KeyTypeNone => Err(Error::InvalidPrivateKeyType),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_sig::KeyType::{KeyTypePkcs1, KeyTypePkcs8};

    const TESTDATA: &str = "test data for verifying signature";
    const PRIVKEY_PKCS1_PATH: &str = "../src/testdata/private_key_test_pkcs1.pem";
    const PUBKEY_PKCS1_PATH: &str = "../src/testdata/public_key_test_pkcs1.pem";
    const PRIVKEY_PKCS8_PATH: &str = "../src/testdata/private_key_test_pkcs8.pem";
    const PUBKEY_PKCS8_PATH: &str = "../src/testdata/public_key_test_pkcs8.pem";

    #[test]
    fn test_verify_sig() {
        // PKCS1
        let signature = sign_rsa_pkcs(
            TESTDATA.as_bytes(),
            get_private_key_pkcs_pem(PRIVKEY_PKCS1_PATH, KeyTypePkcs1).unwrap(),
        )
        .unwrap_or_else(|error| {
            panic!("failed to sign data: {:?}", error);
        });

        _ = verify_rsa_pkcs_buf(
            TESTDATA.as_bytes(),
            signature.as_slice(),
            get_public_key_pkcs_pem(PUBKEY_PKCS1_PATH, KeyTypePkcs1).unwrap(),
        )
        .unwrap_or_else(|error| {
            panic!("failed to verify data: {:?}", error);
        });

        // PKCS8
        let signature = sign_rsa_pkcs(
            TESTDATA.as_bytes(),
            get_private_key_pkcs_pem(PRIVKEY_PKCS8_PATH, KeyTypePkcs8).unwrap(),
        )
        .unwrap_or_else(|error| {
            panic!("failed to sign data: {:?}", error);
        });

        _ = verify_rsa_pkcs_buf(
            TESTDATA.as_bytes(),
            signature.as_slice(),
            get_public_key_pkcs_pem(PUBKEY_PKCS8_PATH, KeyTypePkcs8).unwrap(),
        )
        .unwrap_or_else(|error| {
            panic!("failed to verify data: {:?}", error);
        });
    }
}
