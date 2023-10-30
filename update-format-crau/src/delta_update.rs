use std::io::{Read, Seek, SeekFrom};
use std::error::Error;
use std::fs::File;
use log::{error, debug};

use protobuf::Message;

use crate::proto::signatures::Signature;
use crate::proto;
use crate::verify_sig;
use crate::verify_sig::get_public_key_pkcs_pem;
use crate::verify_sig::KeyType::KeyTypePkcs8;

const DELTA_UPDATE_HEADER_SIZE: u64 = 4 + 8 + 8;
const DELTA_UPDATE_FILE_MAGIC: &[u8] = b"CrAU";

#[derive(Debug)]
pub struct DeltaUpdateFileHeader {
    magic: [u8; 4],
    file_format_version: u64,
    manifest_size: u64,
}

impl DeltaUpdateFileHeader {
    #[inline]
    fn translate_offset(&self, offset: u64) -> u64 {
        DELTA_UPDATE_HEADER_SIZE + self.manifest_size + offset
    }
}

// Read delta update header from the given file, return DeltaUpdateFileHeader.
pub fn read_delta_update_header(mut f: &File) -> Result<DeltaUpdateFileHeader, Box<dyn Error>> {
    let mut header = DeltaUpdateFileHeader {
        magic: [0; 4],
        file_format_version: 0,
        manifest_size: 0,
    };

    f.read_exact(&mut header.magic)?;
    if header.magic != DELTA_UPDATE_FILE_MAGIC {
        return Err("bad file magic".into());
    }

    let mut buf = [0u8; 8];
    f.read_exact(&mut buf)?;
    header.file_format_version = u64::from_be_bytes(buf);
    if header.file_format_version != 1 {
        return Err("unsupported file format version".into());
    }

    f.read_exact(&mut buf)?;
    header.manifest_size = u64::from_be_bytes(buf);

    Ok(header)
}

// Take a file stream and DeltaUpdateFileHeader,
// return a bytes slice of the actual signature data as well as its length.
pub fn get_signatures_bytes<'a>(mut f: &'a File, header: &'a DeltaUpdateFileHeader) -> Result<Box<[u8]>, Box<dyn Error>> {
    let manifest_bytes = {
        let mut buf = vec![0u8; header.manifest_size as usize];
        f.read_exact(&mut buf)?;
        buf.into_boxed_slice()
    };

    let manifest = proto::DeltaArchiveManifest::parse_from_bytes(&manifest_bytes)?;

    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // !!! signature offsets are from the END of the manifest !!!
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // this may also be the case for the InstallOperations
    // use header.translate_offset()

    let signatures_bytes = match (manifest.signatures_offset, manifest.signatures_size) {
        (Some(sig_offset), Some(sig_size)) => {
            f.seek(SeekFrom::Start(header.translate_offset(sig_offset)))?;

            let mut buf = vec![0u8; sig_size as usize];
            f.read_exact(&mut buf)?;
            Some(buf.into_boxed_slice())
        }
        _ => None,
    };

    Ok(signatures_bytes.unwrap())
}

#[rustfmt::skip]
// parse_signature_data takes a bytes slice for signature and public key file path.
// Return only actual data, without version and special fields.
pub fn parse_signature_data(testdata: &[u8], sigbytes: &[u8], pubkeyfile: &str) -> Option<Box<[u8]>> {
    // Signatures has a container of the fields, i.e. version, data, and
    // special fields.
    let sigmessage = match proto::Signatures::parse_from_bytes(sigbytes) {
        Ok(data) => data,
        _ => return None,
    };

    // sigmessages.signatures[] has a single element in case of dev update payloads,
    // while it could have multiple elements in case of production update payloads.
    // For now we assume only dev update payloads are supported.
    // Return the first valid signature, iterate into the next slot if invalid.
    sigmessage.signatures.iter()
        .find_map(|sig|
            verify_sig_pubkey(testdata, sig, pubkeyfile)
            .map(Vec::into_boxed_slice))
}

// Verify signature with public key
pub fn verify_sig_pubkey(testdata: &[u8], sig: &Signature, pubkeyfile: &str) -> Option<Vec<u8>> {
    // The signature version is actually a numeration of the present signatures,
    // with the index starting at 2 if only one signature is present.
    // The Flatcar dev payload has only one signature but
    // the production payload has two from which only one is valid.
    // So, we see only "version 2" for dev payloads , and "version 1" and "version 2"
    // in case of production update payloads. However, we do not explicitly check
    // for a signature version, as the number could differ in some cases.
    debug!("supported signature version: {:?}", sig.version());
    let sigvec = match &sig.data {
        Some(sigdata) => Some(sigdata),
        _ => None,
    };

    debug!("data: {:?}", sig.data());
    debug!("special_fields: {:?}", sig.special_fields());

    // verify signature with pubkey
    let res_verify = verify_sig::verify_rsa_pkcs(testdata, sig.data(), get_public_key_pkcs_pem(pubkeyfile, KeyTypePkcs8));
    match res_verify {
        Ok(res_verify) => res_verify,
        Err(err) => {
            error!("verify_rsa_pkcs signature ({}) failed with {}", sig, err);
            return None;
        }
    };

    sigvec.cloned()
}
