use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::error::Error;
use std::fs;
use std::fs::File;
use std::path::Path;
use log::{error, debug};
use bzip2::read::BzDecoder;

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
pub fn read_delta_update_header(f: &mut BufReader<File>) -> Result<DeltaUpdateFileHeader, Box<dyn Error>> {
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

// Take a buffer stream and DeltaUpdateFileHeader,
// return DeltaArchiveManifest that contains manifest.
pub fn get_manifest_bytes(f: &mut BufReader<File>, header: &DeltaUpdateFileHeader) -> Result<proto::DeltaArchiveManifest, Box<dyn Error>> {
    let manifest_bytes = {
        let mut buf = vec![0u8; header.manifest_size as usize];
        f.read_exact(&mut buf)?;
        buf.into_boxed_slice()
    };

    let delta_archive_manifest = proto::DeltaArchiveManifest::parse_from_bytes(&manifest_bytes)?;

    Ok(delta_archive_manifest)
}

// Take a buffer stream and DeltaUpdateFileHeader,
// return a bytes slice of the actual signature data as well as its length.
pub fn get_signatures_bytes<'a>(f: &'a mut BufReader<File>, header: &'a DeltaUpdateFileHeader, manifest: &mut proto::DeltaArchiveManifest) -> Result<Box<[u8]>, Box<dyn Error>> {
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

// Return data length, including header and manifest.
pub fn get_header_data_length(header: &DeltaUpdateFileHeader, manifest: &proto::DeltaArchiveManifest) -> usize {
    // Read from the beginning of the stream, which means the whole buffer including
    // delta update header as well as manifest. That is because data that must be verified
    // with signatures start from the beginning.
    //
    // Payload data structure:
    //  | header | manifest | data blobs | signatures |

    header.translate_offset(manifest.signatures_offset.unwrap()) as usize
}

// Take a buffer reader, delta file header, manifest as input.
// Return path to data blobs, without header, manifest, or signatures.
pub fn get_data_blobs<'a>(f: &'a mut BufReader<File>, header: &'a DeltaUpdateFileHeader, manifest: &proto::DeltaArchiveManifest, tmppath: &Path) -> Result<File, Box<dyn Error>> {
    fs::create_dir_all(tmppath.parent().unwrap())?;
    let mut outfile = File::create(tmppath)?;

    // Read from the beginning of header, which means buffer including only data blobs.
    // It means it is necessary to call header.translate_offset(), in contrast to
    // get_header_data_length.
    // Iterate each partition_operations to get data offset and data length.
    for pop in &manifest.partition_operations {
        let data_offset = pop.data_offset.unwrap();
        let data_length = pop.data_length.unwrap();

        let mut partdata = vec![0u8; data_length as usize];

        f.seek(SeekFrom::Start(header.translate_offset(data_offset.into())))?;
        f.read_exact(&mut partdata)?;

        // In case of bzip2-compressed chunks, extract.
        if pop.type_.unwrap() == proto::install_operation::Type::REPLACE_BZ.into() {
            let mut bzdecoder = BzDecoder::new(&partdata[..]);
            let mut partdata_unpacked = Vec::new();
            bzdecoder.read_to_end(&mut partdata_unpacked)?;

            outfile.write_all(&partdata_unpacked)?;
        } else {
            outfile.write_all(&partdata)?;
        }
        outfile.flush()?;
    }

    Ok(outfile)
}

#[rustfmt::skip]
// parse_signature_data takes bytes slices for signature and digest of data blobs,
// and path to public key, to parse and verify the signature.
// Return only actual signature data, without version and special fields.
pub fn parse_signature_data(sigbytes: &[u8], digest: &[u8], pubkeyfile: &str) -> Option<Box<[u8]>> {
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
            verify_sig_pubkey(digest, sig, pubkeyfile)
            .map(Vec::into_boxed_slice))
}

// verify_sig_pubkey verifies signature with the given digest and the public key.
// Return the verified signature data.
pub fn verify_sig_pubkey(digest: &[u8], sig: &Signature, pubkeyfile: &str) -> Option<Vec<u8>> {
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

    debug!("digest: {:?}", digest);
    debug!("data: {:?}", sig.data());
    debug!("special_fields: {:?}", sig.special_fields());

    // verify signature with pubkey
    let res_verify = verify_sig::verify_rsa_pkcs_prehash(&digest, sig.data(), get_public_key_pkcs_pem(pubkeyfile, KeyTypePkcs8));
    match res_verify {
        Ok(res_verify) => res_verify,
        Err(err) => {
            error!("verify_rsa_pkcs signature ({}) failed with {}", sig, err);
            return None;
        }
    };

    sigvec.cloned()
}
