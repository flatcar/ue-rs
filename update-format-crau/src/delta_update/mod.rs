mod error;

use std::io::{Read, Write};
use std::fs;
use std::fs::File;
use std::path::Path;
use std::mem;
use std::os::unix::prelude::FileExt;
use log::{debug, info};
use bzip2::read::BzDecoder;

use protobuf::Message;
use crate::proto::signatures::Signature;
use crate::proto;
use crate::verify_sig;
use crate::verify_sig::get_public_key_pkcs_pem;
use crate::verify_sig::KeyType::KeyTypePkcs8;

pub use error::Error;
pub(super) type Result<T> = std::result::Result<T, Error>;

const DELTA_UPDATE_HEADER_SIZE: u64 = 4 + 8 + 8;
const DELTA_UPDATE_FILE_MAGIC: &[u8] = b"CrAU";

/// Type alias that represents u8 Vec.
/// Note: Vec<u8>, which has its size known at compile-time. is a better choice
/// than slice, which would require lifetime definitions or Box.
type DeltaMagic = Vec<u8>;

#[derive(Debug)]
pub struct DeltaUpdateFileHeader {
    magic: DeltaMagic,
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
pub fn read_delta_update_header(f: &File) -> Result<DeltaUpdateFileHeader> {
    let mut header = DeltaUpdateFileHeader {
        magic: DeltaMagic::with_capacity(4),
        file_format_version: 0,
        manifest_size: 0,
    };

    f.read_exact_at(header.magic.as_mut_slice(), 0).map_err(Error::ReadHeaderMagic)?;
    if header.magic != DELTA_UPDATE_FILE_MAGIC {
        return Err(Error::BadHeaderMagic(header.magic));
    }

    let mut buf = [0u8; 8];
    f.read_exact_at(&mut buf, header.magic.len() as u64).map_err(Error::ReadFileFormatVersion)?;
    header.file_format_version = u64::from_be_bytes(buf);
    if header.file_format_version != 1 {
        return Err(Error::UnsupportedFileFormatVersion(header.file_format_version));
    }

    f.read_exact_at(&mut buf, (header.magic.len() + mem::size_of::<u64>()) as u64).map_err(Error::ReadManifestSize)?;
    header.manifest_size = u64::from_be_bytes(buf);

    Ok(header)
}

// Take a buffer stream and DeltaUpdateFileHeader,
// return DeltaArchiveManifest that contains manifest.
pub fn get_manifest_bytes(f: &File, header: &DeltaUpdateFileHeader) -> Result<proto::DeltaArchiveManifest> {
    let manifest_bytes = {
        let mut buf = vec![0u8; header.manifest_size as usize];
        f.read_exact_at(
            &mut buf,
            (header.magic.len() + mem::size_of::<u64>() + mem::size_of::<u64>()) as u64,
        )
        .map_err(Error::ReadManifestBytes)?;
        buf.into_boxed_slice()
    };

    proto::DeltaArchiveManifest::parse_from_bytes(&manifest_bytes).map_err(Error::ParseManifest)
}

// Take a buffer stream and DeltaUpdateFileHeader,
// return a bytes slice of the actual signature data as well as its length.
pub fn get_signatures_bytes<'a>(f: &'a File, header: &'a DeltaUpdateFileHeader, manifest: &mut proto::DeltaArchiveManifest) -> Result<Box<[u8]>> {
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // !!! signature offsets are from the END of the manifest !!!
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // this may also be the case for the InstallOperations
    // use header.translate_offset()

    match (manifest.signatures_offset, manifest.signatures_size) {
        (Some(sig_offset), Some(sig_size)) => {
            let mut buf = vec![0u8; sig_size as usize];
            f.read_exact_at(&mut buf, header.translate_offset(sig_offset)).map_err(Error::ReadSignature)?;
            Ok(buf.into_boxed_slice())
        }
        (Some(_), _) => Err(Error::MissingSignatureSize),
        (_, Some(_)) => Err(Error::MissingSignatureOffset),
        _ => Err(Error::MissingSignatureOffsetAndSize),
    }
}

// Return data length, including header and manifest.
pub fn get_header_data_length(header: &DeltaUpdateFileHeader, manifest: &proto::DeltaArchiveManifest) -> Result<usize> {
    // Read from the beginning of the stream, which means the whole buffer including
    // delta update header as well as manifest. That is because data that must be verified
    // with signatures start from the beginning.
    //
    // Payload data structure:
    //  | header | manifest | data blobs | signatures |

    Ok(header.translate_offset(manifest.signatures_offset.ok_or(Error::MissingSignatureOffset)?) as usize)
}

// Take a buffer reader, delta file header, manifest as input.
// Return path to data blobs, without header, manifest, or signatures.
pub fn get_data_blobs<'a>(f: &'a File, header: &'a DeltaUpdateFileHeader, manifest: &proto::DeltaArchiveManifest, tmpfile: &Path) -> Result<()> {
    let tmpdir = tmpfile.parent().ok_or(Error::InvalidParentPath(tmpfile.to_path_buf()))?;
    fs::create_dir_all(tmpdir).map_err(Error::CreateDirectory)?;
    let mut outfile = File::create(tmpfile).map_err(Error::CreateFile)?;

    // Read from the beginning of header, which means buffer including only data blobs.
    // It means it is necessary to call header.translate_offset(), in contrast to
    // get_header_data_length.
    // Iterate each partition_operations to get data offset and data length.
    for pop in &manifest.partition_operations {
        let data_offset = pop.data_offset.ok_or(Error::MissingDataOffset)?;
        let data_length = pop.data_length.ok_or(Error::MissingDataLength)?;
        let block_size = manifest.block_size() as u64;
        if pop.dst_extents.len() != 1 {
            return Err(Error::IncorrectNumExtents(pop.dst_extents.len()));
        }
        let start_block = block_size * pop.dst_extents[0].start_block.ok_or(Error::MissingStartBlock)?;

        let mut partdata = vec![0u8; data_length as usize];

        let translated_offset = header.translate_offset(data_offset.into());
        f.read_exact_at(&mut partdata, translated_offset).map_err(Error::ReadData)?;

        // In case of bzip2-compressed chunks, extract.
        if pop.type_.ok_or(Error::MissingPartitionType)? == proto::install_operation::Type::REPLACE_BZ.into() {
            let mut bzdecoder = BzDecoder::new(&partdata[..]);
            let mut partdata_unpacked = Vec::new();
            bzdecoder.read_to_end(&mut partdata_unpacked).map_err(|err| Error::UnpackBzip2(err, translated_offset))?;

            outfile.write_all_at(&partdata_unpacked, start_block).map_err(|err| Error::CopyUnpackedData(err, translated_offset))?;
        } else {
            outfile.write_all_at(&partdata, start_block).map_err(|err| Error::CopyPlainData(err, translated_offset))?;
        }

        outfile.flush().map_err(|err| Error::FlushFile(err, translated_offset))?;
    }

    Ok(())
}

// parse_signature_data takes bytes slices for signature and digest of data blobs,
// and path to public key, to parse and verify the signature.
// Return only actual signature data, without version and special fields.
pub fn parse_signature_data(sigbytes: &[u8], digest: &[u8], pubkeyfile: &str) -> Result<Vec<u8>> {
    // Signatures has a container of the fields, i.e. version, data, and
    // special fields.
    let sigmessage = proto::Signatures::parse_from_bytes(sigbytes).map_err(Error::ParseSignatures)?;

    // sigmessages.signatures[] has a single element in case of dev update payloads,
    // while it could have multiple elements in case of production update payloads.
    // For now we assume only dev update payloads are supported.
    // Return the first valid signature, iterate into the next slot if invalid.
    for sig in sigmessage.signatures {
        match verify_sig_pubkey(digest, &sig, pubkeyfile) {
            Ok(sbox) => {
                return Ok(sbox.to_vec());
            }
            _ => {
                info!("failed to verify signature, jumping to the next slot");
                continue;
            }
        };
    }

    Err(Error::NoValidSignature)
}

// verify_sig_pubkey verifies signature with the given digest and the public key.
// Return the verified signature data.
pub fn verify_sig_pubkey(digest: &[u8], sig: &Signature, pubkeyfile: &str) -> Result<Box<[u8]>> {
    // The signature version is actually a numeration of the present signatures,
    // with the index starting at 2 if only one signature is present.
    // The Flatcar dev payload has only one signature but
    // the production payload has two from which only one is valid.
    // So, we see only "version 2" for dev payloads , and "version 1" and "version 2"
    // in case of production update payloads. However, we do not explicitly check
    // for a signature version, as the number could differ in some cases.
    debug!("supported signature version: {:?}", sig.version());
    let sigvec = match &sig.data {
        Some(sigdata) => sigdata,
        _ => return Err(Error::EmptySignature),
    };

    debug!("digest: {digest:?}");
    debug!("data: {:?}", sig.data());
    debug!("special_fields: {:?}", sig.special_fields());

    // verify signature with pubkey
    let pkcspem_pubkey = get_public_key_pkcs_pem(pubkeyfile, KeyTypePkcs8).map_err(Error::GetPkcs8PemPubKey)?;
    verify_sig::verify_rsa_pkcs_prehash(digest, sig.data(), pkcspem_pubkey).map_err(Error::VerifyPkcsSignature)?;

    Ok(sigvec.clone().into_boxed_slice())
}
