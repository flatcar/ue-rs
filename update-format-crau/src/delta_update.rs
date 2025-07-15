use std::io::{Read, Write};
use std::fs;
use std::fs::File;
use std::path::Path;
use std::mem;
use std::os::unix::prelude::FileExt;
use log::{debug, info};
use bzip2::read::BzDecoder;
use anyhow::{Context, Result, anyhow, bail};

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
pub fn read_delta_update_header(f: &File) -> Result<DeltaUpdateFileHeader> {
    let mut header = DeltaUpdateFileHeader {
        magic: [0; 4],
        file_format_version: 0,
        manifest_size: 0,
    };

    f.read_exact_at(&mut header.magic, 0).context("failed to read header magic")?;
    if header.magic != DELTA_UPDATE_FILE_MAGIC {
        bail!("bad file magic");
    }

    let mut buf = [0u8; 8];
    f.read_exact_at(&mut buf, header.magic.len() as u64).context("failed to read file format version")?;
    header.file_format_version = u64::from_be_bytes(buf);
    if header.file_format_version != 1 {
        bail!("unsupported file format version");
    }

    f.read_exact_at(&mut buf, (header.magic.len() + mem::size_of::<u64>()) as u64).context("failed to read manifest size")?;
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
        .context("failed to read manifest bytes")?;
        buf.into_boxed_slice()
    };

    let delta_archive_manifest = proto::DeltaArchiveManifest::parse_from_bytes(&manifest_bytes).context("failed to parse manifest")?;

    Ok(delta_archive_manifest)
}

// Take a buffer stream and DeltaUpdateFileHeader,
// return a bytes slice of the actual signature data as well as its length.
pub fn get_signatures_bytes<'a>(f: &'a File, header: &'a DeltaUpdateFileHeader, manifest: &mut proto::DeltaArchiveManifest) -> Result<Box<[u8]>> {
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // !!! signature offsets are from the END of the manifest !!!
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // this may also be the case for the InstallOperations
    // use header.translate_offset()

    let signatures_bytes = match (manifest.signatures_offset, manifest.signatures_size) {
        (Some(sig_offset), Some(sig_size)) => {
            let mut buf = vec![0u8; sig_size as usize];
            f.read_exact_at(&mut buf, header.translate_offset(sig_offset)).context("failed to read signature")?;
            Some(buf.into_boxed_slice())
        }
        _ => None,
    };

    signatures_bytes.ok_or(anyhow!("failed to get signature bytes slice"))
}

// Return data length, including header and manifest.
pub fn get_header_data_length(header: &DeltaUpdateFileHeader, manifest: &proto::DeltaArchiveManifest) -> Result<usize> {
    // Read from the beginning of the stream, which means the whole buffer including
    // delta update header as well as manifest. That is because data that must be verified
    // with signatures start from the beginning.
    //
    // Payload data structure:
    //  | header | manifest | data blobs | signatures |

    Ok(header.translate_offset(manifest.signatures_offset.ok_or(anyhow!("no signature offset"))?) as usize)
}

// Take a buffer reader, delta file header, manifest as input.
// Return path to data blobs, without header, manifest, or signatures.
pub fn get_data_blobs<'a>(f: &'a File, header: &'a DeltaUpdateFileHeader, manifest: &proto::DeltaArchiveManifest, tmpfile: &Path) -> Result<()> {
    let tmpdir = tmpfile.parent().ok_or(anyhow!("unable to get parent directory"))?;
    fs::create_dir_all(tmpdir).context(format!("failed to create directory {tmpdir:?}"))?;
    let mut outfile = File::create(tmpfile).context(format!("failed to create file {tmpfile:?}"))?;

    // Read from the beginning of header, which means buffer including only data blobs.
    // It means it is necessary to call header.translate_offset(), in contrast to
    // get_header_data_length.
    // Iterate each partition_operations to get data offset and data length.
    for pop in &manifest.partition_operations {
        let data_offset = pop.data_offset.ok_or(anyhow!("unable to get data offset"))?;
        let data_length = pop.data_length.ok_or(anyhow!("unable to get data length"))?;
        let block_size = manifest.block_size() as u64;
        if pop.dst_extents.len() != 1 {
            bail!(
                "unexpected number of extents, only one can be handled: {}",
                pop.dst_extents.len()
            );
        }
        let start_block = block_size * pop.dst_extents[0].start_block.ok_or(anyhow!("unable to get start_block"))?;

        let mut partdata = vec![0u8; data_length as usize];

        let translated_offset = header.translate_offset(data_offset.into());
        f.read_exact_at(&mut partdata, translated_offset).context(format!(
            "failed to read data with length {data_length:?} at {translated_offset:?}",
        ))?;

        // In case of bzip2-compressed chunks, extract.
        if pop.type_.ok_or(anyhow!("unable to get type_ from partition operations"))? == proto::install_operation::Type::REPLACE_BZ.into() {
            let mut bzdecoder = BzDecoder::new(&partdata[..]);
            let mut partdata_unpacked = Vec::new();
            bzdecoder.read_to_end(&mut partdata_unpacked).context(format!("failed to unpack bzip2ed data at offset {translated_offset:?}"))?;

            outfile.write_all_at(&partdata_unpacked, start_block).context(format!("failed to copy unpacked data at offset {translated_offset:?}"))?;
        } else {
            outfile.write_all_at(&partdata, start_block).context(format!("failed to copy plain data at offset {translated_offset:?}"))?;
        }
        outfile.flush().context(format!("failed to flush at offset {translated_offset:?}"))?;
    }

    Ok(())
}

#[rustfmt::skip]
// parse_signature_data takes bytes slices for signature and digest of data blobs,
// and path to public key, to parse and verify the signature.
// Return only actual signature data, without version and special fields.
pub fn parse_signature_data(sigbytes: &[u8], digest: &[u8], pubkeyfile: &str) -> Result<Vec<u8>> {
    // Signatures has a container of the fields, i.e. version, data, and
    // special fields.
    let sigmessage = match proto::Signatures::parse_from_bytes(sigbytes) {
        Ok(data) => data,
        _ => bail!("failed to parse signature messages"),
    };

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
                continue
            }
        };
    }

    bail!("failed to find a valid signature in any slot");
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
        _ => bail!("empty signature data, nothing to verify"),
    };

    debug!("digest: {digest:?}");
    debug!("data: {:?}", sig.data());
    debug!("special_fields: {:?}", sig.special_fields());

    // verify signature with pubkey
    let pkcspem_pubkey = match get_public_key_pkcs_pem(pubkeyfile, KeyTypePkcs8) {
        Ok(key) => key,
        Err(err) => {
            bail!("failed to get PKCS8 PEM public key ({pubkeyfile:?}) with error {err:?}");
        }
    };

    let res_verify = verify_sig::verify_rsa_pkcs_prehash(digest, sig.data(), pkcspem_pubkey);
    match res_verify {
        Ok(res_verify) => res_verify,
        Err(err) => {
            bail!("verify_rsa_pkcs signature ({sig:?}) failed with error {err:?}");
        }
    };

    Ok(sigvec.clone().into_boxed_slice())
}
