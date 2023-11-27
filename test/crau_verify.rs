use std::io;
use std::io::{BufReader, Write};
use std::error::Error;
use std::fs;
use std::fs::File;
use std::path::Path;
use tempfile;

use update_format_crau::{delta_update, proto};

use anyhow::{Context, Result};
use argh::FromArgs;

const PUBKEY_FILE: &str = "../src/testdata/public_key_test_pkcs8.pem";

#[derive(FromArgs, Debug)]
/// A test program for verifying CRAU header of update payloads.
struct Args {
    /// source payload path
    #[argh(option, short = 's')]
    src_path: String,

    /// destination signature path
    #[argh(option, short = 'd')]
    sig_path: String,
}

fn hash_on_disk(path: &Path) -> Result<omaha::Hash<omaha::Sha256>> {
    use sha2::{Sha256, Digest};

    let mut file = File::open(path).context(format!("failed to open path({:?})", path.display()))?;
    let mut hasher = Sha256::new();

    io::copy(&mut file, &mut hasher).context(format!("failed to copy data path ({:?})", path.display()))?;

    Ok(omaha::Hash::from_bytes(hasher.finalize().into()))
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Args = argh::from_env();

    let srcpath = &args.src_path;
    let sigpath = &args.sig_path;

    // Read update payload from srcpath, read delta update header from the payload.
    let upfile = fs::File::open(srcpath.clone())?;

    let freader = &mut BufReader::new(upfile);
    let header = delta_update::read_delta_update_header(freader)?;

    let mut delta_archive_manifest: proto::DeltaArchiveManifest = Default::default();

    // Extract signature from header.
    let sigbytes = delta_update::get_signatures_bytes(freader, &header, &mut delta_archive_manifest)?;

    // Parse signature data from the signature containing data, version, special fields.
    let tmpdir = tempfile::tempdir()?.into_path();
    fs::create_dir_all(tmpdir.clone())?;

    let headerdatapath = tmpdir.join("ue_header_data");

    let hdhash = hash_on_disk(headerdatapath.as_path())?;
    let hdhashvec: Vec<u8> = hdhash.into();

    // Get length of header and data
    let datablobspath = tmpdir.join("ue_data_blobs");

    // Extract data blobs into file path.
    delta_update::get_data_blobs(freader, &header, &delta_archive_manifest, datablobspath.as_path())?;

    // Parse signature data from the signature containing data, version, special fields.
    let sigdata = match delta_update::parse_signature_data(&sigbytes, hdhashvec.as_slice(), PUBKEY_FILE) {
        Ok(data) => data,
        _ => return Err("unable to parse signature data".into()),
    };

    println!("Parsed signature data from file {:?}", srcpath);

    // Store signature into a file.
    let mut sigfile = fs::File::create(sigpath.clone())?;
    let _ = sigfile.write_all(sigdata.as_slice());

    println!("Wrote signature data into file {:?}", sigpath);

    Ok(())
}
