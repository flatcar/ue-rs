use std::io::Write;
use std::error::Error;
use std::fs;

use update_format_crau::delta_update;

use anyhow::Context;
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

fn main() -> Result<(), Box<dyn Error>> {
    let args: Args = argh::from_env();

    let srcpath = &args.src_path;
    let sigpath = &args.sig_path;

    // Read update payload from srcpath, read delta update header from the payload.
    let upfile = fs::File::open(srcpath.clone())?;

    let header = delta_update::read_delta_update_header(&upfile)?;

    // Parse signature data from the signature containing data, version, special fields.
    let mut delta_archive_manifest = delta_update::get_manifest_bytes(&upfile, &header)?;

    // Extract signature from header.
    let sigbytes = delta_update::get_signatures_bytes(&upfile, &header, &mut delta_archive_manifest)?;

    let tmpdir = tempfile::tempdir()?.keep();
    fs::create_dir_all(tmpdir.clone())?;
    let headerdatapath = tmpdir.join("ue_header_data");

    // Get length of header and data, including header and manifest.
    let header_data_length = delta_update::get_header_data_length(&header, &delta_archive_manifest).context("failed to get header data length")?;
    let hdhash = ue_rs::hash_on_disk::<omaha::Sha256>(headerdatapath.as_path(), Some(header_data_length))?;
    let hdhashvec: Vec<u8> = hdhash.clone().into();

    // Get length of header and data
    let datablobspath = tmpdir.join("ue_data_blobs");

    // Extract data blobs into file path.
    delta_update::get_data_blobs(&upfile, &header, &delta_archive_manifest, datablobspath.as_path())?;

    // Parse signature data from the signature containing data, version, special fields.
    let sigdata = match delta_update::parse_signature_data(&sigbytes, hdhashvec.as_slice(), PUBKEY_FILE) {
        Ok(data) => data,
        _ => {
            return Err(format!("unable to parse and verify signature, sigbytes ({sigbytes:?}), hdhash ({hdhash:?}), pubkey_path ({PUBKEY_FILE:?})",).into());
        }
    };

    println!("Parsed signature data from file {srcpath:?}");

    // Store signature into a file.
    let mut sigfile = fs::File::create(sigpath.clone())?;
    let _ = sigfile.write_all(sigdata.as_slice());

    println!("Wrote signature data into file {sigpath:?}");

    Ok(())
}
