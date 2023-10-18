use std::io::Write;
use std::error::Error;
use std::fs;

use update_format_crau::delta_update;

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

    // Extract signature from header.
    let sigbytes = delta_update::get_signatures_bytes(&upfile, &header)?;

    const TESTDATA: &str = "test data for verifying signature";

    // Parse signature data from the signature containing data, version, special fields.
    let sigdata = match delta_update::parse_signature_data(TESTDATA.as_bytes(), &sigbytes, PUBKEY_FILE) {
        Some(data) => Box::leak(data),
        _ => return Err("unable to parse signature data".into()),
    };

    println!("Parsed signature data from file {:?}", srcpath);

    // Store signature into a file.
    let mut sigfile = fs::File::create(sigpath.clone())?;
    let _ = sigfile.write_all(sigdata);

    println!("Wrote signature data into file {:?}", sigpath);

    Ok(())
}
