use std::io::Write;
use std::error::Error;
use std::fs;

use update_format_crau::delta_update;

const PUBKEY_FILE: &str = "../src/testdata/public_key_test_pkcs8.pem";

fn main() -> Result<(), Box<dyn Error>> {
    // TODO: parse args using a decent command-line parameter framework
    let srcpath = std::env::args().nth(1).expect("missing source payload path (second argument)");
    let sigpath = std::env::args().nth(2).expect("missing destination signature path (third argument)");

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
