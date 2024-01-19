use std::error::Error;
use url::Url;
use std::str::FromStr;

use ue_rs::download_and_hash;

fn main() -> Result<(), Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();

    let url = Url::from_str(std::env::args().nth(1).expect("missing URL (second argument)").as_str())?;

    println!("fetching {}...", url);

    let tempdir = tempfile::tempdir()?;
    let path = tempdir.path().join("tmpfile");
    let res = download_and_hash(&client, url, &path, None, None)?;
    tempdir.close()?;

    println!("hash: {}", res.hash_sha256);

    Ok(())
}
