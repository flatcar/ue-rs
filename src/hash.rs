use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result};
use digest::Digest;

use omaha::HashAlgo;

pub fn hash_on_disk_digest<D>(path: &Path, maxlen: Option<usize>) -> Result<omaha::Hash<D>>
where
    D: Digest + omaha::HashAlgo,
    <D as HashAlgo>::Output: From<Vec<u8>>,
{
    let file = File::open(path).context(format!("failed to open path({:?})", path.display()))?;
    let mut hasher = D::new();

    let filelen = file.metadata().context(format!("failed to get metadata of {:?}", path.display()))?.len() as usize;

    let mut maxlen_to_read: usize = match maxlen {
        Some(len) => {
            if filelen < len {
                filelen
            } else {
                len
            }
        }
        None => filelen,
    };

    const CHUNKLEN: usize = 10485760; // 10M

    let mut freader = BufReader::new(file);
    let mut chunklen: usize;

    freader.seek(SeekFrom::Start(0)).context("failed to seek(0)".to_string())?;
    while maxlen_to_read > 0 {
        if maxlen_to_read < CHUNKLEN {
            chunklen = maxlen_to_read;
        } else {
            chunklen = CHUNKLEN;
        }

        let mut databuf = vec![0u8; chunklen];

        freader.read_exact(&mut databuf).context(format!("failed to read_exact(chunklen {:?})", chunklen))?;

        maxlen_to_read -= chunklen;

        hasher.update(&databuf);
    }

    Ok(omaha::Hash::from_bytes(
        hasher.finalize().to_vec().try_into().unwrap_or_default(),
    ))
}
