use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use sha2::{Sha256, Digest};

pub fn hash_on_disk_sha256(path: &Path, maxlen: Option<usize>) -> Result<omaha::Hash<omaha::Sha256>> {
    let file = File::open(path).context(format!("failed to open path({:?})", path.display()))?;
    let mut hasher = Sha256::new();

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

    Ok(omaha::Hash::from_bytes(hasher.finalize().into()))
}
