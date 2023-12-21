use anyhow::{Context, Result, bail};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::fs::File;
use std::path::Path;
use log::info;
use url::Url;

use reqwest::StatusCode;
use reqwest::blocking::Client;

use sha2::{Sha256, Digest};

const MAX_DOWNLOAD_RETRY: u32 = 20;

pub struct DownloadResult {
    pub hash: omaha::Hash<omaha::Sha256>,
    pub data: File,
}

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

fn do_download_and_hash<U>(client: &Client, url: U, path: &Path, print_progress: bool) -> Result<DownloadResult>
where
    U: reqwest::IntoUrl + Clone,
    Url: From<U>,
{
    let client_url = url.clone();

    #[rustfmt::skip]
    let mut res = client.get(url.clone())
        .send()
        .context(format!("client get & send{:?} failed ", client_url.as_str()))?;

    // Redirect was already handled at this point, so there is no need to touch
    // response or url again. Simply print info and continue.
    if <U as Into<Url>>::into(client_url) != *res.url() {
        info!("redirected to URL {:?}", res.url());
    }

    // Return immediately on download failure on the client side.
    let status = res.status();

    if !status.is_success() {
        match status {
            StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => {
                bail!("cannnot fetch remotely with status code {:?}", status);
            }
            _ => bail!("general failure with status code {:?}", status),
        }
    }

    if print_progress {
        println!("writing to {}", path.display());
    }
    let mut file = File::create(path).context(format!("failed to create path ({:?})", path.display()))?;
    res.copy_to(&mut file)?;

    Ok(DownloadResult {
        hash: hash_on_disk_sha256(path, None)?,
        data: file,
    })
}

pub fn download_and_hash<U>(client: &Client, url: U, path: &Path, print_progress: bool) -> Result<DownloadResult>
where
    U: reqwest::IntoUrl + Clone,
    Url: From<U>,
{
    crate::retry_loop(
        || do_download_and_hash(client, url.clone(), path, print_progress),
        MAX_DOWNLOAD_RETRY,
    )
}
