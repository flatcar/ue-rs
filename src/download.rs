use anyhow::{Context, Result, bail};
use std::io::{BufReader, Read};
use std::fs::File;
use std::path::Path;
use log::{info, debug};
use url::Url;

use reqwest::StatusCode;
use reqwest::blocking::Client;

use sha2::digest::DynDigest;

const MAX_DOWNLOAD_RETRY: u32 = 20;

pub struct DownloadResult {
    pub hash_sha256: omaha::Hash<omaha::Sha256>,
    pub hash_sha1: omaha::Hash<omaha::Sha1>,
    pub data: File,
}

pub fn hash_on_disk<T: omaha::HashAlgo>(path: &Path, maxlen: Option<usize>) -> Result<omaha::Hash<T>> {
    let file = File::open(path).context(format!("failed to open path({:?})", path.display()))?;
    let mut hasher = T::hasher();

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

    Ok(omaha::Hash::from_bytes(Box::new(hasher).finalize()))
}

fn do_download_and_hash<U>(client: &Client, url: U, path: &Path, expected_sha256: Option<omaha::Hash<omaha::Sha256>>, expected_sha1: Option<omaha::Hash<omaha::Sha1>>) -> Result<DownloadResult>
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

    println!("writing to {}", path.display());

    let mut file = File::create(path).context(format!("failed to create path ({:?})", path.display()))?;
    res.copy_to(&mut file)?;

    let calculated_sha256 = hash_on_disk::<omaha::Sha256>(path, None)?;
    let calculated_sha1 = hash_on_disk::<omaha::Sha1>(path, None)?;

    debug!("    expected sha256:   {:?}", expected_sha256);
    debug!("    calculated sha256: {}", calculated_sha256);
    debug!("    sha256 match?      {}", expected_sha256 == Some(calculated_sha256.clone()));
    debug!("    expected sha1:   {:?}", expected_sha1);
    debug!("    calculated sha1: {}", calculated_sha1);
    debug!("    sha1 match?      {}", expected_sha1 == Some(calculated_sha1.clone()));

    if expected_sha256.is_some() && expected_sha256 != Some(calculated_sha256.clone()) {
        bail!("Checksum mismatch for sha256");
    }
    if expected_sha1.is_some() && expected_sha1 != Some(calculated_sha1.clone()) {
        bail!("Checksum mismatch for sha1");
    }

    Ok(DownloadResult {
        hash_sha256: calculated_sha256,
        hash_sha1: calculated_sha1,
        data: file,
    })
}

pub fn download_and_hash<U>(client: &Client, url: U, path: &Path, expected_sha256: Option<omaha::Hash<omaha::Sha256>>, expected_sha1: Option<omaha::Hash<omaha::Sha1>>) -> Result<DownloadResult>
where
    U: reqwest::IntoUrl + Clone,
    Url: From<U>,
{
    crate::retry_loop(
        || do_download_and_hash(client, url.clone(), path, expected_sha256.clone(), expected_sha1.clone()),
        MAX_DOWNLOAD_RETRY,
    )
}
