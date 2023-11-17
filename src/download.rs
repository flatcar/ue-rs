use anyhow::{Context, Result, bail};
use std::io::Write;
use std::io;
use log::info;
use url::Url;

use reqwest::StatusCode;

use sha2::{Sha256, Digest};

pub struct DownloadResult<W: std::io::Write> {
    pub hash: omaha::Hash<omaha::Sha256>,
    pub data: W,
}

pub async fn download_and_hash<U, W>(client: &reqwest::Client, url: U, mut data: W) -> Result<DownloadResult<W>>
where
    U: reqwest::IntoUrl + Clone,
    W: io::Write,
    Url: From<U>,
{
    let client_url = url.clone();

    #[rustfmt::skip]
    let mut res = client.get(url)
        .send()
        .await
        .context(format!("client get and send({:?}) failed", client_url.as_str()))?;

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

    let mut hasher = Sha256::new();

    let mut bytes_read = 0usize;
    let bytes_to_read = res.content_length().unwrap_or(u64::MAX) as usize;

    while let Some(chunk) = res.chunk().await.context("failed to get response chunk")? {
        bytes_read += chunk.len();

        hasher.update(&chunk);
        data.write_all(&chunk).context("failed to write_all chunk")?;

        // TODO: better way to report progress?
        print!(
            "\rread {}/{} ({:3}%)",
            bytes_read,
            bytes_to_read,
            ((bytes_read as f32 / bytes_to_read as f32) * 100.0f32).floor()
        );
        io::stdout().flush().context("failed to flush stdout")?;
    }

    data.flush().context("failed to flush data")?;
    println!();

    Ok(DownloadResult {
        hash: omaha::Hash::from_bytes(hasher.finalize().into()),
        data,
    })
}
