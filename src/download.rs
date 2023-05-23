use std::error::Error;
use std::io::Write;
use std::io;

use sha2::{Sha256, Digest};


pub struct DownloadResult<W: std::io::Write> {
    pub hash: omaha::Hash<omaha::Sha256>,
    pub data: W
}

pub async fn download_and_hash<U, W>(client: &reqwest::Client, url: U, mut data: W) -> Result<DownloadResult<W>, Box<dyn Error>>
    where U: reqwest::IntoUrl,
          W: io::Write
{

    #[rustfmt::skip]
    let mut res = client.get(url)
        .send()
        .await?;

    let mut hasher = Sha256::new();

    let mut bytes_read = 0usize;
    let bytes_to_read = res.content_length().unwrap_or(u64::MAX) as usize;

    while let Some(chunk) = res.chunk().await? {
        bytes_read += chunk.len();

        hasher.update(&chunk);
        data.write_all(&chunk)?;

        // TODO: better way to report progress?
        print!("\rread {}/{} ({:3}%)",
            bytes_read, bytes_to_read,
            ((bytes_read as f32 / bytes_to_read as f32) * 100.0f32).floor());
        io::stdout().flush()?;
    }

    data.flush()?;
    println!();

    Ok(DownloadResult {
        hash: omaha::Hash::from_bytes(hasher.finalize().into()),
        data
    })
}
