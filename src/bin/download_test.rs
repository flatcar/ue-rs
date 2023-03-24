use std::error::Error;
use std::io;

use sha2::{Sha256, Digest};

struct DownloadResult<W: std::io::Write> {
    hash: omaha::Hash<omaha::Sha256>,
    data: W
}

async fn download_and_hash<U, W>(client: &reqwest::Client, url: U, mut data: W) -> Result<DownloadResult<W>, Box<dyn Error>>
    where U: reqwest::IntoUrl,
          W: io::Write
{

    let mut res = client.get(url)
        .send()
        .await?;

    let mut hasher = Sha256::new();

    let mut bytes_read = 0usize;
    let bytes_to_read = res.content_length().unwrap_or(u64::MAX) as usize;

    while let Some(chunk) = res.chunk().await? {
        bytes_read += chunk.len();

        hasher.update(&chunk);
        data.write(&chunk)?;

        println!("read {}/{} ({:3}%)",
            bytes_read, bytes_to_read,
            ((bytes_read as f32 / bytes_to_read as f32) * 100.0f32).floor());
    }

    data.flush()?;

    Ok(DownloadResult {
        hash: omaha::Hash::from_bytes(hasher.finalize().into()),
        data
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = reqwest::Client::new();

    let url = std::env::args().nth(1).expect("missing URL (second argument)");

    println!("fetching {}...", url);

    let data = Vec::new();
    let res = download_and_hash(&client, url, data).await?;

    println!("hash: {}", res.hash);

    Ok(())
}
