use std::error::Error;

use ue_rs::download_and_hash;


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
