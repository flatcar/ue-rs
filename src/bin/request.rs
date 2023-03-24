use std::error::Error;

use ue_rs::perform_request;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = reqwest::Client::new();
    let response = perform_request(&client).await?;

    println!("response:\n\t{:#?}", response);

    Ok(())
}
