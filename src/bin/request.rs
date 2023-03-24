use std::error::Error;
use std::borrow::Cow;

use ue_rs::request;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = reqwest::Client::new();

    let parameters = request::Parameters {
        app_version: Cow::Borrowed("3340.0.0+nightly-20220823-2100"),
        machine_id:  Cow::Borrowed("abce671d61774703ac7be60715220bfe"),

        track: Cow::Borrowed("stable")
    };

    let response = request::perform(&client, parameters).await?;

    println!("response:\n\t{:#?}", response);

    Ok(())
}
