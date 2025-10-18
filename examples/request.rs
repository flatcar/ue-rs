use std::error::Error;
use std::borrow::Cow;

use ue_rs::request;

fn main() -> Result<(), Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();

    const APP_VERSION_DEFAULT: &str = "3340.0.0+nightly-20220823-2100";
    const MACHINE_ID_DEFAULT: &str = "abce671d61774703ac7be60715220bfe";
    const TRACK_DEFAULT: &str = "stable";

    let parameters = request::Parameters {
        app_version: Cow::Borrowed(APP_VERSION_DEFAULT),
        machine_id: Cow::Borrowed(MACHINE_ID_DEFAULT),

        track: Cow::Borrowed(TRACK_DEFAULT),
    };

    let response = request::perform(&client, parameters)?;

    println!("response:\n\t{:#?}", response);

    Ok(())
}
