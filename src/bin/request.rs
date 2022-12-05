use std::error::Error;
use std::borrow::Cow;

use hard_xml::XmlWrite;


//
// SERVER=https://public.update.flatcar-linux.net/v1/update/
// GROUP=
//
// FLATCAR_RELEASE_VERSION=3340.0.0+nightly-20220823-2100
// FLATCAR_RELEASE_BOARD=
// FLATCAR_RELEASE_APPID={e96281a6-d1af-4bde-9a0a-97b76e56dc57}
//

const UPDATE_URL: &str = "https://public.update.flatcar-linux.net/v1/update/";
const PROTOCOL_VERSION: &str = "3.0";
const UPDATER_VERSION_STR: &str = "ue-rs-0.0.0";

const OS_PLATFORM: &str = "CoreOS";
const OS_VERSION: &str = "Chateau";

const APP_VERSION: &str = "3340.0.0+nightly-20220823-2100";
const APP_ID: omaha::Uuid = omaha::uuid!("{e96281a6-d1af-4bde-9a0a-97b76e56dc57}");

const MACHINE_ID: &str = "abce671d61774703ac7be60715220bfe";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let req_body = {
        let r = omaha::Request {
            protocol_version: Cow::Borrowed(PROTOCOL_VERSION),

            version: Cow::Borrowed(UPDATER_VERSION_STR),
            updater_version: Cow::Borrowed(UPDATER_VERSION_STR),

            install_source: omaha::request::InstallSource::OnDemand,
            is_machine: 1,

            os: omaha::request::Os {
                platform: Cow::Borrowed(OS_PLATFORM),
                version: Cow::Borrowed(OS_VERSION),
                service_pack: Cow::Owned(format!("{}_{}", APP_VERSION, "x86_64"))
            },

            apps: vec![
                omaha::request::App {
                    id: APP_ID,
                    version: Cow::Borrowed(APP_VERSION),
                    track: Cow::Borrowed("stable"),

                    boot_id: None,

                    oem: None,
                    oem_version: None,

                    machine_id: Cow::Borrowed(MACHINE_ID),

                    update_check: Some(omaha::request::AppUpdateCheck)
                }
            ]
        };

        r.to_string()?
    };

    println!("{}", req_body);

    // return Ok(());

    let client = reqwest::Client::new();
    let resp = client.post(UPDATE_URL)
        .body(req_body)
        .send()
        .await?;

    println!("{:#?}", resp);

    println!("{:#?}", resp.text().await?);

    Ok(())
}
