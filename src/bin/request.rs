use std::error::Error;
use std::borrow::Cow;

use hard_xml::{XmlWrite};


use ue_rs::omaha;


//
// SERVER=https://public.update.flatcar-linux.net/v1/update/
// GROUP=
//
// FLATCAR_RELEASE_VERSION=3340.0.0+nightly-20220823-2100
// FLATCAR_RELEASE_BOARD=
// FLATCAR_RELEASE_APPID={e96281a6-d1af-4bde-9a0a-97b76e56dc57}
//

const UPDATE_URL: &'static str = "https://public.update.flatcar-linux.net/v1/update/";
const PROTOCOL_VERSION: &'static str = "3.0";
// const UPDATER_VERSION_STR: &'static str = "update-engine-0.4.10";
const UPDATER_VERSION_STR: &'static str = "ue-rs-0.0.0";

const OS_PLATFORM: &'static str = "CoreOS";
const OS_VERSION: &'static str = "Chateau";

const APP_VERSION: &'static str = "3340.0.0+nightly-20220823-2100";
const APP_ID: omaha::Uuid = ue_rs::uuid!("{e96281a6-d1af-4bde-9a0a-97b76e56dc57}");

const MACHINE_ID: &'static str = "abce671d61774703ac7be60715220bfe";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let req_body = {
        let r = omaha::Request {
            protocol_version: Cow::Borrowed(PROTOCOL_VERSION),

            version: Cow::Borrowed(UPDATER_VERSION_STR),
            updater_version: Cow::Borrowed(UPDATER_VERSION_STR),

            install_source: omaha::request::InstallSource::OnDemand,
            is_machine: 1,

            os: omaha::request::OsTag {
                platform: Cow::Borrowed(OS_PLATFORM),
                version: Cow::Borrowed(OS_VERSION),
                service_pack: Cow::Owned(format!("{}_{}", APP_VERSION, "x86_64"))
            },

            apps: vec![
                omaha::request::AppTag {
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
