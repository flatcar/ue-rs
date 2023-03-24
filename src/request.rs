use std::error::Error;
use std::borrow::Cow;

use hard_xml::XmlWrite;
use omaha;


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

const APP_ID: omaha::Uuid = omaha::uuid!("{e96281a6-d1af-4bde-9a0a-97b76e56dc57}");


pub struct Parameters<'a> {
    pub app_version: Cow<'a, str>,
    pub track: Cow<'a, str>,

    pub machine_id: Cow<'a, str>,
}

pub async fn perform<'a>(client: &reqwest::Client, parameters: Parameters<'a>) -> Result<String, Box<dyn Error>> {
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
                service_pack: Cow::Owned(
                    format!("{}_{}", parameters.app_version, "x86_64")
                )
            },

            apps: vec![
                omaha::request::App {
                    id: APP_ID,
                    version: parameters.app_version,
                    track: parameters.track,

                    boot_id: None,

                    oem: None,
                    oem_version: None,

                    machine_id: parameters.machine_id,

                    update_check: Some(omaha::request::AppUpdateCheck)
                }
            ]
        };

        r.to_string()?
    };

    // TODO: remove
    println!("request body:\n\t{}", req_body);
    println!();

    let resp = client.post(UPDATE_URL)
        .body(req_body)
        .send()
        .await?;

    Ok(resp.text().await?)
}
