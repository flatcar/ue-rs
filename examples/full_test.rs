use std::error::Error;
use std::borrow::Cow;

use hard_xml::XmlRead;
use url::Url;
use omaha::Sha256Digest;

fn get_pkgs_to_download(resp: &omaha::Response) -> Result<Vec<(Url, Sha256Digest)>, ()> {
    let mut to_download: Vec<(Url, Sha256Digest)> = Vec::new();

    for app in &resp.apps {
        let manifest = &app.update_check.manifest;

        for pkg in &manifest.packages {
            #[rustfmt::skip]
            let hash_sha256 = pkg.hash_sha256
                .as_ref()
                .or_else(|| {
                    manifest.actions.iter()
                        .find(|a| a.event == omaha::response::ActionEvent::PostInstall)
                        .map(|a| &a.sha256)
                });

            // TODO: multiple URLs per package
            //       not sure if nebraska sends us more than one right now but i suppose this is
            //       for mirrors?
            #[rustfmt::skip]
            let url = app.update_check.urls.get(0)
                .map(|u| u.join(&pkg.name));

            match (url, hash_sha256) {
                (Some(Ok(url)), Some(hash)) => {
                    to_download.push((url, hash.clone()));
                }

                _ => (),
            }
        }
    }

    Ok(to_download)
}

fn main() -> Result<(), Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();

    const APP_VERSION_DEFAULT: &str = "3340.0.0+nightly-20220823-2100";
    const MACHINE_ID_DEFAULT: &str = "abce671d61774703ac7be60715220bfe";
    const TRACK_DEFAULT: &str = "stable";

    ////
    // request
    ////
    let parameters = ue_rs::request::Parameters {
        app_version: Cow::Borrowed(APP_VERSION_DEFAULT),
        machine_id: Cow::Borrowed(MACHINE_ID_DEFAULT),

        track: Cow::Borrowed(TRACK_DEFAULT),
    };

    let response_text = ue_rs::request::perform(&client, parameters)?;

    println!("response:\n\t{:#?}", response_text);
    println!();

    ////
    // parse response
    ////
    let resp = omaha::Response::from_str(&response_text)?;

    // TODO: fine for an example but shouldnt recommend
    let pkgs_to_dl = get_pkgs_to_download(&resp).unwrap();

    ////
    // download
    ////
    for (url, expected_sha256) in pkgs_to_dl {
        println!("downloading {}...", url);

        let tempdir = tempfile::tempdir()?;
        let path = tempdir.path().join("tmpfile");
        let res = ue_rs::download_and_hash(&client, url.clone(), &path, Some(expected_sha256.clone()), None)?;
        tempdir.close()?;

        println!("\texpected sha256:   {:?}", expected_sha256);
        println!("\tcalculated sha256: {:?}", res.hash_sha256);
        println!("\tsha256 match?      {:?}", expected_sha256 == res.hash_sha256);
    }

    Ok(())
}
