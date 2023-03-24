use std::error::Error;

use hard_xml::XmlRead;
use url::Url;


fn get_pkgs_to_download(resp: &omaha::Response) -> Result<Vec<(Url, omaha::Hash<omaha::Sha256>)>, Box<dyn Error>> {
    let mut to_download: Vec<(Url, omaha::Hash<_>)> = Vec::new();

    for app in &resp.apps {
        let manifest = &app.update_check.manifest;

        for pkg in &manifest.packages {
            let hash_sha256 = pkg.hash_sha256
                .as_ref()
                .or_else(|| {
                    manifest.actions.iter()
                        .find(|a| a.event == omaha::response::ActionEvent::PostInstall)
                        .map(|a| &a.sha256)
                });

            let url = app.update_check.urls.get(0)
                .map(|u| u.join(&pkg.name));

            match (url, hash_sha256) {
                (Some(Ok(url)), Some(hash)) => {
                    to_download.push((url, hash.clone()));
                },

                _ => ()
            }
        }
    }

    Ok(to_download)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = reqwest::Client::new();
    let response_text = ue_rs::perform_request(&client).await?;

    println!("response:\n\t{:#?}", response_text);
    println!();

    let resp = omaha::Response::from_str(&response_text)?;

    let pkgs_to_dl = get_pkgs_to_download(&resp)?;

    for (url, expected_sha256) in pkgs_to_dl {
        println!("downloading {}...", url);

        // TODO: use a file or anything that implements std::io::Write here.
        //       std::io::BufWriter wrapping an std::fs::File is probably the right choice.
        //       std::io::sink() is basically just /dev/null
        let data = std::io::sink();
        let res = ue_rs::download_and_hash(&client, url, data).await?;

        println!("\texpected sha256:   {}", expected_sha256);
        println!("\tcalculated sha256: {}", res.hash);
        println!("\tsha256 match?      {}", expected_sha256 == res.hash);
    }

    Ok(())
}
