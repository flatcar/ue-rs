use std::error::Error;
use std::borrow::Cow;
use std::io::prelude::*;
use std::fs;
use std::io;

use globset::{Glob, GlobSet, GlobSetBuilder};
use hard_xml::XmlRead;
use argh::FromArgs;
use url::Url;

fn get_pkgs_to_download(resp: &omaha::Response, glob_set: &GlobSet)
        -> Result<Vec<(Url, omaha::Hash<omaha::Sha256>)>, Box<dyn Error>> {
    let mut to_download: Vec<(Url, omaha::Hash<_>)> = Vec::new();

    for app in &resp.apps {
        let manifest = &app.update_check.manifest;

        for pkg in &manifest.packages {
            if !glob_set.is_match(&*pkg.name) {
                continue
            }

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

#[derive(FromArgs, Debug)]
/// Parse an update-engine Omaha XML response to extract sysext images, then download and verify
/// their signatures.
struct Args {
    /// the directory to download the sysext images into
    #[argh(option, short = 'o')]
    output_dir: String,

    /// path to the Omaha XML file, or - to read from stdin
    #[argh(option, short = 'i')]
    input_xml: String,

    /// regex pattern to match update URLs.
    /// may be specified multiple times.
    #[argh(option, short = 'm')]
    image_match: Vec<String>,
}

impl Args {
    fn image_match_glob_set(&self) -> Result<GlobSet, globset::Error> {
        let mut builder = GlobSetBuilder::new();

        for m in &*self.image_match {
            builder.add(Glob::new(&*m)?);
        }

        builder.build()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Args = argh::from_env();
    println!("{:?}", args);

    let glob_set = args.image_match_glob_set()?;

    let response_text = match &*args.input_xml {
        "-" => io::read_to_string(io::stdin())?,
        path => {
            let file = fs::File::open(path)?;
            io::read_to_string(file)?
        }
    };

    ////
    // parse response
    ////
    let resp = omaha::Response::from_str(&response_text)?;

    let pkgs_to_dl = get_pkgs_to_download(&resp, &glob_set)?;

    println!("pkgs:\n\t{:#?}", pkgs_to_dl);
    println!();

    return Ok(());

    // ////
    // // download
    // ////
    // for (url, expected_sha256) in pkgs_to_dl {
    //     println!("downloading {}...", url);

    //     // TODO: use a file or anything that implements std::io::Write here.
    //     //       std::io::BufWriter wrapping an std::fs::File is probably the right choice.
    //     //       std::io::sink() is basically just /dev/null
    //     let data = std::io::sink();
    //     let res = ue_rs::download_and_hash(&client, url, data).await?;

    //     println!("\texpected sha256:   {}", expected_sha256);
    //     println!("\tcalculated sha256: {}", res.hash);
    //     println!("\tsha256 match?      {}", expected_sha256 == res.hash);
    // }

    // Ok(())
}
