use std::error::Error;
use std::borrow::Cow;
use std::path::Path;
use std::fs::File;
use std::io;

#[macro_use]
extern crate log;

use globset::{Glob, GlobSet, GlobSetBuilder};
use hard_xml::XmlRead;
use argh::FromArgs;
use url::Url;

#[derive(Debug)]
struct Package<'a> {
    url: Url,
    name: Cow<'a, str>,
    hash: omaha::Hash<omaha::Sha256>,
}

#[rustfmt::skip]
fn get_pkgs_to_download<'a>(resp: &'a omaha::Response, glob_set: &GlobSet)
        -> Result<Vec<Package<'a>>, Box<dyn Error>> {
    let mut to_download: Vec<_> = Vec::new();

    for app in &resp.apps {
        let manifest = &app.update_check.manifest;

        for pkg in &manifest.packages {
            if !glob_set.is_match(&*pkg.name) {
                info!("package `{}` doesn't match glob pattern, skipping", pkg.name);
                continue;
            }

            let hash_sha256 = pkg.hash_sha256.as_ref();

            // TODO: multiple URLs per package
            //       not sure if nebraska sends us more than one right now but i suppose this is
            //       for mirrors?
            let url = app.update_check.urls.get(0)
                .map(|u| u.join(&pkg.name));

            match (url, hash_sha256) {
                (Some(Ok(url)), Some(hash)) => {
                    to_download.push(Package {
                        url,
                        name: Cow::Borrowed(&pkg.name),
                        hash: hash.clone()
                    })
                }

                (Some(Ok(_)), None) => {
                    warn!("package `{}` doesn't have a valid SHA256 hash, skipping", pkg.name);
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

    /// glob pattern to match update URLs.
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
    env_logger::init();

    let args: Args = argh::from_env();
    println!("{:?}", args);

    let glob_set = args.image_match_glob_set()?;

    let response_text = match &*args.input_xml {
        "-" => io::read_to_string(io::stdin())?,
        path => {
            let file = File::open(path)?;
            io::read_to_string(file)?
        }
    };

    let output_dir = Path::new(&*args.output_dir);
    if !output_dir.try_exists()? {
        return Err(format!("output directory `{}` does not exist", args.output_dir).into());
    }

    ////
    // parse response
    ////
    let resp = omaha::Response::from_str(&response_text)?;

    let pkgs_to_dl = get_pkgs_to_download(&resp, &glob_set)?;

    println!("pkgs:\n\t{:#?}", pkgs_to_dl);
    println!();

    ////
    // download
    ////
    let client = reqwest::Client::new();

    for pkg in pkgs_to_dl {
        println!("downloading {}...", pkg.url);

        let path = output_dir.join(&*pkg.name);
        let mut file = File::create(path)?;

        let res = ue_rs::download_and_hash(&client, pkg.url, &mut file).await?;

        println!("\texpected sha256:   {}", pkg.hash);
        println!("\tcalculated sha256: {}", res.hash);
        println!("\tsha256 match?      {}", pkg.hash == res.hash);
    }

    Ok(())
}
