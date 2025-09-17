use std::error::Error;
use std::fs::File;
use std::io;
use std::path::Path;

#[macro_use]
extern crate log;

use anyhow::Result;
use argh::FromArgs;
use globset::{Glob, GlobSet, GlobSetBuilder};

use ue_rs::{TARGET_FILENAME_DEFAULT, DownloadVerify};

#[derive(FromArgs, Debug)]
/// Parse an update-engine Omaha XML response to extract sysext images, then download and verify
/// their signatures.
struct Args {
    /// the directory to download the sysext images into
    #[argh(option, short = 'o')]
    output_dir: String,

    /// target filename in directory, requires --payload-url or --take-first-match
    #[argh(option, short = 'n')]
    target_filename: Option<String>,

    /// path to the Omaha XML file, or - to read from stdin
    #[argh(option, short = 'i')]
    input_xml: Option<String>,

    /// URL to fetch remote update payload
    #[argh(option, short = 'u')]
    payload_url: Option<String>,

    /// path to the public key file
    #[argh(option, short = 'p')]
    pubkey_file: String,

    /// glob pattern to match update URLs.
    /// may be specified multiple times.
    #[argh(option, short = 'm')]
    image_match: Vec<String>,

    /// only take the first matching entry
    #[argh(switch, short = 't')]
    take_first_match: bool,
}

impl Args {
    fn image_match_glob_set(&self) -> Result<GlobSet, globset::Error> {
        let mut builder = GlobSetBuilder::new();

        for m in &*self.image_match {
            builder.add(Glob::new(m)?);
        }

        builder.build()
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let args: Args = argh::from_env();
    println!("{args:?}");

    if args.payload_url.is_none() && !args.take_first_match && args.target_filename.is_some() {
        return Err("--target-filename can only be specified with --take-first-match".into());
    }

    let output_dir = Path::new(&args.output_dir);
    if !output_dir.try_exists()? {
        return Err(format!("output directory `{:?}` does not exist", output_dir).into());
    }

    // If input_xml exists, simply read it.
    // If not, try to read from payload_url.
    let input_xml = match args.input_xml.clone() {
        Some(name) => {
            if name == "-" {
                Some(io::read_to_string(io::stdin())?)
            } else {
                let file = File::open(name)?;
                Some(io::read_to_string(file)?)
            }
        }
        None => {
            info!("failed to get input xml file, fall back to payload_url");
            None
        }
    };

    let payload_url = match (&input_xml, args.payload_url.clone()) {
        (Some(_), Some(_)) => {
            return Err("only one of the options can be given, --input-xml or --payload-url.".into());
        }
        (Some(_), None) => return Ok(()),
        (None, Some(url)) => &url.clone(),
        (None, None) => return Err("either --input-xml or --payload-url must be given.".into()),
    };

    let glob_set = args.image_match_glob_set()?;

    DownloadVerify::new(args.output_dir, args.pubkey_file, args.take_first_match, glob_set)
        .target_filename(args.target_filename.unwrap_or(TARGET_FILENAME_DEFAULT.into()))
        .input_xml(input_xml.unwrap_or_default())
        .payload_url(payload_url.clone())
        .run()?;

    Ok(())
}
