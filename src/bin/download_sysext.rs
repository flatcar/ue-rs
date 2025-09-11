use std::error::Error;

extern crate log;

use anyhow::Result;
use argh::FromArgs;
use globset::{Glob, GlobSet, GlobSetBuilder};

use ue_rs::DownloadVerify;

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

    let glob_set = args.image_match_glob_set()?;

    DownloadVerify::new(
        args.output_dir,
        args.target_filename,
        args.input_xml,
        args.pubkey_file,
        args.payload_url,
        args.take_first_match,
        glob_set,
    )
    .run()?;

    Ok(())
}
