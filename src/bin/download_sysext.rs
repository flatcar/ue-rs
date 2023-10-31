use std::error::Error;
use std::borrow::Cow;
use std::path::Path;
use std::fs::File;
use std::fs;
use std::io;

#[macro_use]
extern crate log;

use globset::{Glob, GlobSet, GlobSetBuilder};
use hard_xml::XmlRead;
use argh::FromArgs;
use url::Url;

use update_format_crau::delta_update;

#[derive(Debug)]
enum PackageStatus {
    ToDownload,
    DownloadIncomplete(omaha::FileSize),
    DownloadFailed,
    BadChecksum,
    Unverified,
    BadSignature,
    Verified,
}

#[derive(Debug)]
struct Package<'a> {
    url: Url,
    name: Cow<'a, str>,
    hash: omaha::Hash<omaha::Sha256>,
    size: omaha::FileSize,
    status: PackageStatus,
}

impl<'a> Package<'a> {
    #[rustfmt::skip]
    fn hash_on_disk(&mut self, path: &Path) -> Result<omaha::Hash<omaha::Sha256>, Box<dyn Error>> {
        use sha2::{Sha256, Digest};

        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();

        io::copy(&mut file, &mut hasher)?;

        Ok(omaha::Hash::from_bytes(
            hasher.finalize().into()
        ))
    }

    #[rustfmt::skip]
    fn check_download(&mut self, in_dir: &Path) -> Result<(), Box<dyn Error>> {
        let path = in_dir.join(&*self.name);
        let md = fs::metadata(&path)?;

        let size_on_disk = md.len() as usize;
        let expected_size = self.size.bytes();

        if size_on_disk < expected_size {
            info!("{}: have downloaded {}/{} bytes, will resume", path.display(), size_on_disk, expected_size);

            self.status = PackageStatus::DownloadIncomplete(
                omaha::FileSize::from_bytes(size_on_disk)
            );
            return Ok(());
        }

        if size_on_disk == expected_size {
            info!("{}: download complete, checking hash...", path.display());
            let hash = self.hash_on_disk(&path)?;
            if self.verify_checksum(hash) {
                info!("{}: good hash, will continue without re-download", path.display());
            } else {
                info!("{}: bad hash, will re-download", path.display());
                self.status = PackageStatus::ToDownload;
            }
        }

        Ok(())
    }

    async fn download(&mut self, into_dir: &Path, client: &reqwest::Client) -> Result<(), Box<dyn Error>> {
        // FIXME: use _range_start for completing downloads
        let _range_start = match self.status {
            PackageStatus::ToDownload => 0,
            PackageStatus::DownloadIncomplete(s) => s.bytes(),
            _ => return Ok(()),
        };

        info!("downloading {}...", self.url);

        let path = into_dir.join(&*self.name);
        let mut file = File::create(path)?;

        let res = match ue_rs::download_and_hash(&client, self.url.clone(), &mut file).await {
            Ok(ok) => ok,
            Err(err) => {
                error!("Downloading failed with error {}", err);
                self.status = PackageStatus::DownloadFailed;
                return Err("unable to download data".into());
            }
        };

        self.verify_checksum(res.hash);
        Ok(())
    }

    fn verify_checksum(&mut self, calculated: omaha::Hash<omaha::Sha256>) -> bool {
        debug!("    expected sha256:   {}", self.hash);
        debug!("    calculated sha256: {}", calculated);
        debug!("    sha256 match?      {}", self.hash == calculated);

        if self.hash != calculated {
            self.status = PackageStatus::BadChecksum;
            return false;
        } else {
            self.status = PackageStatus::Unverified;
            return true;
        }
    }

    fn verify_signature_on_disk(&mut self, from_path: &Path, pubkey_path: &str) -> Result<(), Box<dyn Error>> {
        let upfile = File::open(from_path)?;

        // Read update payload from file, read delta update header from the payload.
        let res_data = fs::read_to_string(from_path);

        let header = delta_update::read_delta_update_header(&upfile)?;

        // Extract signature from header.
        let sigbytes = delta_update::get_signatures_bytes(&upfile, &header)?;

        // Parse signature data from the signature containing data, version, special fields.
        let _sigdata = match delta_update::parse_signature_data(res_data.unwrap().as_bytes(), &sigbytes, pubkey_path) {
            Some(data) => data,
            _ => {
                self.status = PackageStatus::BadSignature;
                return Err("unable to parse signature data".into());
            }
        };

        println!("Parsed and verified signature data from file {:?}", from_path);

        self.status = PackageStatus::Verified;
        Ok(())
    }
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
                        hash: hash.clone(),
                        size: pkg.size,
                        status: PackageStatus::ToDownload
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

    /// path to the public key file
    #[argh(option, short = 'p')]
    pubkey_file: String,

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

    let unverified_dir = output_dir.join(".unverified");
    fs::create_dir_all(&unverified_dir)?;

    ////
    // parse response
    ////
    let resp = omaha::Response::from_str(&response_text)?;

    let mut pkgs_to_dl = get_pkgs_to_download(&resp, &glob_set)?;

    debug!("pkgs:\n\t{:#?}", pkgs_to_dl);
    debug!("");

    ////
    // download
    ////
    let client = reqwest::Client::new();

    for pkg in pkgs_to_dl.iter_mut() {
        pkg.check_download(&unverified_dir)?;

        match pkg.download(&unverified_dir, &client).await {
            Ok(_) => (),
            _ => return Err(format!("unable to download \"{}\"", pkg.name).into()),
        };

        let pkg_unverified = unverified_dir.join(&*pkg.name);
        let pkg_verified = output_dir.join(&*pkg.name);

        match pkg.verify_signature_on_disk(&pkg_unverified, &args.pubkey_file) {
            Ok(_) => {
                // move the verified file back from unverified_dir to output_dir
                fs::rename(&pkg_unverified, &pkg_verified)?;
            }
            _ => return Err(format!("unable to verify signature \"{}\"", pkg.name).into()),
        };
    }

    Ok(())
}
