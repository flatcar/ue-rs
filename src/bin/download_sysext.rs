use std::error::Error;
use std::borrow::Cow;
use std::ffi::OsStr;
use std::fs::File;
use std::fs;
use std::io;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[macro_use]
extern crate log;

use anyhow::{Context, Result, bail, anyhow};
use argh::FromArgs;
use globset::{Glob, GlobSet, GlobSetBuilder};
use hard_xml::XmlRead;
use omaha::FileSize;
use reqwest::Client;
use reqwest::redirect::Policy;
use url::Url;

use update_format_crau::delta_update;
use ue_rs::hash_on_disk_digest;

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
    // Return Sha256 hash of data in the given path.
    // If maxlen is None, a simple read to the end of the file.
    // If maxlen is Some, read only until the given length.
    fn hash_on_disk(&mut self, path: &Path, maxlen: Option<usize>) -> Result<omaha::Hash<omaha::Sha256>> {
        hash_on_disk_digest::<sha2::Sha256>(path, maxlen)
    }

    #[rustfmt::skip]
    fn check_download(&mut self, in_dir: &Path) -> Result<()> {
        let path = in_dir.join(&*self.name);

        if !path.exists() {
            // skip checking for existing downloads
            info!("{} does not exist, skipping existing downloads.", path.display());
            return Ok(());
        }

        let md = fs::metadata(&path).context({
            format!("failed to get metadata, path ({:?})", path.display())
        })?;

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
            let hash = self.hash_on_disk(&path, None).context({
                format!("failed to hash_on_disk, path ({:?})", path.display())
            })?;
            if self.verify_checksum(hash) {
                info!("{}: good hash, will continue without re-download", path.display());
            } else {
                info!("{}: bad hash, will re-download", path.display());
                self.status = PackageStatus::ToDownload;
            }
        }

        Ok(())
    }

    async fn download(&mut self, into_dir: &Path, client: &reqwest::Client) -> Result<()> {
        // FIXME: use _range_start for completing downloads
        let _range_start = match self.status {
            PackageStatus::ToDownload => 0,
            PackageStatus::DownloadIncomplete(s) => s.bytes(),
            _ => return Ok(()),
        };

        info!("downloading {}...", self.url);

        let path = into_dir.join(&*self.name);
        let mut file = File::create(path.clone()).context(format!("failed to create path ({:?})", path.display()))?;

        let res = match ue_rs::download_and_hash(client, self.url.clone(), &mut file).await {
            Ok(ok) => ok,
            Err(err) => {
                error!("Downloading failed with error {}", err);
                self.status = PackageStatus::DownloadFailed;
                bail!("unable to download data(url {})", self.url);
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
            false
        } else {
            self.status = PackageStatus::Unverified;
            true
        }
    }

    fn verify_signature_on_disk(&mut self, from_path: &Path, pubkey_path: &str) -> Result<PathBuf> {
        let upfile = File::open(from_path).context(format!("failed to open path ({:?})", from_path.display()))?;

        // create a BufReader to pass down to parsing functions.
        let upfreader = &mut BufReader::new(upfile);

        // Read update payload from file, read delta update header from the payload.
        let header = delta_update::read_delta_update_header(upfreader).context(format!("failed to read_delta_update_header path ({:?})", from_path.display()))?;

        let mut delta_archive_manifest = delta_update::get_manifest_bytes(upfreader, &header).context(format!("failed to get_manifest_bytes path ({:?})", from_path.display()))?;

        // Extract signature from header.
        let sigbytes = delta_update::get_signatures_bytes(upfreader, &header, &mut delta_archive_manifest).context(format!("failed to get_signatures_bytes path ({:?})", from_path.display()))?;

        // tmp dir == "/var/tmp/outdir/.tmp"
        let tmpdirpathbuf = from_path.parent().ok_or(anyhow!("unable to get parent dir"))?.parent().ok_or(anyhow!("unable to get parent dir"))?.join(".tmp");
        let tmpdir = tmpdirpathbuf.as_path();
        let datablobspath = tmpdir.join("ue_data_blobs");

        // Get length of header and data, including header and manifest.
        let header_data_length = delta_update::get_header_data_length(&header, &delta_archive_manifest).context("failed to get header data length")?;
        let hdhash = self.hash_on_disk(from_path, Some(header_data_length)).context(format!("failed to hash_on_disk path ({:?}) failed", from_path.display()))?;
        let hdhashvec: Vec<u8> = hdhash.clone().into();

        // Extract data blobs into a file, datablobspath.
        delta_update::get_data_blobs(upfreader, &header, &delta_archive_manifest, datablobspath.as_path()).context(format!("failed to get_data_blobs path ({:?})", datablobspath.display()))?;

        // Check for hash of data blobs with new_partition_info hash.
        let pinfo_hash = match &delta_archive_manifest.new_partition_info.hash {
            Some(hash) => hash,
            None => bail!("unable to get new_partition_info hash"),
        };

        let datahash = self.hash_on_disk(datablobspath.as_path(), None).context(format!("failed to hash_on_disk path ({:?})", datablobspath.display()))?;
        if datahash != omaha::Hash::from_bytes(pinfo_hash.as_slice()[..].try_into().unwrap_or_default()) {
            bail!(
                "mismatch of data hash ({:?}) with new_partition_info hash ({:?})",
                datahash,
                pinfo_hash
            );
        }

        // Parse signature data from sig blobs, data blobs, public key, and verify.
        match delta_update::parse_signature_data(&sigbytes, hdhashvec.as_slice(), pubkey_path) {
            Ok(_) => (),
            _ => {
                self.status = PackageStatus::BadSignature;
                bail!(
                    "unable to parse and verify signature, sigbytes ({:?}), hdhash ({:?}), pubkey_path ({:?})",
                    sigbytes,
                    hdhash,
                    pubkey_path
                );
            }
        };

        println!("Parsed and verified signature data from file {:?}", from_path);

        self.status = PackageStatus::Verified;
        Ok(datablobspath)
    }
}

#[rustfmt::skip]
fn get_pkgs_to_download<'a>(resp: &'a omaha::Response, glob_set: &GlobSet)
        -> Result<Vec<Package<'a>>> {
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

// Read data from remote URL into File
async fn fetch_url_to_file<'a, U>(path: &'a Path, input_url: U, client: &'a Client) -> Result<Package<'a>>
where
    U: reqwest::IntoUrl + From<U> + std::clone::Clone + std::fmt::Debug,
    Url: From<U>,
{
    let mut file = File::create(path).context(format!("failed to create path ({:?})", path.display()))?;

    ue_rs::download_and_hash(client, input_url.clone(), &mut file).await.context(format!("unable to download data(url {:?})", input_url))?;

    Ok(Package {
        name: Cow::Borrowed(path.file_name().unwrap_or(OsStr::new("fakepackage")).to_str().unwrap_or("fakepackage")),
        hash: hash_on_disk_digest::<sha2::Sha256>(path, None)?,
        size: FileSize::from_bytes(file.metadata().context(format!("failed to get metadata, path ({:?})", path.display()))?.len() as usize),
        url: input_url.into(),
        status: PackageStatus::Unverified,
    })
}

async fn do_download_verify(pkg: &mut Package<'_>, output_dir: &Path, unverified_dir: &Path, pubkey_file: &str, client: &Client) -> Result<()> {
    pkg.check_download(unverified_dir)?;

    pkg.download(unverified_dir, client).await.context(format!("unable to download \"{:?}\"", pkg.name))?;

    // Unverified payload is stored in e.g. "output_dir/.unverified/oem.gz".
    // Verified payload is stored in e.g. "output_dir/oem.raw".
    let pkg_unverified = unverified_dir.join(&*pkg.name);
    let pkg_verified = output_dir.join(pkg_unverified.with_extension("raw").file_name().unwrap_or_default());

    let datablobspath = pkg.verify_signature_on_disk(&pkg_unverified, pubkey_file).context(format!("unable to verify signature \"{}\"", pkg.name))?;

    // write extracted data into the final data.
    debug!("data blobs written into file {:?}", pkg_verified);
    fs::rename(datablobspath, pkg_verified)?;

    Ok(())
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let args: Args = argh::from_env();
    println!("{:?}", args);

    let glob_set = args.image_match_glob_set()?;

    let output_dir = Path::new(&*args.output_dir);
    if !output_dir.try_exists()? {
        return Err(format!("output directory `{}` does not exist", args.output_dir).into());
    }

    let unverified_dir = output_dir.join(".unverified");
    let temp_dir = output_dir.join(".tmp");
    fs::create_dir_all(&unverified_dir)?;
    fs::create_dir_all(&temp_dir)?;

    // The default policy of reqwest Client supports max 10 attempts on HTTP redirect.
    let client = Client::builder().redirect(Policy::default()).build()?;

    // If input_xml exists, simply read it.
    // If not, try to read from payload_url.
    let res_local = match args.input_xml {
        Some(name) => {
            if name == "-" {
                Some(io::read_to_string(io::stdin())?)
            } else {
                let file = File::open(name)?;
                Some(io::read_to_string(file)?)
            }
        }
        None => None,
    };

    match (&res_local, args.payload_url) {
        (Some(_), Some(_)) => {
            return Err("Only one of the options can be given, --input-xml or --payload-url.".into());
        }
        (Some(res), None) => res,
        (None, Some(url)) => {
            let u = Url::parse(&url)?;
            let fname = u.path_segments().ok_or(anyhow!("failed to get path segments, url ({:?})", u))?.next_back().ok_or(anyhow!("failed to get path segments, url ({:?})", u))?;
            let mut pkg_fake: Package;

            let temp_payload_path = unverified_dir.join(fname);
            pkg_fake = fetch_url_to_file(
                &temp_payload_path,
                Url::from_str(url.as_str()).context(anyhow!("failed to convert into url ({:?})", url))?,
                &client,
            )
            .await?;
            do_download_verify(
                &mut pkg_fake,
                output_dir,
                unverified_dir.as_path(),
                args.pubkey_file.as_str(),
                &client,
            )
            .await?;

            // verify only a fake package, early exit and skip the rest.
            return Ok(());
        }
        (None, None) => return Err("Either --input-xml or --payload-url must be given.".into()),
    };

    let response_text = res_local.ok_or(anyhow!("failed to get response text"))?;
    debug!("response_text: {:?}", response_text);

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

    for pkg in pkgs_to_dl.iter_mut() {
        do_download_verify(pkg, output_dir, unverified_dir.as_path(), args.pubkey_file.as_str(), &client).await?;
    }

    // clean up data
    fs::remove_dir_all(temp_dir)?;

    Ok(())
}
