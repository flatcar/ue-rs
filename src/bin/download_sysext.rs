use std::error::Error;
use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::fs::File;
use std::fs;
use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::io::BufReader;

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
    fn hash_on_disk(&mut self, path: &Path, maxlen: Option<usize>) -> Result<omaha::Hash<omaha::Sha256>, Box<dyn Error>> {
        use sha2::{Sha256, Digest};

        let file = File::open(path)?;
        let mut hasher = Sha256::new();

        let filelen = file.metadata().unwrap().len() as usize;

        let mut maxlen_to_read: usize = match maxlen {
            Some(len) => {
                if filelen < len {
                    filelen
                } else {
                    len
                }
            }
            None => filelen,
        };

        const CHUNKLEN: usize = 10485760; // 10M

        let mut freader = BufReader::new(file);
        let mut chunklen: usize;

        freader.seek(SeekFrom::Start(0))?;
        while maxlen_to_read > 0 {
            if maxlen_to_read < CHUNKLEN {
                chunklen = maxlen_to_read;
            } else {
                chunklen = CHUNKLEN;
            }

            let mut databuf = vec![0u8; chunklen];

            freader.read_exact(&mut databuf)?;

            maxlen_to_read -= chunklen;

            hasher.update(&databuf);
        }

        Ok(omaha::Hash::from_bytes(
            hasher.finalize().into()
        ))
    }

    #[rustfmt::skip]
    fn check_download(&mut self, in_dir: &Path) -> Result<(), Box<dyn Error>> {
        let path = in_dir.join(&*self.name);

        if !path.exists() {
            // skip checking for existing downloads
            info!("{} does not exist, skipping existing downloads.", path.display());
            return Ok(());
        }

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
            let hash = self.hash_on_disk(&path, None)?;
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

        let res = ue_rs::download_and_hash(&client, self.url.clone(), &mut file).await?;

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

    fn verify_signature_on_disk(&mut self, from_path: &Path, pubkey_path: &str) -> Result<PathBuf, Box<dyn Error>> {
        let upfile = File::open(from_path)?;

        // create a BufReader to pass down to parsing functions.
        let upfreader = &mut BufReader::new(upfile);

        // Read update payload from file, read delta update header from the payload.
        let header = delta_update::read_delta_update_header(upfreader)?;

        let mut delta_archive_manifest = delta_update::get_manifest_bytes(upfreader, &header)?;

        // Extract signature from header.
        let sigbytes = delta_update::get_signatures_bytes(upfreader, &header, &mut delta_archive_manifest)?;

        // tmp dir == "/var/tmp/outdir/.tmp"
        let tmpdirpathbuf = from_path.parent().unwrap().parent().unwrap().join(".tmp");
        let tmpdir = tmpdirpathbuf.as_path();
        let datablobspath = tmpdir.join("ue_data_blobs");

        // Get length of header and data, including header and manifest.
        let header_data_length = delta_update::get_header_data_length(&header, &delta_archive_manifest);
        let hdhash = self.hash_on_disk(from_path, Some(header_data_length))?;
        let hdhashvec: Vec<u8> = hdhash.into();

        // Extract data blobs into a file, datablobspath.
        delta_update::get_data_blobs(upfreader, &header, &delta_archive_manifest, datablobspath.as_path())?;

        // Check for hash of data blobs with new_partition_info hash.
        let pinfo_hash = match &delta_archive_manifest.new_partition_info.hash {
            Some(hash) => hash,
            None => return Err("unable to parse signature data".into()),
        };

        let datahash = self.hash_on_disk(datablobspath.as_path(), None)?;
        if datahash != omaha::Hash::from_bytes(pinfo_hash.as_slice()[..].try_into().unwrap_or_default()) {
            return Err("data hash mismatch with new_partition_info hash".into());
        }

        // Parse signature data from sig blobs, data blobs, public key, and verify.
        match delta_update::parse_signature_data(&sigbytes, hdhashvec.as_slice(), pubkey_path) {
            Some(_) => (),
            _ => {
                self.status = PackageStatus::BadSignature;
                return Err("unable to parse and verify signature data".into());
            }
        };

        println!("Parsed and verified signature data from file {:?}", from_path);

        self.status = PackageStatus::Verified;
        Ok(datablobspath)
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
    let temp_dir = output_dir.join(".tmp");
    fs::create_dir_all(&unverified_dir)?;
    fs::create_dir_all(&temp_dir)?;

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

        pkg.download(&unverified_dir, &client).await?;

        // Unverified payload is stored in e.g. "output_dir/.unverified/oem.gz".
        // Verified payload is stored in e.g. "output_dir/oem.raw".
        let pkg_unverified = unverified_dir.join(&*pkg.name);
        let pkg_verified = output_dir.join(pkg_unverified.with_extension("raw").file_name().unwrap_or_default());

        match pkg.verify_signature_on_disk(&pkg_unverified, &args.pubkey_file) {
            Ok(datablobspath) => {
                // write extracted data into the final data.
                fs::rename(datablobspath, pkg_verified.clone())?;
                debug!("data blobs written into file {:?}", pkg_verified);
            }
            _ => return Err(format!("unable to verify signature \"{}\"", pkg.name).into()),
        };
    }

    // clean up data
    fs::remove_dir_all(temp_dir)?;

    Ok(())
}
