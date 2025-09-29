pub mod package;

use std::borrow::Cow;
use std::io::{BufReader, Read};
use std::ffi::OsStr;
use std::fs::File;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use globset::GlobSet;
use hard_xml::XmlRead;
use log::{debug, info, warn};
use reqwest::{StatusCode, blocking::Client, redirect::Policy};
use url::Url;

use crate::{Package, PackageStatus};
use omaha::{Sha1Digest, Sha256Digest};

const DOWNLOAD_TIMEOUT: u64 = 3600;
const HTTP_CONN_TIMEOUT: u64 = 20;
const MAX_DOWNLOAD_RETRY: u32 = 20;

pub const TARGET_FILENAME_DEFAULT: &str = "oem-azure.gz";
pub const PAYLOAD_URL_DEFAULT: &str = "https://update.release.flatcar-linux.net/amd64-usr/current/oem-azure.gz";

const UNVERFIED_SUFFIX: &str = ".unverified";
const TMP_SUFFIX: &str = ".tmp";

pub struct DownloadResult {
    pub hash_sha256: Sha256Digest,
    pub hash_sha1: Sha1Digest,
    pub data: File,
}

pub fn hash_on_disk<T: omaha::Hasher>(path: &Path, maxlen: Option<usize>) -> Result<T::Output> {
    let file = File::open(path).context(format!("File::open({:?})", path))?;

    let filelen = file.metadata().context(format!("failed to get metadata of {:?}", path))?.len() as usize;

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

    let mut hasher = T::new();

    const CHUNKLEN: usize = 10485760; // 10M

    let mut freader = BufReader::new(file);
    let mut databuf = vec![0u8; CHUNKLEN];

    while maxlen_to_read > 0 {
        if maxlen_to_read < CHUNKLEN {
            // last and submaximal chunk to read, shrink the buffer for it
            databuf.truncate(maxlen_to_read);
        }

        freader.read_exact(&mut databuf).context(format!("failed to read_exact(chunklen {:?})", databuf.len()))?;

        maxlen_to_read -= databuf.len();

        hasher.update(&databuf);
    }

    Ok(hasher.finalize())
}

fn do_download_and_hash<U>(client: &Client, url: U, path: &Path, expected_sha256: Option<Sha256Digest>, expected_sha1: Option<Sha1Digest>) -> Result<DownloadResult>
where
    U: reqwest::IntoUrl + Clone,
    Url: From<U>,
{
    let client_url = url.clone();

    #[rustfmt::skip]
    let mut res = client.get(url.clone())
        .send()
        .context(format!("client get & send{:?} failed ", client_url.as_str()))?;

    // Redirect was already handled at this point, so there is no need to touch
    // response or url again. Simply print info and continue.
    if <U as Into<Url>>::into(client_url) != *res.url() {
        info!("redirected to URL {:?}", res.url());
    }

    // Return immediately on download failure on the client side.
    let status = res.status();

    if !status.is_success() {
        match status {
            StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => {
                bail!("cannnot fetch remotely with status code {:?}", status);
            }
            _ => bail!("general failure with status code {:?}", status),
        }
    }

    println!("writing to {}", path.display());

    let mut file = File::create(path).context(format!("failed to create path ({:?})", path.display()))?;
    res.copy_to(&mut file)?;

    let calculated_sha256 = hash_on_disk::<omaha::Sha256>(path, None)?;
    let calculated_sha1 = hash_on_disk::<omaha::Sha1>(path, None)?;

    debug!("    expected sha256:   {expected_sha256:?}");
    debug!("    calculated sha256: {calculated_sha256:?}");
    debug!("    sha256 match?      {}", expected_sha256 == Some(calculated_sha256));
    debug!("    expected sha1:   {expected_sha1:?}");
    debug!("    calculated sha1: {calculated_sha1:?}");
    debug!("    sha1 match?      {}", expected_sha1 == Some(calculated_sha1));

    if expected_sha256.is_some() && expected_sha256 != Some(calculated_sha256) {
        bail!("checksum mismatch for sha256");
    }
    if expected_sha1.is_some() && expected_sha1 != Some(calculated_sha1) {
        bail!("checksum mismatch for sha1");
    }

    Ok(DownloadResult {
        hash_sha256: calculated_sha256,
        hash_sha1: calculated_sha1,
        data: file,
    })
}

pub fn download_and_hash<U>(client: &Client, url: U, path: &Path, expected_sha256: Option<Sha256Digest>, expected_sha1: Option<Sha1Digest>) -> Result<DownloadResult>
where
    U: reqwest::IntoUrl + Clone,
    Url: From<U>,
{
    crate::retry_loop(
        || do_download_and_hash(client, url.clone(), path, expected_sha256, expected_sha1),
        MAX_DOWNLOAD_RETRY,
    )
}

fn get_pkgs_to_download<'a>(resp: &'a omaha::Response, glob_set: &GlobSet) -> Result<Vec<Package<'a>>> {
    let mut to_download: Vec<_> = Vec::new();

    for app in &resp.apps {
        let manifest = &app.update_check.manifest;

        for pkg in &manifest.packages {
            if !glob_set.is_match(&*pkg.name) {
                info!("package `{}` doesn't match glob pattern, skipping", pkg.name);
                continue;
            }

            let hash_sha256 = pkg.hash_sha256.as_ref();
            let hash_sha1 = pkg.hash.as_ref();

            // TODO: multiple URLs per package
            //       not sure if nebraska sends us more than one right now but i suppose this is
            //       for mirrors?
            let Some(Ok(url)) = app.update_check.urls.first().map(|u| u.join(&pkg.name)) else {
                warn!("can't get url for package `{}`, skipping", pkg.name);
                continue;
            };

            if hash_sha256.is_none() && hash_sha1.is_none() {
                warn!("package `{}` doesn't have a valid SHA256 or SHA1 hash, skipping", pkg.name);
                continue;
            }

            to_download.push(Package {
                url,
                name: Cow::Borrowed(&pkg.name),
                hash_sha256: hash_sha256.cloned(),
                hash_sha1: hash_sha1.cloned(),
                size: pkg.size,
                status: PackageStatus::ToDownload,
            });
        }
    }

    Ok(to_download)
}

// Read data from remote URL into File
fn fetch_url_to_file<'a, U>(path: &'a Path, input_url: U, client: &'a Client) -> Result<Package<'a>>
where
    U: reqwest::IntoUrl + From<U> + std::clone::Clone + std::fmt::Debug,
    Url: From<U>,
{
    let r = download_and_hash(client, input_url.clone(), path, None, None).context(format!("unable to download data(url {input_url:?})"))?;

    Ok(Package {
        name: Cow::Borrowed(path.file_name().unwrap_or(OsStr::new("fakepackage")).to_str().unwrap_or("fakepackage")),
        hash_sha256: Some(r.hash_sha256),
        hash_sha1: Some(r.hash_sha1),
        size: r.data.metadata().context(format!("failed to get metadata, path ({:?})", path.display()))?.len() as usize,
        url: input_url.into(),
        status: PackageStatus::Unverified,
    })
}

fn do_download_verify(pkg: &mut Package<'_>, output_filename: Option<String>, output_dir: &Path, unverified_dir: &Path, pubkey_file: &str, client: &Client) -> Result<()> {
    pkg.check_download(unverified_dir)?;

    pkg.download(unverified_dir, client).context(format!("unable to download \"{:?}\"", pkg.name))?;

    // Unverified payload is stored in e.g. "output_dir/.unverified/oem.gz".
    // Verified payload is stored in e.g. "output_dir/oem.raw".
    let pkg_unverified = unverified_dir.join(&*pkg.name);
    let pkg_verified = output_dir.join(output_filename.as_ref().map(OsStr::new).unwrap_or(pkg_unverified.with_extension("raw").file_name().unwrap_or_default()));

    let datablobspath = pkg.verify_signature_on_disk(&pkg_unverified, pubkey_file).context(format!("unable to verify signature \"{}\"", pkg.name))?;

    // write extracted data into the final data.
    debug!("data blobs written into file {pkg_verified:?}");
    fs::rename(datablobspath, pkg_verified)?;

    Ok(())
}

pub struct DownloadVerify {
    output_dir: String,
    target_filename: Option<String>,
    input_xml: String,
    pubkey_file: String,
    payload_url: Option<String>,
    take_first_match: bool,
    glob_set: GlobSet,
}

impl DownloadVerify {
    pub fn new(param_output_dir: String, param_pubkey_file: String, param_take_first_match: bool, param_glob_set: GlobSet) -> Self {
        Self {
            output_dir: param_output_dir,
            target_filename: None,
            input_xml: "".to_string(),
            pubkey_file: param_pubkey_file,
            payload_url: None,
            take_first_match: param_take_first_match,
            glob_set: param_glob_set,
        }
    }

    pub fn target_filename(mut self, param_target_filename: String) -> Self {
        self.target_filename = Some(param_target_filename);
        self
    }

    pub fn input_xml(mut self, param_input_xml: String) -> Self {
        self.input_xml = param_input_xml;
        self
    }

    pub fn payload_url(mut self, param_payload_url: String) -> Self {
        self.payload_url = Some(param_payload_url);
        self
    }

    pub fn run(&self) -> Result<()> {
        let output_dir = Path::new(&self.output_dir);

        let unverified_dir = output_dir.join(UNVERFIED_SUFFIX);
        let temp_dir = output_dir.join(TMP_SUFFIX);
        fs::create_dir_all(&unverified_dir)?;
        fs::create_dir_all(&temp_dir)?;

        // The default policy of reqwest Client supports max 10 attempts on HTTP redirect.
        let client = Client::builder()
            .tcp_keepalive(Duration::from_secs(HTTP_CONN_TIMEOUT))
            .connect_timeout(Duration::from_secs(HTTP_CONN_TIMEOUT))
            .timeout(Duration::from_secs(DOWNLOAD_TIMEOUT))
            .redirect(Policy::default())
            .build()?;

        if self.payload_url.is_some() {
            let url = self.payload_url.clone().unwrap();
            let u = Url::parse(&url)?;
            let fname = u.path_segments().ok_or(anyhow!("failed to get path segments, url ({:?})", u))?.next_back().ok_or(anyhow!("failed to get path segments, url ({:?})", u))?;
            let mut pkg_fake: Package;

            let temp_payload_path = unverified_dir.join(fname);
            pkg_fake = fetch_url_to_file(
                &temp_payload_path,
                Url::from_str(url.as_str()).context(anyhow!("failed to convert into url ({:?})", self.payload_url))?,
                &client,
            )?;
            do_download_verify(
                &mut pkg_fake,
                self.target_filename.clone(),
                output_dir,
                unverified_dir.as_path(),
                self.pubkey_file.as_str(),
                &client,
            )?;

            // verify only a fake package, early exit and skip the rest.
            return Ok(());
        }

        ////
        // parse response
        ////
        let resp = omaha::Response::from_str(&self.input_xml)?;

        let mut pkgs_to_dl = get_pkgs_to_download(&resp, &self.glob_set)?;

        debug!("pkgs:\n\t{pkgs_to_dl:#?}");
        debug!("");

        ////
        // download
        ////

        for pkg in pkgs_to_dl.iter_mut() {
            do_download_verify(
                pkg,
                self.target_filename.clone(),
                output_dir,
                unverified_dir.as_path(),
                self.pubkey_file.as_str(),
                &client,
            )?;
            if self.take_first_match {
                break;
            }
        }

        // clean up data
        fs::remove_dir_all(temp_dir)?;

        Ok(())
    }
}
