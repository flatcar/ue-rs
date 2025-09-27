use std::borrow::Cow;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};

use log::{debug, error, info};

use anyhow::{Context, Result, bail, anyhow};
use reqwest::blocking::Client;
use url::Url;

use crate::{download_and_hash, hash_on_disk};
use omaha::{Sha1Digest, Sha256Digest};
use update_format_crau::delta_update;

#[derive(Debug)]
pub enum PackageStatus {
    ToDownload,
    DownloadIncomplete(usize),
    DownloadFailed,
    BadChecksum,
    Unverified,
    BadSignature,
    Verified,
}

#[derive(Debug)]
pub struct Package<'a> {
    pub url: Url,
    pub name: Cow<'a, str>,
    pub hash_sha256: Option<Sha256Digest>,
    pub hash_sha1: Option<Sha1Digest>,
    pub size: usize,
    pub status: PackageStatus,
}

impl Package<'_> {
    #[rustfmt::skip]
    // Return Sha256 hash of data in the given path.
    // If maxlen is None, a simple read to the end of the file.
    // If maxlen is Some, read only until the given length.
    fn hash_on_disk<T: omaha::Hasher>(&mut self, path: &Path, maxlen: Option<usize>) -> Result<T::Output> {
        hash_on_disk::<T>(path, maxlen)
    }

    #[rustfmt::skip]
    pub fn check_download(&mut self, in_dir: &Path) -> Result<()> {
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
        let expected_size = self.size;

        if size_on_disk < expected_size {
            info!("{}: have downloaded {}/{} bytes, will resume", path.display(), size_on_disk, expected_size);

            self.status = PackageStatus::DownloadIncomplete(size_on_disk);
            return Ok(());
        }

        if size_on_disk == expected_size {
            info!("{}: download complete, checking hash...", path.display());
            let hash_sha256 = self.hash_on_disk::<omaha::Sha256>(&path, None).context({
                format!("failed to hash_on_disk, path ({:?})", path.display())
            })?;
            let hash_sha1 = self.hash_on_disk::<omaha::Sha1>(&path, None).context({
                format!("failed to hash_on_disk, path ({:?})", path.display())
            })?;
            if self.verify_checksum(hash_sha256, hash_sha1) {
                info!("{}: good hash, will continue without re-download", path.display());
            } else {
                info!("{}: bad hash, will re-download", path.display());
                self.status = PackageStatus::ToDownload;
            }
        }

        Ok(())
    }

    pub fn download(&mut self, into_dir: &Path, client: &Client) -> Result<()> {
        // FIXME: use _range_start for completing downloads
        let _range_start = match self.status {
            PackageStatus::ToDownload => 0usize,
            PackageStatus::DownloadIncomplete(s) => s,
            _ => return Ok(()),
        };

        info!("downloading {}...", self.url);

        let path = into_dir.join(&*self.name);
        match download_and_hash(
            client,
            self.url.clone(),
            &path,
            self.hash_sha256.clone(),
            self.hash_sha1.clone(),
        ) {
            Ok(ok) => ok,
            Err(err) => {
                error!("downloading failed with error {err}");
                self.status = PackageStatus::DownloadFailed;
                bail!("unable to download data(url {})", self.url);
            }
        };

        self.status = PackageStatus::Unverified;
        Ok(())
    }

    fn verify_checksum(&mut self, calculated_sha256: Sha256Digest, calculated_sha1: Sha1Digest) -> bool {
        debug!("    expected sha256:   {:?}", self.hash_sha256);
        debug!("    calculated sha256: {calculated_sha256:?}");
        debug!("    sha256 match?      {}", self.hash_sha256 == Some(calculated_sha256.clone()));
        debug!("    expected sha1:   {:?}", self.hash_sha1);
        debug!("    calculated sha1: {calculated_sha1:?}");
        debug!("    sha1 match?      {}", self.hash_sha1 == Some(calculated_sha1.clone()));

        if self.hash_sha256.is_some() && self.hash_sha256 != Some(calculated_sha256.clone()) || self.hash_sha1.is_some() && self.hash_sha1 != Some(calculated_sha1.clone()) {
            self.status = PackageStatus::BadChecksum;
            false
        } else {
            self.status = PackageStatus::Unverified;
            true
        }
    }

    pub fn verify_signature_on_disk(&mut self, from_path: &Path, pubkey_path: &str) -> Result<PathBuf> {
        let upfile = File::open(from_path).context(format!("failed to open path ({:?})", from_path.display()))?;

        // Read update payload from file, read delta update header from the payload.
        let header = delta_update::read_delta_update_header(&upfile).context(format!("failed to read_delta_update_header path ({:?})", from_path.display()))?;

        let mut delta_archive_manifest = delta_update::get_manifest_bytes(&upfile, &header).context(format!("failed to get_manifest_bytes path ({:?})", from_path.display()))?;

        // Extract signature from header.
        let sigbytes = delta_update::get_signatures_bytes(&upfile, &header, &mut delta_archive_manifest).context(format!("failed to get_signatures_bytes path ({:?})", from_path.display()))?;

        // tmp dir == "/var/tmp/outdir/.tmp"
        let tmpdirpathbuf = from_path.parent().ok_or(anyhow!("unable to get parent dir"))?.parent().ok_or(anyhow!("unable to get parent dir"))?.join(".tmp");
        let tmpdir = tmpdirpathbuf.as_path();
        let datablobspath = tmpdir.join("ue_data_blobs");

        // Get length of header and data, including header and manifest.
        let header_data_length = delta_update::get_header_data_length(&header, &delta_archive_manifest).context("failed to get header data length")?;
        let hdhash = self.hash_on_disk::<omaha::Sha256>(from_path, Some(header_data_length)).context(format!("failed to hash_on_disk path ({:?}) failed", from_path.display()))?;
        let hdhashvec: Vec<u8> = hdhash.clone().into();

        // Extract data blobs into a file, datablobspath.
        delta_update::get_data_blobs(&upfile, &header, &delta_archive_manifest, datablobspath.as_path()).context(format!("failed to get_data_blobs path ({:?})", datablobspath.display()))?;

        // Check for hash of data blobs with new_partition_info hash.
        let pinfo_hash = match &delta_archive_manifest.new_partition_info.hash {
            Some(hash) => hash,
            None => bail!("unable to get new_partition_info hash"),
        };

        let datahash = self.hash_on_disk::<omaha::Sha256>(datablobspath.as_path(), None).context(format!("failed to hash_on_disk path ({:?})", datablobspath.display()))?;
        if datahash != pinfo_hash.as_slice() {
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

        println!("Parsed and verified signature data from file {from_path:?}");

        self.status = PackageStatus::Verified;
        Ok(datablobspath)
    }
}
