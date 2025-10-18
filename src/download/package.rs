use std::borrow::Cow;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};

use log::{debug, info};

use reqwest::blocking::Client;
use url::Url;

use crate::{download_and_hash, hash_on_disk};
use omaha::{Sha1Digest, Sha256Digest};
use update_format_crau::delta_update;

use crate::{error::Error, Result};

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

        let size_on_disk = fs::metadata(&path).map_err(Error::GetFileMetadata)?.len() as usize;
        let expected_size = self.size;

        if size_on_disk < expected_size {
            info!("{}: have downloaded {}/{} bytes, will resume", path.display(), size_on_disk, expected_size);

            self.status = PackageStatus::DownloadIncomplete(size_on_disk);
            return Ok(());
        }

        if size_on_disk == expected_size {
            info!("{}: download complete, checking hash...", path.display());
            let hash_sha256 = self.hash_on_disk::<omaha::Sha256>(&path, None)?;
            let hash_sha1 = self.hash_on_disk::<omaha::Sha1>(&path, None)?;

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

        // TODO: why ignore returned DownloadResult here?
        match download_and_hash(client, self.url.clone(), &path, self.hash_sha256, self.hash_sha1) {
            Ok(_) => {
                self.status = PackageStatus::Unverified;
                Ok(())
            }
            Err(err) => {
                self.status = PackageStatus::DownloadFailed;
                Err(err)
            }
        }
    }

    fn verify_checksum(&mut self, calculated_sha256: Sha256Digest, calculated_sha1: Sha1Digest) -> bool {
        debug!("    expected sha256:   {:?}", self.hash_sha256);
        debug!("    calculated sha256: {calculated_sha256:?}");
        debug!("    sha256 match?      {}", self.hash_sha256 == Some(calculated_sha256));
        debug!("    expected sha1:   {:?}", self.hash_sha1);
        debug!("    calculated sha1: {calculated_sha1:?}");
        debug!("    sha1 match?      {}", self.hash_sha1 == Some(calculated_sha1));

        if self.hash_sha256.is_some() && self.hash_sha256 != Some(calculated_sha256) || self.hash_sha1.is_some() && self.hash_sha1 != Some(calculated_sha1) {
            self.status = PackageStatus::BadChecksum;
            false
        } else {
            self.status = PackageStatus::Unverified;
            true
        }
    }

    pub fn verify_signature_on_disk(&mut self, from_path: &Path, pubkey_path: &str) -> Result<PathBuf> {
        let upfile = File::open(from_path).map_err(Error::OpenFile)?;

        // Read update payload from file, read delta update header from the payload.
        let header = delta_update::read_delta_update_header(&upfile)?;

        let mut delta_archive_manifest = delta_update::get_manifest_bytes(&upfile, &header)?;

        // Extract signature from header.
        let sigbytes = delta_update::get_signatures_bytes(&upfile, &header, &mut delta_archive_manifest)?;

        // tmp dir == "/var/tmp/outdir/.tmp"
        let tmpdirpathbuf = from_path.parent().ok_or(Error::InvalidParentPath(from_path.to_path_buf()))?.parent().ok_or(Error::InvalidParentPath(from_path.to_path_buf()))?.join(".tmp");
        let tmpdir = tmpdirpathbuf.as_path();
        let datablobspath = tmpdir.join("ue_data_blobs");

        // Get length of header and data, including header and manifest.
        let header_data_length = delta_update::get_header_data_length(&header, &delta_archive_manifest)?;
        let hdhash = self.hash_on_disk::<omaha::Sha256>(from_path, Some(header_data_length))?;
        let hdhashvec: Vec<u8> = hdhash.into();

        // Extract data blobs into a file, datablobspath.
        delta_update::get_data_blobs(&upfile, &header, &delta_archive_manifest, datablobspath.as_path())?;

        // Check for hash of data blobs with new_partition_info hash.
        let pinfo_hash = match &delta_archive_manifest.new_partition_info.hash {
            Some(hash) => hash,
            None => return Err(Error::MissingPartitionHash),
        };

        let datahash = self.hash_on_disk::<omaha::Sha256>(datablobspath.as_path(), None)?;
        if datahash != pinfo_hash.as_slice() {
            let mut pinfo_hash_array = [0; 32];
            pinfo_hash_array.copy_from_slice(pinfo_hash);
            return Err(Error::Sha256ChecksumMismatch(datahash, pinfo_hash_array));
        }

        // Parse signature data from sig blobs, data blobs, public key, and verify.
        match delta_update::parse_signature_data(&sigbytes, hdhashvec.as_slice(), pubkey_path) {
            // TODO: why throw away the result of the above call here?
            Ok(_) => {
                self.status = PackageStatus::Verified;
                Ok(datablobspath)
            }
            Err(err) => {
                self.status = PackageStatus::BadSignature;
                Err(err.into())
            }
        }
    }
}
