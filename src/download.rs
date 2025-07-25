use anyhow::{Context, Result, bail};
use std::io::{BufReader, Read};
use std::fs::File;
use std::path::Path;
use log::{info, debug};
use url::Url;

use reqwest::StatusCode;
use reqwest::blocking::Client;

use sha2::digest::DynDigest;

const MAX_DOWNLOAD_RETRY: u32 = 20;

/// Result of a successful download operation.
///
/// Contains the computed hashes and file handle for the downloaded content.
pub struct DownloadResult {
    /// SHA-256 hash of the downloaded file
    pub hash_sha256: omaha::Hash<omaha::Sha256>,
    /// SHA-1 hash of the downloaded file  
    pub hash_sha1: omaha::Hash<omaha::Sha1>,
    /// File handle to the downloaded content on disk
    pub data: File,
}

/// Computes a hash of a file on disk.
///
/// Reads the file at the given path and computes its hash using the specified hash algorithm.
/// The file is read in chunks to handle large files efficiently.
///
/// # Arguments
///
/// * `path` - Path to the file to hash
/// * `maxlen` - Optional maximum number of bytes to read from the file. If `None`,
///   the entire file is hashed. If `Some(len)`, only the first `len` bytes are hashed.
///
/// # Returns
///
/// Returns the computed hash on success.
///
/// # Errors
///
/// This function will return an error if:
/// * The file cannot be opened
/// * File metadata cannot be read
/// * The file cannot be read (e.g., I/O errors)
/// * `read_exact` fails when reading file chunks
///
/// # Examples
///
/// ```ignore
/// use std::path::Path;
/// let hash = hash_on_disk::<omaha::Sha256>(Path::new("file.txt"), None)?;
/// ```
pub fn hash_on_disk<T: omaha::HashAlgo>(path: &Path, maxlen: Option<usize>) -> Result<omaha::Hash<T>> {
    let file = File::open(path).context(format!("failed to open path({:?})", path.display()))?;
    let mut hasher = T::hasher();

    let filelen = file.metadata().context(format!("failed to get metadata of {:?}", path.display()))?.len() as usize;

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

    while maxlen_to_read > 0 {
        if maxlen_to_read < CHUNKLEN {
            chunklen = maxlen_to_read;
        } else {
            chunklen = CHUNKLEN;
        }

        let mut databuf = vec![0u8; chunklen];

        freader.read_exact(&mut databuf).context(format!("failed to read_exact(chunklen {chunklen:?})"))?;

        maxlen_to_read -= chunklen;

        hasher.update(&databuf);
    }

    Ok(omaha::Hash::from_bytes(Box::new(hasher).finalize()))
}

/// Downloads a file from a URL and computes its hashes.
///
/// This is the internal implementation that performs a single download attempt.
/// It downloads the content to the specified path, computes SHA-256 and SHA-1 hashes,
/// and validates them against expected values if provided.
///
/// # Arguments
///
/// * `client` - HTTP client to use for the download
/// * `url` - URL to download from
/// * `path` - Local path where the file should be saved
/// * `expected_sha256` - Optional expected SHA-256 hash for validation
/// * `expected_sha1` - Optional expected SHA-1 hash for validation
///
/// # Returns
///
/// Returns a `DownloadResult` containing the computed hashes and file handle.
///
/// # Errors
///
/// This function will return an error if:
/// * The HTTP request fails
/// * The server returns a non-success status code
/// * The file cannot be created at the specified path
/// * Hash computation fails
/// * Hash validation fails (when expected hashes are provided)
fn do_download_and_hash<U>(client: &Client, url: U, path: &Path, expected_sha256: Option<omaha::Hash<omaha::Sha256>>, expected_sha1: Option<omaha::Hash<omaha::Sha1>>) -> Result<DownloadResult>
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
    debug!("    calculated sha256: {calculated_sha256}");
    debug!("    sha256 match?      {}", expected_sha256 == Some(calculated_sha256.clone()));
    debug!("    expected sha1:   {expected_sha1:?}");
    debug!("    calculated sha1: {calculated_sha1}");
    debug!("    sha1 match?      {}", expected_sha1 == Some(calculated_sha1.clone()));

    if expected_sha256.is_some() && expected_sha256 != Some(calculated_sha256.clone()) {
        bail!("Checksum mismatch for sha256");
    }
    if expected_sha1.is_some() && expected_sha1 != Some(calculated_sha1.clone()) {
        bail!("Checksum mismatch for sha1");
    }

    Ok(DownloadResult {
        hash_sha256: calculated_sha256,
        hash_sha1: calculated_sha1,
        data: file,
    })
}

/// Downloads a file from a URL with retry logic and hash verification.
///
/// This function downloads a file from the specified URL, saves it to the given path,
/// and computes SHA-256 and SHA-1 hashes. It includes automatic retry logic to handle
/// transient network errors.
///
/// # Arguments
///
/// * `client` - HTTP client to use for the download
/// * `url` - URL to download from (must implement `reqwest::IntoUrl` and be cloneable)
/// * `path` - Local path where the file should be saved
/// * `expected_sha256` - Optional expected SHA-256 hash for validation. If provided,
///   the computed hash must match or an error is returned.
/// * `expected_sha1` - Optional expected SHA-1 hash for validation. If provided,
///   the computed hash must match or an error is returned.
///
/// # Returns
///
/// Returns a `DownloadResult` containing:
/// * The computed SHA-256 hash
/// * The computed SHA-1 hash  
/// * A file handle to the downloaded content
///
/// # Errors
///
/// This function will return an error if:
/// * All retry attempts fail due to network issues
/// * The server returns a non-success HTTP status code
/// * The file cannot be created at the specified path
/// * Hash computation fails
/// * Hash validation fails (when expected hashes are provided)
/// * Any I/O operation fails during download or hash computation
///
/// # Examples
///
/// ```ignore
/// use reqwest::blocking::Client;
/// use std::path::Path;
///
/// let client = Client::new();
/// let result = download_and_hash(
///     &client,
///     "https://example.com/file.zip",
///     Path::new("downloaded_file.zip"),
///     None, // no SHA-256 validation
///     None  // no SHA-1 validation
/// )?;
/// println!("SHA-256: {}", result.hash_sha256);
/// ```
pub fn download_and_hash<U>(client: &Client, url: U, path: &Path, expected_sha256: Option<omaha::Hash<omaha::Sha256>>, expected_sha1: Option<omaha::Hash<omaha::Sha1>>) -> Result<DownloadResult>
where
    U: reqwest::IntoUrl + Clone,
    Url: From<U>,
{
    crate::retry_loop(
        || do_download_and_hash(client, url.clone(), path, expected_sha256.clone(), expected_sha1.clone()),
        MAX_DOWNLOAD_RETRY,
    )
}
