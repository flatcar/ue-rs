use std::fmt::Debug;
use std::path::PathBuf;
use url::Url;

#[derive(Debug)]
pub enum Error {
    OpenFile(std::io::Error),
    GetFileMetadata(std::io::Error),
    ReadFromFile(std::io::Error),
    SendGetRequest(Url, reqwest::Error),
    GetRequestFailed(reqwest::StatusCode),
    CreateFile(std::io::Error),
    CopyRequestBodyToFile(reqwest::Error),
    Sha256ChecksumMismatch(omaha::Sha256Digest, omaha::Sha256Digest),
    Sha1ChecksumMismatch(omaha::Sha1Digest, omaha::Sha1Digest),
    DeltaUpdate(update_format_crau::delta_update::Error),
    InvalidParentPath(PathBuf),
    MissingPartitionHash,
    RenameFile(std::io::Error),
    CreateDirectory(std::io::Error),
    BuildClient(reqwest::Error),
    ParseUrl(url::ParseError),
    InvalidBaseUrl(Url),
    EmptyUrlIterator,
    RemoveDirectory(std::io::Error),
    InvalidHashDigestString(hard_xml::XmlError),
    PostRequestFailed(reqwest::Error),
    GetResponseBodyText(reqwest::Error),
    XmlRequestToString(hard_xml::XmlError),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::OpenFile(err) => write!(f, "failed to open file: {err}"),
            Error::GetFileMetadata(err) => write!(f, "failed to get file metadata: {err}"),
            Error::ReadFromFile(err) => write!(f, "failed to read file: {err}"),
            Error::SendGetRequest(url, err) => write!(f, "failed to send GET request to {url}: {err}"),
            Error::GetRequestFailed(status) => write!(f, "GET request returned status code {status}"),
            Error::CreateFile(err) => write!(f, "failed to create file: {err}"),
            Error::CopyRequestBodyToFile(err) => write!(f, "failed to copy request body to file: {err}"),
            Error::Sha256ChecksumMismatch(exp, got) => write!(f, "SHA256 checksum mismatch: expected {exp:?}, got {got:?}"),
            Error::Sha1ChecksumMismatch(exp, got) => write!(f, "SHA1 checksum mismatch: expected {exp:?}, got {got:?}"),
            Error::DeltaUpdate(err) => write!(f, "failed to read delta update header: {err}"),
            Error::InvalidParentPath(path) => write!(f, "invalid parent path: {path:?}"),
            Error::MissingPartitionHash => write!(f, "missing partition hash"),
            Error::RenameFile(err) => write!(f, "failed to rename file: {err}"),
            Error::CreateDirectory(err) => write!(f, "failed to create directory: {err}"),
            Error::BuildClient(err) => write!(f, "failed to build client: {err}"),
            Error::ParseUrl(url) => write!(f, "failed to parse URL: {url}"),
            Error::InvalidBaseUrl(url) => write!(f, "invalid base URL: {url}"),
            Error::EmptyUrlIterator => write!(f, "empty URL iterator"),
            Error::RemoveDirectory(err) => write!(f, "failed to remove directory: {err}"),
            Error::InvalidHashDigestString(err) => write!(f, "invalid hash digest: {err}"),
            Error::PostRequestFailed(err) => write!(f, "POST request failed: {err}"),
            Error::GetResponseBodyText(err) => write!(f, "failed to get response body text: {err}"),
            Error::XmlRequestToString(err) => write!(f, "xml request to string: {err}"),
        }
    }
}

impl From<update_format_crau::delta_update::Error> for Error {
    fn from(err: update_format_crau::delta_update::Error) -> Self {
        Error::DeltaUpdate(err)
    }
}
