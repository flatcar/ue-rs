use std::path::PathBuf;

#[derive(Debug)]
pub enum Error {
    ReadHeaderMagic(std::io::Error),
    BadHeaderMagic([u8; 4]),
    ReadFileFormatVersion(std::io::Error),
    UnsupportedFileFormatVersion(u64),
    ReadManifestSize(std::io::Error),
    ReadManifestBytes(std::io::Error),
    ParseManifest(protobuf::Error),
    ReadSignature(std::io::Error),
    MissingSignatureOffset,
    MissingSignatureSize,
    MissingSignatureOffsetAndSize,
    InvalidParentPath(PathBuf),
    CreateDirectory(std::io::Error),
    CreateFile(std::io::Error),
    MissingDataOffset,
    MissingDataLength,
    IncorrectNumExtents(usize),
    MissingStartBlock,
    ReadData(std::io::Error),
    MissingPartitionType,
    UnpackBzip2(std::io::Error, u64),
    CopyUnpackedData(std::io::Error, u64),
    CopyPlainData(std::io::Error, u64),
    FlushFile(std::io::Error, u64),
    ParseSignatures(protobuf::Error),
    NoValidSignature,
    EmptySignature,
    GetPkcs8PemPubKey(crate::verify_sig::Error),
    VerifyPkcsSignature(crate::verify_sig::Error),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ReadHeaderMagic(err) => write!(f, "failed to read header magic: {err}"),
            Error::BadHeaderMagic(magic) => write!(f, "bad header magic: {magic:?}"),
            Error::ReadFileFormatVersion(err) => write!(f, "failed to read file format version: {err}"),
            Error::UnsupportedFileFormatVersion(version) => write!(f, "unsupported file format version: {version}"),
            Error::ReadManifestSize(err) => write!(f, "failed to read manifest size: {err}"),
            Error::ReadManifestBytes(err) => write!(f, "failed to read manifest bytes: {err}"),
            Error::ParseManifest(err) => write!(f, "failed to parse manifest: {err}"),
            Error::ReadSignature(err) => write!(f, "failed to read signature: {err}"),
            Error::MissingSignatureOffset => write!(f, "file header missing signature offset"),
            Error::MissingSignatureSize => write!(f, "file header missing signature size"),
            Error::MissingSignatureOffsetAndSize => write!(f, "file header missing signature offset and size"),
            Error::InvalidParentPath(path) => write!(f, "invalid parent path: {path:?}"),
            Error::CreateDirectory(err) => write!(f, "failed to create directory: {err}"),
            Error::CreateFile(err) => write!(f, "failed to create file: {err}"),
            Error::MissingDataOffset => write!(f, "install operation missing data offset"),
            Error::MissingDataLength => write!(f, "install operation missing data length"),
            Error::IncorrectNumExtents(num) => write!(f, "incorrect number of extents: expected 1, got {num}"),
            Error::MissingStartBlock => write!(f, "extent missing start block"),
            Error::ReadData(err) => write!(f, "failed to read data: {err}"),
            Error::MissingPartitionType => write!(f, "install operation missing partition type"),
            Error::UnpackBzip2(err, offset) => write!(f, "failed to unpack bzip2 at offset {offset}: {err}"),
            Error::CopyUnpackedData(err, offset) => write!(f, "failed to copy unpacked data at offset {offset}: {err}"),
            Error::CopyPlainData(err, offset) => write!(f, "failed to copy plaintext at offset {offset}: {err}"),
            Error::FlushFile(err, offset) => write!(f, "failed to flush file at offset {offset}: {err}"),
            Error::ParseSignatures(err) => write!(f, "failed to parse signatures: {err}"),
            Error::NoValidSignature => write!(f, "failed to find a valid signature"),
            Error::EmptySignature => write!(f, "empty signature"),
            Error::GetPkcs8PemPubKey(err) => write!(f, "failed to get PKCS8 PEM public key: {err}"),
            Error::VerifyPkcsSignature(err) => write!(f, "failed to verify PKCS signature: {err}"),
        }
    }
}
