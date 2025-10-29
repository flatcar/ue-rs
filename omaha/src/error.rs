use std::fmt::Display;
use std::num::ParseIntError;

#[derive(Debug)]
pub enum Error {
    TryFromHex(ParseIntError),
    TryFromBase64(ct_codecs::Error),
    InvalidDigestLength {
        expected: usize,
        actual: usize,
    },
    UnknownActionEvent(String),
    UnknownSuccessAction(String),
    ParseFileSize(ParseIntError),
    ParseUuid(uuid::Error),
    ParseUrl(url::ParseError),
}

impl Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::TryFromHex(err) => write!(fmt, "failed to convert from hex: {err}"),
            Error::TryFromBase64(err) => write!(fmt, "failed to convert from base64: {err}"),
            Error::InvalidDigestLength {
                expected,
                actual,
            } => {
                write!(fmt, "invalid digest length: expected {expected}, actual {actual}")
            }
            Error::UnknownActionEvent(action) => write!(fmt, "unknown action event: {action}"),
            Error::UnknownSuccessAction(action) => write!(fmt, "unknown success action: {action}"),
            Error::ParseFileSize(err) => write!(fmt, "failed to parse file size: {err}"),
            Error::ParseUuid(err) => write!(fmt, "failed to parse uuid: {err}"),
            Error::ParseUrl(err) => write!(fmt, "failed to parse url: {err}"),
        }
    }
}

impl std::error::Error for Error {}
