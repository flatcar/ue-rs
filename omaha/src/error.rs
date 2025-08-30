use std::fmt::Display;
use std::num::ParseIntError;

#[derive(Debug)]
pub enum Error {
    Decode(ct_codecs::Error),
    TryFromHex(ParseIntError),
    InvalidDigestLength {
        expected: usize,
        actual: usize,
    },
    UnknownActionEvent(String),
    UnknownSuccessAction(String),
    ParseFileSize(ParseIntError),
    ParseUuid(uuid::Error),
}

impl Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Decode(err) => write!(fmt, "failed to decode: {}", err),
            Error::TryFromHex(err) => write!(fmt, "failed to convert from hex: {}", err),
            Error::InvalidDigestLength {
                expected,
                actual,
            } => {
                write!(fmt, "invalid digest length: expected {}, actual {}", expected, actual)
            }
            Error::UnknownActionEvent(action) => write!(fmt, "unknown action event: {}", action),
            Error::UnknownSuccessAction(action) => write!(fmt, "unknown success action: {}", action),
            Error::ParseFileSize(err) => write!(fmt, "failed to parse file size: {}", err),
            Error::ParseUuid(err) => write!(fmt, "failed to parse uuid: {}", err),
        }
    }
}

impl std::error::Error for Error {}
