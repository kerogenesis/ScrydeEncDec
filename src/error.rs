use obfstr::obfstr;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    Io(std::io::Error),
    InvalidHeader,
    DecompressionFailed,
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Io(err) => write!(f, "{}: {err}", obfstr!("I/O Error")),
            AppError::InvalidHeader => write!(f, "{}", obfstr!("Invalid or unrecognized file header")),
            AppError::DecompressionFailed => {
                write!(f, "{}", obfstr!("Decompression failed - Zlib/Blowfish error"))
            }
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AppError::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::Io(err)
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
