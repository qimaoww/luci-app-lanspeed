use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InteriorNul,
    Allocation(&'static str),
    Platform {
        operation: &'static str,
        code: libc::c_int,
    },
    InvalidJson,
    InvalidData(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InteriorNul => formatter.write_str("string contains an interior NUL byte"),
            Self::Allocation(kind) => write!(formatter, "failed to allocate {kind}"),
            Self::Platform { operation, code } => {
                write!(formatter, "{operation} failed with code {code}")
            }
            Self::InvalidJson => formatter.write_str("invalid JSON/blobmsg value"),
            Self::InvalidData(detail) => write!(formatter, "invalid OpenWrt data: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::ffi::NulError> for Error {
    fn from(_: std::ffi::NulError) -> Self {
        Self::InteriorNul
    }
}
