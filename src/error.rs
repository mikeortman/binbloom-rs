//! Error types for the crate.

use thiserror::Error;

/// Errors that can occur while analysing a firmware image.
#[derive(Debug, Error)]
pub enum BinbloomError {
    /// The firmware file could not be opened or read.
    #[error("cannot access file '{path}'")]
    FileAccess {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// The firmware image is smaller than a single pointer for the target
    /// architecture, so no meaningful analysis is possible.
    #[error("input file must be at least {required} bytes, got {actual}")]
    FileTooSmall { required: usize, actual: usize },

    /// Endianness could not be inferred from the firmware content.
    #[error("unable to detect endianness")]
    EndiannessUndetectable,

    /// No point of interest was found, so a base address cannot be deduced.
    #[error("no point of interest found, cannot deduce loading address")]
    NoPointsOfInterest,

    /// An invalid architecture string was supplied on the command line.
    #[error("invalid architecture '{0}', must be '32' or '64'")]
    InvalidArch(String),

    /// An invalid endianness string was supplied on the command line.
    #[error("invalid endianness '{0}', must be 'le' or 'be'")]
    InvalidEndianness(String),

    /// A generic I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Convenience alias for results produced by this crate.
pub type Result<T> = std::result::Result<T, BinbloomError>;
