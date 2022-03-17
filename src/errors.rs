use core::fmt::{self, Display, Formatter};

use alloc::string::FromUtf8Error;

#[cfg(feature = "std")]
use std::io::Error as IOError;

#[cfg(feature = "std")]
use std::error::Error;

use base64::DecodeError;
use block_modes::BlockModeError;

/// Errors for MagicCrypt.
#[derive(Debug)]
pub enum MagicCryptError {
    #[cfg(feature = "std")]
    IOError(IOError),
    Base64Error(DecodeError),
    StringError(FromUtf8Error),
    DecryptError(BlockModeError),
}

#[cfg(feature = "std")]
impl From<IOError> for MagicCryptError {
    #[inline]
    fn from(error: IOError) -> MagicCryptError {
        MagicCryptError::IOError(error)
    }
}

impl From<DecodeError> for MagicCryptError {
    #[inline]
    fn from(error: DecodeError) -> MagicCryptError {
        MagicCryptError::Base64Error(error)
    }
}

impl From<FromUtf8Error> for MagicCryptError {
    #[inline]
    fn from(error: FromUtf8Error) -> MagicCryptError {
        MagicCryptError::StringError(error)
    }
}

impl From<BlockModeError> for MagicCryptError {
    #[inline]
    fn from(error: BlockModeError) -> MagicCryptError {
        MagicCryptError::DecryptError(error)
    }
}

impl Display for MagicCryptError {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        match self {
            #[cfg(feature = "std")]
            MagicCryptError::IOError(err) => Display::fmt(err, f),
            MagicCryptError::Base64Error(err) => Display::fmt(err, f),
            MagicCryptError::StringError(err) => Display::fmt(err, f),
            MagicCryptError::DecryptError(err) => Display::fmt(err, f),
        }
    }
}

#[cfg(feature = "std")]
impl Error for MagicCryptError {}
