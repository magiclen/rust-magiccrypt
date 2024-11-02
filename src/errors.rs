use alloc::string::FromUtf8Error;
use core::fmt::{self, Display, Formatter};
#[cfg(feature = "std")]
use std::error::Error;
#[cfg(feature = "std")]
use std::io::Error as IOError;

use base64::DecodeError;
use cbc::cipher::block_padding::UnpadError;

/// Errors for MagicCrypt.
#[derive(Debug)]
pub enum MagicCryptError {
    #[cfg(feature = "std")]
    IOError(IOError),
    Base64Error(DecodeError),
    StringError(FromUtf8Error),
    DecryptError(UnpadError),
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

impl From<UnpadError> for MagicCryptError {
    #[inline]
    fn from(error: UnpadError) -> MagicCryptError {
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
