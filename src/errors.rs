extern crate base64;
extern crate block_modes;

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::Error as IOError;
use std::string::FromUtf8Error;

use self::base64::DecodeError;
use self::block_modes::BlockModeError;

/// Errors for MagicCrypt.
#[derive(Debug)]
pub enum MagicCryptError {
    IOError(IOError),
    Base64Error(DecodeError),
    StringError(FromUtf8Error),
    DecryptError(BlockModeError),
}

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
            MagicCryptError::IOError(err) => Display::fmt(err, f),
            MagicCryptError::Base64Error(err) => Display::fmt(err, f),
            MagicCryptError::StringError(err) => Display::fmt(err, f),
            MagicCryptError::DecryptError(err) => Display::fmt(err, f),
        }
    }
}

impl Error for MagicCryptError {}
