use alloc::{string::String, vec::Vec};
#[cfg(feature = "std")]
use std::io::{Read, Write};
#[cfg(feature = "std")]
use std::ops::Add;

use base64::Engine;

#[cfg(feature = "std")]
use crate::generic_array::typenum::{IsGreaterOrEqual, PartialDiv, True, B1, U16, U4096};
#[cfg(feature = "std")]
use crate::generic_array::ArrayLength;
use crate::MagicCryptError;

/// Methods for `MagicCrypt` and `MagicCrypt<bits>` structs.
pub trait MagicCryptTrait {
    fn new<S: AsRef<[u8]>, V: AsRef<[u8]>>(key: S, iv: Option<V>) -> Self;

    #[inline]
    fn encrypt_str_to_base64<S: AsRef<str>>(&self, string: S) -> String {
        self.encrypt_to_base64(string.as_ref())
    }

    #[inline]
    fn encrypt_str_to_bytes<S: AsRef<str>>(&self, string: S) -> Vec<u8> {
        self.encrypt_to_bytes(string.as_ref())
    }

    #[inline]
    fn encrypt_bytes_to_base64<T: ?Sized + AsRef<[u8]>>(&self, bytes: &T) -> String {
        self.encrypt_to_base64(bytes)
    }

    #[inline]
    fn encrypt_bytes_to_bytes<T: ?Sized + AsRef<[u8]>>(&self, bytes: &T) -> Vec<u8> {
        self.encrypt_to_bytes(bytes)
    }

    #[inline]
    fn encrypt_to_base64<T: ?Sized + AsRef<[u8]>>(&self, data: &T) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.encrypt_to_bytes(data))
    }

    fn encrypt_to_bytes<T: ?Sized + AsRef<[u8]>>(&self, data: &T) -> Vec<u8>;

    #[cfg(feature = "std")]
    #[inline]
    fn encrypt_reader_to_base64(&self, reader: &mut dyn Read) -> Result<String, MagicCryptError> {
        self.encrypt_reader_to_bytes(reader)
            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    #[cfg(feature = "std")]
    fn encrypt_reader_to_bytes(&self, reader: &mut dyn Read) -> Result<Vec<u8>, MagicCryptError>;

    #[cfg(feature = "std")]
    fn encrypt_reader_to_writer(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), MagicCryptError> {
        self.encrypt_reader_to_writer2::<U4096>(reader, writer)
    }

    #[cfg(feature = "std")]
    fn encrypt_reader_to_writer2<
        N: ArrayLength<u8> + PartialDiv<U16> + IsGreaterOrEqual<U16, Output = True>,
    >(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), MagicCryptError>;

    #[inline]
    fn decrypt_base64_to_string<S: AsRef<str>>(
        &self,
        base64: S,
    ) -> Result<String, MagicCryptError> {
        Ok(String::from_utf8(self.decrypt_base64_to_bytes(base64)?)?)
    }

    #[inline]
    fn decrypt_base64_to_bytes<S: AsRef<str>>(
        &self,
        base64: S,
    ) -> Result<Vec<u8>, MagicCryptError> {
        self.decrypt_bytes_to_bytes(
            &base64::engine::general_purpose::STANDARD.decode(base64.as_ref())?,
        )
    }

    fn decrypt_bytes_to_bytes<T: ?Sized + AsRef<[u8]>>(
        &self,
        bytes: &T,
    ) -> Result<Vec<u8>, MagicCryptError>;

    #[cfg(feature = "std")]
    fn decrypt_reader_to_bytes(&self, reader: &mut dyn Read) -> Result<Vec<u8>, MagicCryptError>;

    #[cfg(feature = "std")]
    fn decrypt_reader_to_writer(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), MagicCryptError> {
        self.decrypt_reader_to_writer2::<U4096>(reader, writer)
    }

    #[cfg(feature = "std")]
    fn decrypt_reader_to_writer2<
        N: ArrayLength<u8> + PartialDiv<U16> + IsGreaterOrEqual<U16, Output = True> + Add<B1>,
    >(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), MagicCryptError>
    where
        <N as Add<B1>>::Output: ArrayLength<u8>;
}
