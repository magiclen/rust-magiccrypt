/*!
# MagicCrypt

MagicCrypt is a Java/PHP/NodeJS/Rust library to encrypt/decrpyt strings, files, or data, using Data Encryption Standard(DES) or Advanced Encryption Standard(AES) algorithms. It supports CBC block cipher mode, PKCS5 padding and 64, 128, 192 or 256-bits key length.

## For Rust

### Example

```rust
#[macro_use] extern crate magic_crypt;

use magic_crypt::MagicCryptTrait;

let mut mc = new_magic_crypt!("magickey", 256);

let base64 = mc.encrypt_str_to_base64("http://magiclen.org");

assert_eq!("DS/2U8royDnJDiNY2ps3f6ZoTbpZo8ZtUGYLGEjwLDQ=", base64);

assert_eq!("http://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
```

## For Java

Refer to https://github.com/magiclen/MagicCrypt.

## For PHP

Refer to https://github.com/magiclen/MagicCrypt.

## For NodeJS

Refer to https://github.com/magiclen/node-magiccrypt
*/

mod ciphers;
mod errors;
mod functions;
mod macros;
mod secure_bit;
mod traits;

use std::io::{Read, Write};

pub use ciphers::aes128::MagicCrypt128;
pub use ciphers::aes192::MagicCrypt192;
pub use ciphers::aes256::MagicCrypt256;
pub use ciphers::des64::MagicCrypt64;
pub use errors::MagicCryptError;
pub use secure_bit::SecureBit;
pub use traits::MagicCryptTrait;

const BUFFER_SIZE: usize = 8192; // must be a multiple of 16

#[derive(Debug, Clone)]
enum MagicCryptCipher {
    DES64(MagicCrypt64),
    AES128(MagicCrypt128),
    AES192(MagicCrypt192),
    AES256(MagicCrypt256),
}

/// This struct can help you encrypt or decrypt data in a quick way.
#[derive(Debug, Clone)]
pub struct MagicCrypt {
    cipher: MagicCryptCipher,
}

impl MagicCrypt {
    /// Create a new `MagicCrypt` instance. You may want to use the `new_magic_crypt!` macro.
    pub fn new<S: AsRef<str>, V: AsRef<str>>(key: S, bit: SecureBit, iv: Option<V>) -> MagicCrypt {
        let cipher = match bit {
            SecureBit::Bit64 => MagicCryptCipher::DES64(MagicCrypt64::new(key, iv)),
            SecureBit::Bit128 => MagicCryptCipher::AES128(MagicCrypt128::new(key, iv)),
            SecureBit::Bit192 => MagicCryptCipher::AES192(MagicCrypt192::new(key, iv)),
            SecureBit::Bit256 => MagicCryptCipher::AES256(MagicCrypt256::new(key, iv)),
        };

        MagicCrypt {
            cipher,
        }
    }
}

impl MagicCryptTrait for MagicCrypt {
    #[inline]
    fn new<S: AsRef<str>, V: AsRef<str>>(key: S, iv: Option<V>) -> MagicCrypt {
        MagicCrypt::new(key, SecureBit::default(), iv)
    }

    #[inline]
    fn encrypt_to_bytes<T: ?Sized + AsRef<[u8]>>(&self, data: &T) -> Vec<u8> {
        match &self.cipher {
            MagicCryptCipher::DES64(mc) => mc.encrypt_to_bytes(data),
            MagicCryptCipher::AES128(mc) => mc.encrypt_to_bytes(data),
            MagicCryptCipher::AES192(mc) => mc.encrypt_to_bytes(data),
            MagicCryptCipher::AES256(mc) => mc.encrypt_to_bytes(data),
        }
    }

    #[inline]
    fn encrypt_reader_to_bytes(&self, reader: &mut dyn Read) -> Result<Vec<u8>, MagicCryptError> {
        match &self.cipher {
            MagicCryptCipher::DES64(mc) => mc.encrypt_reader_to_bytes(reader),
            MagicCryptCipher::AES128(mc) => mc.encrypt_reader_to_bytes(reader),
            MagicCryptCipher::AES192(mc) => mc.encrypt_reader_to_bytes(reader),
            MagicCryptCipher::AES256(mc) => mc.encrypt_reader_to_bytes(reader),
        }
    }

    #[inline]
    fn encrypt_reader_to_writer(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), MagicCryptError> {
        match &self.cipher {
            MagicCryptCipher::DES64(mc) => mc.encrypt_reader_to_writer(reader, writer),
            MagicCryptCipher::AES128(mc) => mc.encrypt_reader_to_writer(reader, writer),
            MagicCryptCipher::AES192(mc) => mc.encrypt_reader_to_writer(reader, writer),
            MagicCryptCipher::AES256(mc) => mc.encrypt_reader_to_writer(reader, writer),
        }
    }

    #[inline]
    fn decrypt_bytes_to_bytes<T: ?Sized + AsRef<[u8]>>(
        &self,
        bytes: &T,
    ) -> Result<Vec<u8>, MagicCryptError> {
        match &self.cipher {
            MagicCryptCipher::DES64(mc) => mc.decrypt_bytes_to_bytes(bytes),
            MagicCryptCipher::AES128(mc) => mc.decrypt_bytes_to_bytes(bytes),
            MagicCryptCipher::AES192(mc) => mc.decrypt_bytes_to_bytes(bytes),
            MagicCryptCipher::AES256(mc) => mc.decrypt_bytes_to_bytes(bytes),
        }
    }

    #[inline]
    fn decrypt_reader_to_bytes(&self, reader: &mut dyn Read) -> Result<Vec<u8>, MagicCryptError> {
        match &self.cipher {
            MagicCryptCipher::DES64(mc) => mc.decrypt_reader_to_bytes(reader),
            MagicCryptCipher::AES128(mc) => mc.decrypt_reader_to_bytes(reader),
            MagicCryptCipher::AES192(mc) => mc.decrypt_reader_to_bytes(reader),
            MagicCryptCipher::AES256(mc) => mc.decrypt_reader_to_bytes(reader),
        }
    }

    #[inline]
    fn decrypt_reader_to_writer(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), MagicCryptError> {
        match &self.cipher {
            MagicCryptCipher::DES64(mc) => mc.decrypt_reader_to_writer(reader, writer),
            MagicCryptCipher::AES128(mc) => mc.decrypt_reader_to_writer(reader, writer),
            MagicCryptCipher::AES192(mc) => mc.decrypt_reader_to_writer(reader, writer),
            MagicCryptCipher::AES256(mc) => mc.decrypt_reader_to_writer(reader, writer),
        }
    }
}
