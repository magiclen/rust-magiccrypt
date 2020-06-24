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

## Change the Buffer Size

The default buffer size for the `encrypt_reader_to_writer` method and the `decrypt_reader_to_writer` method is 4096 bytes. If you want to change that, you can use the `encrypt_reader_to_writer2` method or the `decrypt_reader_to_writer2` method, and define a length explicitly.

For example, to change the buffer size to 256 bytes,

```rust
#[macro_use] extern crate magic_crypt;
extern crate base64;

use std::io::Cursor;

use magic_crypt::MagicCryptTrait;
use magic_crypt::generic_array::typenum::U256;

let mut mc = new_magic_crypt!("magickey", 256);

# #[cfg(feature = "std")] {
let mut reader = Cursor::new("http://magiclen.org");
let mut writer = Vec::new();

mc.encrypt_reader_to_writer2::<U256>(&mut reader, &mut writer).unwrap();

let base64 = base64::encode(&writer);

assert_eq!("DS/2U8royDnJDiNY2ps3f6ZoTbpZo8ZtUGYLGEjwLDQ=", base64);

assert_eq!("http://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
# }
```

## No Std

Disable the default features to compile this crate without std.

```toml
[dependencies.magic-crypt]
version = "*"
default-features = false
```

## For Java

Refer to https://github.com/magiclen/MagicCrypt.

## For PHP

Refer to https://github.com/magiclen/MagicCrypt.

## For NodeJS

Refer to https://github.com/magiclen/node-magiccrypt
*/

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

extern crate digest;

mod ciphers;
mod errors;
mod functions;
mod macros;
mod secure_bit;
mod traits;

use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::io::{Read, Write};
#[cfg(feature = "std")]
use std::ops::Add;

pub use ciphers::aes128::MagicCrypt128;
pub use ciphers::aes192::MagicCrypt192;
pub use ciphers::aes256::MagicCrypt256;
pub use ciphers::des64::MagicCrypt64;
pub use digest::generic_array;
pub use errors::MagicCryptError;
pub use secure_bit::SecureBit;
pub use traits::MagicCryptTrait;

#[cfg(feature = "std")]
use generic_array::typenum::{IsGreaterOrEqual, PartialDiv, True, B1, U16};
#[cfg(feature = "std")]
use generic_array::ArrayLength;

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

    #[cfg(feature = "std")]
    #[inline]
    fn encrypt_reader_to_bytes(&self, reader: &mut dyn Read) -> Result<Vec<u8>, MagicCryptError> {
        match &self.cipher {
            MagicCryptCipher::DES64(mc) => mc.encrypt_reader_to_bytes(reader),
            MagicCryptCipher::AES128(mc) => mc.encrypt_reader_to_bytes(reader),
            MagicCryptCipher::AES192(mc) => mc.encrypt_reader_to_bytes(reader),
            MagicCryptCipher::AES256(mc) => mc.encrypt_reader_to_bytes(reader),
        }
    }

    #[cfg(feature = "std")]
    #[inline]
    fn encrypt_reader_to_writer2<
        N: ArrayLength<u8> + PartialDiv<U16> + IsGreaterOrEqual<U16, Output = True>,
    >(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), MagicCryptError> {
        match &self.cipher {
            MagicCryptCipher::DES64(mc) => mc.encrypt_reader_to_writer2::<N>(reader, writer),
            MagicCryptCipher::AES128(mc) => mc.encrypt_reader_to_writer2::<N>(reader, writer),
            MagicCryptCipher::AES192(mc) => mc.encrypt_reader_to_writer2::<N>(reader, writer),
            MagicCryptCipher::AES256(mc) => mc.encrypt_reader_to_writer2::<N>(reader, writer),
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

    #[cfg(feature = "std")]
    #[inline]
    fn decrypt_reader_to_bytes(&self, reader: &mut dyn Read) -> Result<Vec<u8>, MagicCryptError> {
        match &self.cipher {
            MagicCryptCipher::DES64(mc) => mc.decrypt_reader_to_bytes(reader),
            MagicCryptCipher::AES128(mc) => mc.decrypt_reader_to_bytes(reader),
            MagicCryptCipher::AES192(mc) => mc.decrypt_reader_to_bytes(reader),
            MagicCryptCipher::AES256(mc) => mc.decrypt_reader_to_bytes(reader),
        }
    }

    #[cfg(feature = "std")]
    #[inline]
    fn decrypt_reader_to_writer2<
        N: ArrayLength<u8> + PartialDiv<U16> + IsGreaterOrEqual<U16, Output = True> + Add<B1>,
    >(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), MagicCryptError>
    where
        <N as Add<B1>>::Output: ArrayLength<u8>, {
        match &self.cipher {
            MagicCryptCipher::DES64(mc) => mc.decrypt_reader_to_writer(reader, writer),
            MagicCryptCipher::AES128(mc) => mc.decrypt_reader_to_writer(reader, writer),
            MagicCryptCipher::AES192(mc) => mc.decrypt_reader_to_writer(reader, writer),
            MagicCryptCipher::AES256(mc) => mc.decrypt_reader_to_writer(reader, writer),
        }
    }
}
