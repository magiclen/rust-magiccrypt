/*!
# MagicCrypt

MagicCrypt is a Java/PHP/NodeJS/Rust library to encrypt/decrpyt strings, files, or data, using Data Encryption Standard(DES) or Advanced Encryption Standard(AES) algorithms. It supports CBC block cipher mode, PKCS5 padding and 64, 128, 192 or 256-bits key length. If the encrypted data is a string, it will be formatted automatically to Base64.

## For Rust

### Example

```rust
#[macro_use] extern crate magic_crypt;

use magic_crypt::MagicCrypt;

let mut mc: MagicCrypt = new_magic_crypt!("magickey", 256);

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

extern crate base64;
extern crate block_modes;
extern crate crc_any;
extern crate crypto;
extern crate des;
extern crate digest;
extern crate digest_old;
extern crate tiger_digest;

use std::error::Error as StdError;
use std::fmt::{Display, Error as FmtError, Formatter};
use std::io::{self, Read, Write};
use std::mem::transmute;
use std::string::FromUtf8Error;

use crc_any::CRCu64;

use digest::generic_array::GenericArray;
use digest_old::FixedOutput as OldFixedOutput;
use tiger_digest::Tiger;

use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use des::block_cipher_trait::BlockCipher;
use des::Des;

type DesCbc = Cbc<Des, Pkcs7>;

use crypto::aes::{cbc_decryptor, cbc_encryptor, KeySize};
use crypto::blockmodes::{PaddingProcessor, PkcsPadding};
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::sha2::Sha256;
use crypto::symmetriccipher::{Decryptor, Encryptor, SymmetricCipherError};

const BUFFER_SIZE: usize = 4096;

/// How secure does your encryption need to be?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecureBit {
    Bit64,
    Bit128,
    Bit192,
    Bit256,
}

impl SecureBit {
    pub fn from(bit_number: u16) -> Result<SecureBit, &'static str> {
        Ok(if bit_number == 64 {
            SecureBit::Bit64
        } else if bit_number == 128 {
            SecureBit::Bit128
        } else if bit_number == 192 {
            SecureBit::Bit192
        } else if bit_number == 256 {
            SecureBit::Bit256
        } else {
            return Err("Unsupported number of bits.");
        })
    }
}

/// You should use `MagicCrypt` enum.
pub struct MagicCryptAES {
    encryptor: Box<dyn Encryptor>,
    decryptor: Box<dyn Decryptor>,
}

/// You should use `MagicCrypt` enum.
pub struct MagicCryptDES {
    key: [u8; 8],
    iv: [u8; 8],
}

/// This enum of structs can help you encrypt or decrypt data in a quick way.
pub enum MagicCrypt {
    AES(MagicCryptAES),
    DES(MagicCryptDES),
}

macro_rules! get_aes_cipher_len {
    ($len:expr) => {{
        (($len + 16) / 16) * 16
    }};
}

macro_rules! get_des_cipher_space {
    ($len:expr) => {{
        (($len + 8) / 8) * 8 + ($len % 8)
    }};
}

struct EncPadding<X> {
    padding: X,
}

impl<X: PaddingProcessor> EncPadding<X> {
    fn wrap(p: X) -> EncPadding<X> {
        EncPadding {
            padding: p,
        }
    }
}

impl<X: PaddingProcessor> PaddingProcessor for EncPadding<X> {
    fn pad_input<W: WriteBuffer>(&mut self, a: &mut W) {
        self.padding.pad_input(a);
    }

    fn strip_output<R: ReadBuffer>(&mut self, _: &mut R) -> bool {
        true
    }
}

struct DecPadding<X> {
    padding: X,
}

impl<X: PaddingProcessor> DecPadding<X> {
    fn wrap(p: X) -> DecPadding<X> {
        DecPadding {
            padding: p,
        }
    }
}

impl<X: PaddingProcessor> PaddingProcessor for DecPadding<X> {
    fn pad_input<W: WriteBuffer>(&mut self, _: &mut W) {}

    fn strip_output<R: ReadBuffer>(&mut self, a: &mut R) -> bool {
        self.padding.strip_output(a)
    }
}

macro_rules! enc_padding {
    () => {{
        EncPadding::wrap(PkcsPadding)
    }};
}

macro_rules! dec_padding {
    () => {{
        DecPadding::wrap(PkcsPadding)
    }};
}

/// Errors for MagicCrypt.
#[derive(Debug)]
pub enum Error {
    CipherError(SymmetricCipherError),
    IOError(io::Error),
    Base64Error(base64::DecodeError),
    StringError(FromUtf8Error),
}

impl Display for Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        match self {
            Error::CipherError(err) => {
                match err {
                    SymmetricCipherError::InvalidLength => f.write_str("The length is invalid."),
                    SymmetricCipherError::InvalidPadding => f.write_str("The padding is invalid."),
                }
            }
            Error::IOError(err) => Display::fmt(err, f),
            Error::Base64Error(err) => Display::fmt(err, f),
            Error::StringError(err) => Display::fmt(err, f),
        }
    }
}

impl StdError for Error {}

impl From<SymmetricCipherError> for Error {
    #[inline]
    fn from(err: SymmetricCipherError) -> Self {
        Error::CipherError(err)
    }
}

impl From<io::Error> for Error {
    #[inline]
    fn from(err: io::Error) -> Self {
        Error::IOError(err)
    }
}

impl From<base64::DecodeError> for Error {
    #[inline]
    fn from(err: base64::DecodeError) -> Self {
        Error::Base64Error(err)
    }
}

impl From<FromUtf8Error> for Error {
    #[inline]
    fn from(err: FromUtf8Error) -> Self {
        Error::StringError(err)
    }
}

impl MagicCrypt {
    /// Create a new MagicCrypt instance. You may want to use `new_magic_crypt!` macro.
    pub fn new<S: AsRef<str>, V: AsRef<str>>(key: S, bit: SecureBit, iv: Option<V>) -> MagicCrypt {
        if let SecureBit::Bit64 = bit {
            let iv = match iv {
                Some(s) => {
                    let mut crc64ecma = CRCu64::crc64we();
                    crc64ecma.digest(s.as_ref().as_bytes());

                    unsafe { transmute(crc64ecma.get_crc().to_be()) }
                }
                None => [0u8; 8],
            };

            let key: [u8; 8] = {
                let mut crc64ecma = CRCu64::crc64we();
                crc64ecma.digest(key.as_ref().as_bytes());

                unsafe { transmute(crc64ecma.get_crc().to_be()) }
            };

            MagicCrypt::DES(MagicCryptDES {
                key,
                iv,
            })
        } else {
            let iv = match iv {
                Some(s) => {
                    let mut md5 = Md5::new();

                    md5.input(s.as_ref().as_bytes());

                    let mut key = [0u8; 16];

                    md5.result(&mut key);

                    key
                }
                None => [0u8; 16],
            };

            match bit {
                SecureBit::Bit128 => {
                    let mut md5 = Md5::new();

                    md5.input(key.as_ref().as_bytes());

                    let mut key = [0u8; 16];

                    md5.result(&mut key);

                    let encryptor = cbc_encryptor(KeySize::KeySize128, &key, &iv, enc_padding!());
                    let decryptor = cbc_decryptor(KeySize::KeySize128, &key, &iv, dec_padding!());

                    MagicCrypt::AES(MagicCryptAES {
                        encryptor,
                        decryptor,
                    })
                }
                SecureBit::Bit192 => {
                    let mut tiger = Tiger::default();

                    tiger.consume(key.as_ref().as_bytes());

                    let key = tiger.fixed_result();

                    let encryptor = cbc_encryptor(KeySize::KeySize192, &key, &iv, enc_padding!());
                    let decryptor = cbc_decryptor(KeySize::KeySize192, &key, &iv, dec_padding!());

                    MagicCrypt::AES(MagicCryptAES {
                        encryptor,
                        decryptor,
                    })
                }
                SecureBit::Bit256 => {
                    let mut sha265 = Sha256::new();

                    sha265.input(key.as_ref().as_bytes());

                    let mut key = [0u8; 32];

                    sha265.result(&mut key);

                    let encryptor = cbc_encryptor(KeySize::KeySize256, &key, &iv, enc_padding!());
                    let decryptor = cbc_decryptor(KeySize::KeySize256, &key, &iv, dec_padding!());

                    MagicCrypt::AES(MagicCryptAES {
                        encryptor,
                        decryptor,
                    })
                }
                _ => unreachable!(),
            }
        }
    }

    #[inline]
    pub fn encrypt_str_to_base64<S: AsRef<str>>(&mut self, string: S) -> String {
        self.encrypt_to_base64(string.as_ref())
    }

    #[inline]
    pub fn encrypt_str_to_bytes<S: AsRef<str>>(&mut self, string: S) -> Vec<u8> {
        self.encrypt_to_bytes(string.as_ref())
    }

    #[inline]
    pub fn encrypt_bytes_to_base64<T: ?Sized + AsRef<[u8]>>(&mut self, bytes: &T) -> String {
        self.encrypt_to_base64(bytes)
    }

    #[inline]
    pub fn encrypt_bytes_to_bytes<T: ?Sized + AsRef<[u8]>>(&mut self, bytes: &T) -> Vec<u8> {
        self.encrypt_to_bytes(bytes)
    }

    #[inline]
    pub fn encrypt_to_base64<T: ?Sized + AsRef<[u8]>>(&mut self, data: &T) -> String {
        base64::encode(&self.encrypt_to_bytes(data))
    }

    pub fn encrypt_to_bytes<T: ?Sized + AsRef<[u8]>>(&mut self, data: &T) -> Vec<u8> {
        let bytes = data.as_ref();

        match self {
            MagicCrypt::DES(mc) => {
                let len = bytes.len();

                let final_len = get_des_cipher_space!(len);

                let mut buffer = Vec::with_capacity(final_len);

                unsafe {
                    buffer.set_len(final_len);
                }

                buffer[..len].copy_from_slice(&bytes);

                let cipher = DesCbc::new(
                    Des::new(GenericArray::from_slice(&mc.key)),
                    GenericArray::from_slice(&mc.iv),
                );

                cipher.encrypt_vec(&buffer[..len])
            }
            MagicCrypt::AES(mc) => {
                let mut final_result = Vec::with_capacity(get_aes_cipher_len!(bytes.len()));

                let mut buffer = [0u8; BUFFER_SIZE];

                let mut output = RefWriteBuffer::new(&mut buffer);

                loop {
                    let result = mc
                        .encryptor
                        .encrypt(&mut RefReadBuffer::new(bytes), &mut output, true)
                        .unwrap();

                    final_result.extend(output.take_read_buffer().take_remaining());

                    if let BufferResult::BufferUnderflow = result {
                        break;
                    }
                }

                final_result
            }
        }
    }

    #[inline]
    pub fn encrypt_reader_to_base64(&mut self, reader: &mut dyn Read) -> Result<String, Error> {
        self.encrypt_reader_to_bytes(reader).map(|bytes| base64::encode(&bytes))
    }

    pub fn encrypt_reader_to_bytes(&mut self, reader: &mut dyn Read) -> Result<Vec<u8>, Error> {
        match self {
            MagicCrypt::DES(mc) => {
                let mut final_result = Vec::new();

                let mut buffer1 = [0u8; BUFFER_SIZE];

                loop {
                    match reader.read(&mut buffer1) {
                        Ok(c) => {
                            if c == 0 {
                                break;
                            }

                            let cipher = DesCbc::new(
                                Des::new(GenericArray::from_slice(&mc.key)),
                                GenericArray::from_slice(&mc.iv),
                            );

                            final_result.extend(cipher.encrypt_vec(&buffer1[..c]));
                        }
                        Err(err) => return Err(Error::IOError(err)),
                    }
                }

                Ok(final_result)
            }
            MagicCrypt::AES(mc) => {
                let mut final_result = Vec::new();

                let mut buffer1 = [0u8; BUFFER_SIZE];

                let mut buffer2 = [0u8; BUFFER_SIZE];

                loop {
                    match reader.read(&mut buffer1) {
                        Ok(c) => {
                            if c == 0 {
                                break;
                            }

                            loop {
                                let mut output = RefWriteBuffer::new(&mut buffer2);

                                let result = mc.encryptor.encrypt(
                                    &mut RefReadBuffer::new(&buffer1[..c]),
                                    &mut output,
                                    false,
                                )?;

                                final_result
                                    .write_all(output.take_read_buffer().take_remaining())?;

                                if let BufferResult::BufferUnderflow = result {
                                    break;
                                }
                            }
                        }
                        Err(err) => return Err(Error::IOError(err)),
                    }
                }

                Ok(final_result)
            }
        }
    }

    pub fn encrypt_reader_to_writer(
        &mut self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), Error> {
        match self {
            MagicCrypt::DES(mc) => {
                let mut buffer1 = [0u8; BUFFER_SIZE];

                loop {
                    match reader.read(&mut buffer1) {
                        Ok(c) => {
                            if c == 0 {
                                break;
                            }

                            let cipher = DesCbc::new(
                                Des::new(GenericArray::from_slice(&mc.key)),
                                GenericArray::from_slice(&mc.iv),
                            );

                            writer.write_all(&cipher.encrypt_vec(&buffer1[..c]))?;
                        }
                        Err(err) => return Err(Error::IOError(err)),
                    }
                }

                Ok(())
            }
            MagicCrypt::AES(mc) => {
                let mut buffer1 = [0u8; BUFFER_SIZE];

                let mut buffer2 = [0u8; BUFFER_SIZE];

                loop {
                    match reader.read(&mut buffer1) {
                        Ok(c) => {
                            if c == 0 {
                                break;
                            }

                            loop {
                                let mut output = RefWriteBuffer::new(&mut buffer2);

                                let result = mc.encryptor.encrypt(
                                    &mut RefReadBuffer::new(&buffer1[..c]),
                                    &mut output,
                                    true,
                                )?;

                                writer.write_all(output.take_read_buffer().take_remaining())?;

                                if let BufferResult::BufferUnderflow = result {
                                    break;
                                }
                            }
                        }
                        Err(err) => return Err(Error::IOError(err)),
                    }
                }

                Ok(())
            }
        }
    }

    #[inline]
    pub fn decrypt_base64_to_string<S: AsRef<str>>(&mut self, base64: S) -> Result<String, Error> {
        Ok(String::from_utf8(self.decrypt_base64_to_bytes(base64)?)?)
    }

    #[inline]
    pub fn decrypt_base64_to_bytes<S: AsRef<str>>(&mut self, base64: S) -> Result<Vec<u8>, Error> {
        self.decrypt_bytes_to_bytes(&base64::decode(base64.as_ref())?)
    }

    #[inline]
    pub fn decrypt_bytes_to_string<T: ?Sized + AsRef<[u8]>>(
        &mut self,
        bytes: &T,
    ) -> Result<String, Error> {
        Ok(String::from_utf8(self.decrypt_bytes_to_bytes(bytes)?)?)
    }

    pub fn decrypt_bytes_to_bytes<T: ?Sized + AsRef<[u8]>>(
        &mut self,
        bytes: &T,
    ) -> Result<Vec<u8>, Error> {
        let bytes = bytes.as_ref();
        match self {
            MagicCrypt::DES(mc) => {
                let buffer = bytes.to_vec();

                let cipher = DesCbc::new(
                    Des::new(GenericArray::from_slice(&mc.key)),
                    GenericArray::from_slice(&mc.iv),
                );

                Ok(cipher.decrypt_vec(&buffer).unwrap())
            }
            MagicCrypt::AES(mc) => {
                let mut final_result = Vec::with_capacity(bytes.len());

                let mut buffer = [0u8; BUFFER_SIZE];

                let mut output = RefWriteBuffer::new(&mut buffer);

                loop {
                    let result = mc
                        .decryptor
                        .decrypt(&mut RefReadBuffer::new(bytes), &mut output, true)
                        .unwrap();

                    final_result.extend(output.take_read_buffer().take_remaining());

                    if let BufferResult::BufferUnderflow = result {
                        break;
                    }
                }

                Ok(final_result)
            }
        }
    }

    pub fn decrypt_reader_to_bytes(&mut self, reader: &mut dyn Read) -> Result<Vec<u8>, Error> {
        match self {
            MagicCrypt::DES(mc) => {
                let mut final_result = Vec::new();

                let mut buffer = [0u8; BUFFER_SIZE];

                loop {
                    match reader.read(&mut buffer) {
                        Ok(c) => {
                            if c == 0 {
                                break;
                            }

                            let cipher = DesCbc::new(
                                Des::new(GenericArray::from_slice(&mc.key)),
                                GenericArray::from_slice(&mc.iv),
                            );

                            final_result.extend(cipher.decrypt_vec(&buffer[..c]).unwrap());
                        }
                        Err(err) => return Err(Error::IOError(err)),
                    }
                }

                Ok(final_result)
            }
            MagicCrypt::AES(mc) => {
                let mut final_result = Vec::new();

                let mut buffer1 = [0u8; BUFFER_SIZE];

                let mut buffer2 = [0u8; BUFFER_SIZE];

                loop {
                    match reader.read(&mut buffer1) {
                        Ok(c) => {
                            if c == 0 {
                                break;
                            }

                            loop {
                                let mut output = RefWriteBuffer::new(&mut buffer2);

                                let result = mc.decryptor.decrypt(
                                    &mut RefReadBuffer::new(&buffer1[..c]),
                                    &mut output,
                                    false,
                                )?;

                                final_result
                                    .write_all(output.take_read_buffer().take_remaining())?;

                                if let BufferResult::BufferUnderflow = result {
                                    break;
                                }
                            }
                        }
                        Err(err) => return Err(Error::IOError(err)),
                    }
                }

                Ok(final_result)
            }
        }
    }

    pub fn decrypt_reader_to_writer(
        &mut self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), Error> {
        match self {
            MagicCrypt::DES(mc) => {
                let mut buffer = [0u8; BUFFER_SIZE];

                loop {
                    match reader.read(&mut buffer) {
                        Ok(c) => {
                            if c == 0 {
                                break;
                            }

                            let cipher = DesCbc::new(
                                Des::new(GenericArray::from_slice(&mc.key)),
                                GenericArray::from_slice(&mc.iv),
                            );

                            writer.write_all(&cipher.decrypt_vec(&buffer[..c]).unwrap())?;
                        }
                        Err(err) => return Err(Error::IOError(err)),
                    }
                }

                Ok(())
            }
            MagicCrypt::AES(mc) => {
                let mut buffer1 = [0u8; BUFFER_SIZE];

                let mut buffer2 = [0u8; BUFFER_SIZE];

                loop {
                    match reader.read(&mut buffer1) {
                        Ok(c) => {
                            if c == 0 {
                                break;
                            }

                            loop {
                                let mut output = RefWriteBuffer::new(&mut buffer2);

                                let result = mc.decryptor.decrypt(
                                    &mut RefReadBuffer::new(&buffer1[..c]),
                                    &mut output,
                                    true,
                                )?;

                                writer.write_all(output.take_read_buffer().take_remaining())?;

                                if let BufferResult::BufferUnderflow = result {
                                    break;
                                }
                            }
                        }
                        Err(err) => return Err(Error::IOError(err)),
                    }
                }

                Ok(())
            }
        }
    }
}

mod macros;
