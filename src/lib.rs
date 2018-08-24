//! # MagicCrypt
//!
//! ## Introduction
//! MagicCrypt is a Java/PHP/NodeJS/Rust library to encrypt/decrpyt strings, files, or data, using Data Encryption Standard(DES) or Advanced Encryption Standard(AES) algorithms. It supports CBC block cipher mode, PKCS5 padding and 64, 128, 192 or 256-bits key length. If the encrypted data is a string, it will be formatted automatically to Base64.
//!
//! ## For Rust
//!
//! ### Example
//!
//! ```
//! #[macro_use] extern crate magic_crypt;
//!
//! use magic_crypt::MagicCrypt;
//!
//! let mut mc: MagicCrypt = new_magic_crypt!("magickey", 256);
//!
//! let base64 = mc.encrypt_str_to_base64("http://magiclen.org");
//!
//! assert_eq!("DS/2U8royDnJDiNY2ps3f6ZoTbpZo8ZtUGYLGEjwLDQ=", base64);
//!
//! assert_eq!("http://magiclen.org", mc.decrypt_base64_to_string(&base64).unwrap());
//!```
//!
//! ## For Java
//!
//! Refer to https://github.com/magiclen/MagicCrypt.
//!
//! ## For PHP
//!
//! Refer to https://github.com/magiclen/MagicCrypt.
//!
//! ## For NodeJS
//!
//! Refer to https://github.com/magiclen/node-magiccrypt

extern crate crypto;
extern crate crc_any;
extern crate base64;
extern crate digest;
extern crate des;
extern crate block_modes;
extern crate tiger_digest;

use std::io::{self, Read, Write};
use std::string::FromUtf8Error;

use crc_any::CRC;

use tiger_digest::Tiger;
use digest::FixedOutput;
use digest::generic_array::GenericArray;

use des::Des;
use block_modes::{BlockMode, BlockModeIv, Cbc};
use block_modes::block_padding::Pkcs7;

type DesCbc = Cbc<Des, Pkcs7>;

use crypto::aes::{KeySize, cbc_encryptor, cbc_decryptor};
use crypto::symmetriccipher::{Encryptor, Decryptor, SymmetricCipherError};
use crypto::blockmodes::{PkcsPadding, PaddingProcessor};
use crypto::buffer::{RefReadBuffer, RefWriteBuffer, BufferResult, WriteBuffer, ReadBuffer};
use crypto::md5::Md5;
use crypto::sha2::Sha256;
use crypto::digest::Digest;

const BUFFER_SIZE: usize = 4096;

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

pub struct MagicCryptAES {
    encryptor: Box<Encryptor>,
    decryptor: Box<Decryptor>,
}

pub struct MagicCryptDES {
    key: [u8; 8],
    iv: [u8; 8],
}

pub enum MagicCrypt {
    AES(MagicCryptAES),
    DES(MagicCryptDES),
}

macro_rules! get_aes_cipher_len {
    ( $len:expr ) => {
        {
            (($len + 16) / 16 ) * 16
        }
    }
}

macro_rules! get_des_cipher_space {
    ( $len:expr ) => {
        {
            (($len + 8) / 8 ) * 8 + ($len % 8)
        }
    }
}

pub struct EncPadding<X> {
    padding: X
}

impl<X: PaddingProcessor> EncPadding<X> {
    fn wrap(p: X) -> EncPadding<X> { EncPadding { padding: p } }
}

impl<X: PaddingProcessor> PaddingProcessor for EncPadding<X> {
    fn pad_input<W: WriteBuffer>(&mut self, a: &mut W) { self.padding.pad_input(a); }
    fn strip_output<R: ReadBuffer>(&mut self, _: &mut R) -> bool { true }
}

pub struct DecPadding<X> {
    padding: X
}

impl<X: PaddingProcessor> DecPadding<X> {
    fn wrap(p: X) -> DecPadding<X> { DecPadding { padding: p } }
}

impl<X: PaddingProcessor> PaddingProcessor for DecPadding<X> {
    fn pad_input<W: WriteBuffer>(&mut self, _: &mut W) {}
    fn strip_output<R: ReadBuffer>(&mut self, a: &mut R) -> bool { self.padding.strip_output(a) }
}

macro_rules! enc_padding {
    ( ) => {
        {
            EncPadding::wrap(PkcsPadding)
        }
    }
}

macro_rules! dec_padding {
    ( ) => {
        {
            DecPadding::wrap(PkcsPadding)
        }
    }
}

#[derive(Debug)]
pub enum Error {
    CipherError(SymmetricCipherError),
    IOError(io::Error),
    Base64Error(base64::DecodeError),
    StringError(FromUtf8Error),
}

impl MagicCrypt {
    pub fn new(key: &str, bit: SecureBit, iv: Option<&str>) -> MagicCrypt {
        if let SecureBit::Bit64 = bit {
            let iv = match iv {
                Some(s) => {
                    let mut crc64ecma = CRC::crc64ecma();
                    crc64ecma.digest(s.as_bytes());

                    crc64ecma.get_crc_array().0
                }
                None => [0u8; 8]
            };

            let key: [u8; 8] = {
                let mut crc64ecma = CRC::crc64ecma();
                crc64ecma.digest(key.as_bytes());

                crc64ecma.get_crc_array().0
            };

            MagicCrypt::DES(MagicCryptDES { key, iv })
        } else {
            let iv = match iv {
                Some(s) => {
                    let mut md5 = Md5::new();

                    md5.input(s.as_bytes());

                    let mut key = [0u8; 16];

                    md5.result(&mut key);

                    key
                }
                None => [0u8; 16]
            };

            match bit {
                SecureBit::Bit128 => {
                    let mut md5 = Md5::new();

                    md5.input(key.as_bytes());

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

                    tiger.consume(key.as_bytes());

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

                    sha265.input(key.as_bytes());

                    let mut key = [0u8; 32];

                    sha265.result(&mut key);

                    let encryptor = cbc_encryptor(KeySize::KeySize256, &key, &iv, enc_padding!());
                    let decryptor = cbc_decryptor(KeySize::KeySize256, &key, &iv, dec_padding!());

                    MagicCrypt::AES(MagicCryptAES {
                        encryptor,
                        decryptor,
                    })
                }
                _ => panic!("not here")
            }
        }
    }

    pub fn encrypt_str_to_base64(&mut self, string: &str) -> String {
        self.encrypt_bytes_to_base64(string.as_bytes())
    }

    pub fn encrypt_str_to_bytes(&mut self, string: &str) -> Vec<u8> {
        self.encrypt_bytes_to_bytes(string.as_bytes())
    }

    pub fn encrypt_bytes_to_base64(&mut self, bytes: &[u8]) -> String {
        base64::encode(&self.encrypt_bytes_to_bytes(bytes))
    }

    pub fn encrypt_bytes_to_bytes(&mut self, bytes: &[u8]) -> Vec<u8> {
        match self {
            MagicCrypt::DES(mc) => {
                let len = bytes.len();

                let final_len = get_des_cipher_space!(len);

                let mut buffer = Vec::with_capacity(final_len);

                unsafe {
                    buffer.set_len(final_len);
                }

                buffer[..len].copy_from_slice(&bytes);

                let cipher = DesCbc::new_varkey(&mc.key, GenericArray::from_slice(&mc.iv)).unwrap();

                let enc = cipher.encrypt_pad(&mut buffer, len).unwrap();

                enc.to_vec()
            }
            MagicCrypt::AES(mc) => {
                let mut final_result = Vec::with_capacity(get_aes_cipher_len!(bytes.len()));

                let mut buffer = [0u8; BUFFER_SIZE];

                let mut output = RefWriteBuffer::new(&mut buffer);

                loop {
                    let result = mc.encryptor.encrypt(&mut RefReadBuffer::new(bytes), &mut output, true).unwrap();

                    final_result.extend(output
                        .take_read_buffer()
                        .take_remaining());

                    if let BufferResult::BufferUnderflow = result {
                        break;
                    }
                }

                final_result
            }
        }
    }

    pub fn encrypt_reader_to_base64(&mut self, reader: &mut Read) -> Result<String, Error> {
        self.encrypt_reader_to_bytes(reader).map(|bytes| base64::encode(&bytes))
    }

    pub fn encrypt_reader_to_bytes(&mut self, reader: &mut Read) -> Result<Vec<u8>, Error> {
        match self {
            MagicCrypt::DES(mc) => {
                let mut final_result = Vec::new();

                let mut buffer1 = [0u8; BUFFER_SIZE + 16];

                loop {
                    match reader.read(&mut buffer1) {
                        Ok(c) => {
                            if c <= 0 {
                                break;
                            }

                            let cipher = DesCbc::new_varkey(&mc.key, GenericArray::from_slice(&mc.iv)).unwrap();

                            let enc = cipher.encrypt_pad(&mut buffer1[..BUFFER_SIZE], c).unwrap();

                            final_result.extend(enc);
                        }
                        Err(err) => return Err(Error::IOError(err))
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
                            if c <= 0 {
                                break;
                            }

                            loop {
                                let mut output = RefWriteBuffer::new(&mut buffer2);

                                let result = mc.encryptor.encrypt(&mut RefReadBuffer::new(&buffer1[..c]), &mut output, false).map_err(|err| Error::CipherError(err))?;

                                final_result.write(output
                                    .take_read_buffer()
                                    .take_remaining()).map_err(|err| Error::IOError(err))?;

                                if let BufferResult::BufferUnderflow = result {
                                    break;
                                }
                            }
                        }
                        Err(err) => return Err(Error::IOError(err))
                    }
                }

                Ok(final_result)
            }
        }
    }

    pub fn encrypt_reader_to_writer(&mut self, reader: &mut Read, writer: &mut Write) -> Result<(), Error> {
        match self {
            MagicCrypt::DES(mc) => {
                let mut buffer1 = [0u8; BUFFER_SIZE + 16];

                loop {
                    match reader.read(&mut buffer1) {
                        Ok(c) => {
                            if c <= 0 {
                                break;
                            }

                            let cipher = DesCbc::new_varkey(&mc.key, GenericArray::from_slice(&mc.iv)).unwrap();

                            let enc = cipher.encrypt_pad(&mut buffer1[..BUFFER_SIZE], c).unwrap();

                            writer.write(enc).map_err(|err| Error::IOError(err))?;
                        }
                        Err(err) => return Err(Error::IOError(err))
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
                            if c <= 0 {
                                break;
                            }

                            loop {
                                let mut output = RefWriteBuffer::new(&mut buffer2);

                                let result = mc.encryptor.encrypt(&mut RefReadBuffer::new(&buffer1[..c]), &mut output, true).map_err(|err| Error::CipherError(err))?;

                                writer.write(output
                                    .take_read_buffer()
                                    .take_remaining()).map_err(|err| Error::IOError(err))?;

                                if let BufferResult::BufferUnderflow = result {
                                    break;
                                }
                            }
                        }
                        Err(err) => return Err(Error::IOError(err))
                    }
                }

                Ok(())
            }
        }
    }

    pub fn decrypt_base64_to_string(&mut self, base64: &str) -> Result<String, Error> {
        String::from_utf8(self.decrypt_base64_to_bytes(base64)?).map_err(|err| Error::StringError(err))
    }

    pub fn decrypt_base64_to_bytes(&mut self, base64: &str) -> Result<Vec<u8>, Error> {
        self.decrypt_bytes_to_bytes(&base64::decode(base64.as_bytes()).map_err(|err| Error::Base64Error(err))?)
    }

    pub fn decrypt_bytes_to_string(&mut self, bytes: &[u8]) -> Result<String, Error> {
        String::from_utf8(self.decrypt_bytes_to_bytes(bytes)?).map_err(|err| Error::StringError(err))
    }

    pub fn decrypt_bytes_to_bytes(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            MagicCrypt::DES(mc) => {
                let mut buffer = bytes.to_vec();

                let cipher = DesCbc::new_varkey(&mc.key, GenericArray::from_slice(&mc.iv)).unwrap();

                let dec = cipher.decrypt_pad(&mut buffer).unwrap();

                Ok(dec.to_vec())
            }
            MagicCrypt::AES(mc) => {
                let mut final_result = Vec::with_capacity(bytes.len());

                let mut buffer = [0u8; BUFFER_SIZE];

                let mut output = RefWriteBuffer::new(&mut buffer);

                loop {
                    let result = mc.decryptor.decrypt(&mut RefReadBuffer::new(bytes), &mut output, true).unwrap();

                    final_result.extend(output
                        .take_read_buffer()
                        .take_remaining());

                    if let BufferResult::BufferUnderflow = result {
                        break;
                    }
                }

                Ok(final_result)
            }
        }
    }

    pub fn decrypt_reader_to_bytes(&mut self, reader: &mut Read) -> Result<Vec<u8>, Error> {
        match self {
            MagicCrypt::DES(mc) => {
                let mut final_result = Vec::new();

                let mut buffer = [0u8; BUFFER_SIZE];

                loop {
                    match reader.read(&mut buffer) {
                        Ok(c) => {
                            if c <= 0 {
                                break;
                            }

                            let cipher = DesCbc::new_varkey(&mc.key, GenericArray::from_slice(&mc.iv)).unwrap();

                            let dec = cipher.decrypt_pad(&mut buffer[..c]).unwrap();

                            final_result.extend(dec);
                        }
                        Err(err) => return Err(Error::IOError(err))
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
                            if c <= 0 {
                                break;
                            }

                            loop {
                                let mut output = RefWriteBuffer::new(&mut buffer2);

                                let result = mc.decryptor.decrypt(&mut RefReadBuffer::new(&buffer1[..c]), &mut output, false).map_err(|err| Error::CipherError(err))?;

                                final_result.write(output
                                    .take_read_buffer()
                                    .take_remaining()).map_err(|err| Error::IOError(err))?;

                                if let BufferResult::BufferUnderflow = result {
                                    break;
                                }
                            }
                        }
                        Err(err) => return Err(Error::IOError(err))
                    }
                }

                Ok(final_result)
            }
        }
    }

    pub fn decrypt_reader_to_writer(&mut self, reader: &mut Read, writer: &mut Write) -> Result<(), Error> {
        match self {
            MagicCrypt::DES(mc) => {
                let mut buffer = [0u8; BUFFER_SIZE];

                loop {
                    match reader.read(&mut buffer) {
                        Ok(c) => {
                            if c <= 0 {
                                break;
                            }

                            let cipher = DesCbc::new_varkey(&mc.key, GenericArray::from_slice(&mc.iv)).unwrap();

                            let dec = cipher.decrypt_pad(&mut buffer[..c]).unwrap();

                            writer.write(dec).map_err(|err| Error::IOError(err))?;
                        }
                        Err(err) => return Err(Error::IOError(err))
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
                            if c <= 0 {
                                break;
                            }

                            loop {
                                let mut output = RefWriteBuffer::new(&mut buffer2);

                                let result = mc.decryptor.decrypt(&mut RefReadBuffer::new(&buffer1[..c]), &mut output, true).map_err(|err| Error::CipherError(err))?;

                                writer.write(output
                                    .take_read_buffer()
                                    .take_remaining()).map_err(|err| Error::IOError(err))?;

                                if let BufferResult::BufferUnderflow = result {
                                    break;
                                }
                            }
                        }
                        Err(err) => return Err(Error::IOError(err))
                    }
                }

                Ok(())
            }
        }
    }
}

#[macro_export]
macro_rules! new_magic_crypt {
    ( $key:expr ) => {
        {
            use self::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit128, None)
        }
    };
    ( $key:expr, 64 ) => {
        {
            use self::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit64, None)
        }
    };
    ( $key:expr, 128 ) => {
        {
            use self::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit128, None)
        }
    };
    ( $key:expr, 192 ) => {
        {
            use self::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit192, None)
        }
    };
    ( $key:expr, 256 ) => {
        {
            use self::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit256, None)
        }
    };
    ( $key:expr, 64 ) => {
        {
            use self::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit64, None)
        }
    };
    ( $key:expr, 128, $iv:expr ) => {
        {
            use self::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit128, Some($iv))
        }
    };
    ( $key:expr, 192, $iv:expr ) => {
        {
            use self::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit192, Some($iv))
        }
    };
    ( $key:expr, 256, $iv:expr ) => {
        {
            use self::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit256, Some($iv))
        }
    };
}

