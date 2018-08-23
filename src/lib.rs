extern crate crypto;
extern crate tiny_keccak;
extern crate base64;

use std::io::{self, Read, Write};
use std::string::FromUtf8Error;

use tiny_keccak::{shake128, shake256, Keccak};

use crypto::aes::{KeySize, ecb_encryptor, ecb_decryptor};
use crypto::symmetriccipher::{Encryptor, Decryptor, SymmetricCipherError};
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer, BufferResult, WriteBuffer, ReadBuffer};

const BUFFER_SIZE: usize = 4096;

fn shake192_inner(data: &[u8], result: &mut [u8]) {
    let mut keccak = Keccak::new(200 - 24, 0x1f);
    keccak.update(data);
    keccak.finalize(result);
}

fn shake192(data: &[u8]) -> [u8; 24] {
    let mut result = [0u8; 24];
    shake192_inner(data, &mut result);

    result
}

pub enum SecureBit {
    Bit128,
    Bit192,
    Bit256,
}

impl SecureBit {
    pub fn from(bit_number: u16) -> Result<SecureBit, &'static str> {
        Ok(if bit_number == 128 {
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

pub struct MagicCrypt {
    encryptor: Box<Encryptor>,
    decryptor: Box<Decryptor>,
}

macro_rules! get_cipher_len {
    ( $len:expr ) => {
        {
            (($len + 16) / 16 ) * 16
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
    pub fn new(key: &str, bit: SecureBit) -> MagicCrypt {
        match bit {
            SecureBit::Bit128 => {
                let key = shake128(key.as_bytes());

                let encryptor = ecb_encryptor(KeySize::KeySize128, &key,  PkcsPadding);
                let decryptor = ecb_decryptor(KeySize::KeySize128, &key,  PkcsPadding);

                MagicCrypt {
                    encryptor,
                    decryptor,
                }
            }
            SecureBit::Bit192 => {
                let key = shake192(key.as_bytes());

                let encryptor = ecb_encryptor(KeySize::KeySize192, &key,  PkcsPadding);
                let decryptor = ecb_decryptor(KeySize::KeySize192, &key,  PkcsPadding);

                MagicCrypt {
                    encryptor,
                    decryptor,
                }
            }
            SecureBit::Bit256 => {
                let key = shake256(key.as_bytes());

                let encryptor = ecb_encryptor(KeySize::KeySize256, &key,  PkcsPadding);
                let decryptor = ecb_decryptor(KeySize::KeySize256, &key,  PkcsPadding);

                MagicCrypt {
                    encryptor,
                    decryptor,
                }
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
        let mut final_result = Vec::with_capacity(get_cipher_len!(bytes.len()));

        let mut buffer = [0u8; BUFFER_SIZE];

        let mut output = RefWriteBuffer::new(&mut buffer);

        loop {
            let result = self.encryptor.encrypt(&mut RefReadBuffer::new(bytes), &mut output, true).unwrap();

            final_result.extend(output
                .take_read_buffer()
                .take_remaining());

            if let BufferResult::BufferUnderflow = result {
                break;
            }
        }

        final_result
    }

    pub fn encrypt_reader_to_base64(&mut self, reader: &mut Read) -> Result<String, Error> {
        self.encrypt_reader_to_bytes(reader).map(|bytes| base64::encode(&bytes))
    }

    pub fn encrypt_reader_to_bytes(&mut self, reader: &mut Read) -> Result<Vec<u8>, Error> {
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

                        let result = self.encryptor.encrypt(&mut RefReadBuffer::new(&buffer1[0..c]), &mut output, false).map_err(|err| Error::CipherError(err))?;

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

    pub fn encrypt_reader_to_writer(&mut self, reader: &mut Read, writer: &mut Write) -> Result<(), Error> {
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

                        let result = self.encryptor.encrypt(&mut RefReadBuffer::new(&buffer1[0..c]), &mut output, true).map_err(|err| Error::CipherError(err))?;

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
        let mut final_result = Vec::with_capacity( bytes.len());

        let mut buffer = [0u8; BUFFER_SIZE];

        let mut output = RefWriteBuffer::new(&mut buffer);

        loop {
            let result = self.decryptor.decrypt(&mut RefReadBuffer::new(bytes), &mut output, true).unwrap();

            final_result.extend(output
                .take_read_buffer()
                .take_remaining());

            if let BufferResult::BufferUnderflow = result {
                break;
            }
        }

        Ok(final_result)
    }

    pub fn decrypt_reader_to_bytes(&mut self, reader: &mut Read) -> Result<Vec<u8>, Error> {
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

                        let result = self.decryptor.decrypt(&mut RefReadBuffer::new(&buffer1[0..c]), &mut output, false).map_err(|err| Error::CipherError(err))?;

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

    pub fn decrypt_reader_to_writer(&mut self, reader: &mut Read, writer: &mut Write) -> Result<(), Error> {
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

                        let result = self.decryptor.decrypt(&mut RefReadBuffer::new(&buffer1[0..c]), &mut output, true).map_err(|err| Error::CipherError(err))?;

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

#[macro_export]
macro_rules! new_magic_crypt {
    ( $key:expr ) => {
        {
            use self::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit128)
        }
    };
    ( $key:expr, 128 ) => {
        {
            use self::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit128)
        }
    };
    ( $key:expr, 192 ) => {
        {
            use self::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit192)
        }
    };
    ( $key:expr, 256 ) => {
        {
            use self::magic_crypt::*;

            MagicCrypt::new($key, SecureBit::Bit256)
        }
    };
}

