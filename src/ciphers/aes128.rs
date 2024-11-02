use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::intrinsics::copy;
#[cfg(feature = "std")]
use std::io::{ErrorKind, Read, Write};
#[cfg(feature = "std")]
use std::ops::Add;

#[cfg(feature = "std")]
use aes::cipher::{
    block_padding::RawPadding,
    generic_array::typenum::{IsGreaterOrEqual, PartialDiv, True, B1, U16},
    ArrayLength,
};
use aes::{
    cipher::{
        block_padding::Pkcs7, generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, Iv,
        Key, KeyIvInit,
    },
    Aes128,
};
use md5::{Digest, Md5};

#[cfg(feature = "std")]
use crate::functions::to_blocks;
use crate::{MagicCryptError, MagicCryptTrait};

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;

#[cfg(feature = "std")]
const BLOCK_SIZE: usize = 16;

/// This struct can help you encrypt or decrypt data via AES-128 in a quick way.
#[derive(Debug, Clone)]
pub struct MagicCrypt128 {
    key: Key<Aes128CbcEnc>,
    iv:  Iv<Aes128CbcEnc>,
}

impl MagicCryptTrait for MagicCrypt128 {
    fn new<S: AsRef<[u8]>, V: AsRef<[u8]>>(key: S, iv: Option<V>) -> MagicCrypt128 {
        let iv = match iv {
            Some(s) => {
                let mut hasher = Md5::new();
                hasher.update(s.as_ref());

                hasher.finalize()
            },
            None => GenericArray::default(),
        };

        let key = {
            let mut hasher = Md5::new();
            hasher.update(key.as_ref());

            hasher.finalize()
        };

        MagicCrypt128 {
            key,
            iv,
        }
    }

    #[inline]
    fn encrypt_to_bytes<T: ?Sized + AsRef<[u8]>>(&self, data: &T) -> Vec<u8> {
        let data = data.as_ref();

        let cipher = Aes128CbcEnc::new(&self.key, &self.iv);

        cipher.encrypt_padded_vec_mut::<Pkcs7>(data)
    }

    #[cfg(feature = "std")]
    fn encrypt_reader_to_bytes(&self, reader: &mut dyn Read) -> Result<Vec<u8>, MagicCryptError> {
        let mut final_result = Vec::new();

        let data_length = reader.read_to_end(&mut final_result)?;

        let padding_length = BLOCK_SIZE - (data_length % BLOCK_SIZE);
        let final_length = data_length + padding_length;

        final_result.reserve_exact(padding_length);

        unsafe {
            final_result.set_len(final_length);
        }

        let cipher = Aes128CbcEnc::new(&self.key, &self.iv);

        cipher.encrypt_padded_mut::<Pkcs7>(&mut final_result, data_length).unwrap();

        Ok(final_result)
    }

    #[cfg(feature = "std")]
    fn encrypt_reader_to_writer2<
        N: ArrayLength<u8> + PartialDiv<U16> + IsGreaterOrEqual<U16, Output = True>,
    >(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), MagicCryptError> {
        let mut buffer: GenericArray<u8, N> = GenericArray::default();

        let mut cipher = Aes128CbcEnc::new(&self.key, &self.iv);

        let mut l = 0;

        loop {
            match reader.read(&mut buffer[l..]) {
                Ok(c) => {
                    if c == 0 {
                        break;
                    }

                    l += c;

                    if l < BLOCK_SIZE {
                        continue;
                    }

                    let r = l % BLOCK_SIZE;
                    let e = l - r;

                    cipher.encrypt_blocks_mut(to_blocks(&mut buffer[..e]));

                    writer.write_all(&buffer[..e])?;

                    unsafe {
                        copy(buffer.as_ptr().add(e), buffer.as_mut_ptr(), r);
                    }

                    l = r;
                },
                Err(error) if error.kind() == ErrorKind::Interrupted => {},
                Err(error) => return Err(MagicCryptError::IOError(error)),
            }
        }

        let raw_block = &mut buffer[..BLOCK_SIZE];

        Pkcs7::raw_pad(raw_block, l);
        cipher.encrypt_blocks_mut(to_blocks(raw_block));

        writer.write_all(raw_block)?;

        Ok(writer.flush()?)
    }

    #[inline]
    fn decrypt_bytes_to_bytes<T: ?Sized + AsRef<[u8]>>(
        &self,
        bytes: &T,
    ) -> Result<Vec<u8>, MagicCryptError> {
        let bytes = bytes.as_ref();

        let cipher = Aes128CbcDec::new(&self.key, &self.iv);

        let final_result = cipher.decrypt_padded_vec_mut::<Pkcs7>(bytes)?;

        Ok(final_result)
    }

    #[cfg(feature = "std")]
    fn decrypt_reader_to_bytes(&self, reader: &mut dyn Read) -> Result<Vec<u8>, MagicCryptError> {
        let mut final_result = Vec::new();

        reader.read_to_end(&mut final_result)?;

        let cipher = Aes128CbcDec::new(&self.key, &self.iv);

        let data_length = cipher.decrypt_padded_mut::<Pkcs7>(&mut final_result)?.len();

        final_result.truncate(data_length);

        Ok(final_result)
    }

    #[cfg(feature = "std")]
    #[allow(clippy::many_single_char_names)]
    fn decrypt_reader_to_writer2<
        N: ArrayLength<u8> + PartialDiv<U16> + IsGreaterOrEqual<U16, Output = True> + Add<B1>,
    >(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), MagicCryptError>
    where
        <N as Add<B1>>::Output: ArrayLength<u8>, {
        let mut buffer: GenericArray<u8, N> = GenericArray::default();

        let mut cipher = Aes128CbcDec::new(&self.key, &self.iv);
        let mut l = 0;

        loop {
            match reader.read(&mut buffer[l..]) {
                Ok(c) => {
                    if c == 0 {
                        break;
                    }

                    l += c;

                    if l < BLOCK_SIZE {
                        continue;
                    }

                    let r = l % BLOCK_SIZE;
                    let e = if r > 0 { l + BLOCK_SIZE - r } else { l };

                    // fill the last block
                    reader.read_exact(&mut buffer[l..e])?;

                    match reader.read_exact(&mut buffer[e..(e + 1)]) {
                        Ok(()) => {
                            cipher.decrypt_blocks_mut(to_blocks(&mut buffer[..e]));

                            writer.write_all(&buffer[..e])?;

                            buffer[0] = buffer[e];

                            l = 1;
                        },
                        Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
                            cipher.decrypt_blocks_mut(to_blocks(&mut buffer[..e]));

                            writer.write_all(Pkcs7::raw_unpad(&buffer[..e])?)?;

                            break;
                        },
                        Err(error) => return Err(MagicCryptError::IOError(error)),
                    }
                },
                Err(error) if error.kind() == ErrorKind::Interrupted => {},
                Err(error) => return Err(MagicCryptError::IOError(error)),
            }
        }

        Ok(writer.flush()?)
    }
}
