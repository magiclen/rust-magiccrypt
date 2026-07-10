use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::io::{ErrorKind, Read, Write};
#[cfg(feature = "std")]
use std::ptr::copy;

#[cfg(feature = "std")]
use aes::cipher::{
    array::ArraySize,
    block_padding::Padding,
    typenum::{IsGreaterOrEqual, PartialDiv, True, U16},
};
use crc_any::CRCu64;
use des::{
    Des,
    cipher::{
        BlockModeDecrypt, BlockModeEncrypt, Iv, Key, KeyIvInit, array::Array, block_padding::Pkcs7,
    },
};

#[cfg(feature = "std")]
use crate::functions::to_blocks;
use crate::{MagicCryptError, MagicCryptTrait};

type Des64CbcEnc = cbc::Encryptor<Des>;
type Des64CbcDec = cbc::Decryptor<Des>;

#[cfg(feature = "std")]
const BLOCK_SIZE: usize = 8;

/// This struct can help you encrypt or decrypt data via AES-64 in a quick way.
#[derive(Debug, Clone)]
pub struct MagicCrypt64 {
    key: Key<Des64CbcEnc>,
    iv:  Iv<Des64CbcEnc>,
}

impl MagicCryptTrait for MagicCrypt64 {
    fn new<S: AsRef<[u8]>, V: AsRef<[u8]>>(key: S, iv: Option<V>) -> MagicCrypt64 {
        let iv = match iv {
            Some(s) => {
                let mut hasher = CRCu64::crc64we();
                hasher.digest(s.as_ref());

                Array::try_from(hasher.get_crc_vec_be().as_slice()).unwrap()
            },
            None => Array::default(),
        };

        let key = {
            let mut hasher = CRCu64::crc64we();
            hasher.digest(key.as_ref());

            Array::try_from(hasher.get_crc_vec_be().as_slice()).unwrap()
        };

        MagicCrypt64 {
            key,
            iv,
        }
    }

    #[inline]
    fn encrypt_to_bytes<T: ?Sized + AsRef<[u8]>>(&self, data: &T) -> Vec<u8> {
        let data = data.as_ref();

        let cipher = Des64CbcEnc::new(&self.key, &self.iv);

        cipher.encrypt_padded_vec::<Pkcs7>(data)
    }

    #[cfg(feature = "std")]
    fn encrypt_reader_to_bytes(&self, reader: &mut dyn Read) -> Result<Vec<u8>, MagicCryptError> {
        let mut final_result = Vec::new();

        let data_length = reader.read_to_end(&mut final_result)?;

        let padding_length = BLOCK_SIZE - (data_length % BLOCK_SIZE);
        let final_length = data_length + padding_length;

        final_result.resize(final_length, 0);

        let cipher = Des64CbcEnc::new(&self.key, &self.iv);

        cipher.encrypt_padded::<Pkcs7>(&mut final_result, data_length).unwrap();

        Ok(final_result)
    }

    #[cfg(feature = "std")]
    fn encrypt_reader_to_writer2<
        N: ArraySize + PartialDiv<U16> + IsGreaterOrEqual<U16, Output = True>,
    >(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), MagicCryptError> {
        let mut buffer: Array<u8, N> = Array::default();

        let mut cipher = Des64CbcEnc::new(&self.key, &self.iv);

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

                    cipher.encrypt_blocks(to_blocks(&mut buffer[..e]));

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
        cipher.encrypt_blocks(to_blocks(raw_block));

        writer.write_all(raw_block)?;

        Ok(writer.flush()?)
    }

    #[inline]
    fn decrypt_bytes_to_bytes<T: ?Sized + AsRef<[u8]>>(
        &self,
        bytes: &T,
    ) -> Result<Vec<u8>, MagicCryptError> {
        let bytes = bytes.as_ref();

        let cipher = Des64CbcDec::new(&self.key, &self.iv);

        let final_result = cipher.decrypt_padded_vec::<Pkcs7>(bytes)?;

        Ok(final_result)
    }

    #[cfg(feature = "std")]
    fn decrypt_reader_to_bytes(&self, reader: &mut dyn Read) -> Result<Vec<u8>, MagicCryptError> {
        let mut final_result = Vec::new();

        reader.read_to_end(&mut final_result)?;

        let cipher = Des64CbcDec::new(&self.key, &self.iv);

        let data_length = cipher.decrypt_padded::<Pkcs7>(&mut final_result)?.len();

        final_result.truncate(data_length);

        Ok(final_result)
    }

    #[cfg(feature = "std")]
    #[allow(clippy::many_single_char_names)]
    fn decrypt_reader_to_writer2<
        N: ArraySize + PartialDiv<U16> + IsGreaterOrEqual<U16, Output = True>,
    >(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), MagicCryptError> {
        let mut buffer: Array<u8, N> = Array::default();
        let mut next_byte = [0];

        let mut cipher = Des64CbcDec::new(&self.key, &self.iv);
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

                    match reader.read_exact(&mut next_byte) {
                        Ok(()) => {
                            cipher.decrypt_blocks(to_blocks(&mut buffer[..e]));

                            writer.write_all(&buffer[..e])?;

                            buffer[0] = next_byte[0];

                            l = 1;
                        },
                        Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
                            cipher.decrypt_blocks(to_blocks(&mut buffer[..e]));

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
