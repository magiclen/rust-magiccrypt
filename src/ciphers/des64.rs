use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::io::{Read, Write};

#[cfg(feature = "std")]
use aes::cipher::{
    array::ArraySize,
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
use crate::functions::{
    decrypt_reader_to_writer as decrypt_stream, encrypt_reader_to_writer as encrypt_stream,
    to_blocks,
};
use crate::{MagicCryptError, MagicCryptTrait};

type Des64CbcEnc = cbc::Encryptor<Des>;
type Des64CbcDec = cbc::Decryptor<Des>;

#[cfg(feature = "std")]
const BLOCK_SIZE: usize = 8;

/// This struct can help you encrypt or decrypt data via DES in a quick way.
#[derive(Clone)]
pub struct MagicCrypt64 {
    key: Key<Des64CbcEnc>,
    iv:  Iv<Des64CbcEnc>,
}

impl_cipher_secret_traits!(MagicCrypt64);

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
        let mut cipher = Des64CbcEnc::new(&self.key, &self.iv);

        encrypt_stream::<N>(reader, writer, BLOCK_SIZE, |buffer| {
            cipher.encrypt_blocks(to_blocks(buffer));
        })
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
    fn decrypt_reader_to_writer2<
        N: ArraySize + PartialDiv<U16> + IsGreaterOrEqual<U16, Output = True>,
    >(
        &self,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<(), MagicCryptError> {
        let mut cipher = Des64CbcDec::new(&self.key, &self.iv);

        decrypt_stream::<N>(reader, writer, BLOCK_SIZE, |buffer| {
            cipher.decrypt_blocks(to_blocks(buffer));
        })
    }
}
