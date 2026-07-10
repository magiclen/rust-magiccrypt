use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::io::{Read, Write};

#[cfg(feature = "std")]
use aes::cipher::{
    array::ArraySize,
    typenum::{IsGreaterOrEqual, PartialDiv, True, U16},
};
use aes::{
    Aes192,
    cipher::{
        BlockModeDecrypt, BlockModeEncrypt, Iv, Key, KeyIvInit, array::Array, block_padding::Pkcs7,
    },
};
use md5::{Digest, Md5};
use tiger::Tiger;

#[cfg(feature = "std")]
use crate::functions::{
    decrypt_reader_to_writer as decrypt_stream, encrypt_reader_to_writer as encrypt_stream,
    to_blocks,
};
use crate::{MagicCryptError, MagicCryptTrait};

type Aes192CbcEnc = cbc::Encryptor<Aes192>;
type Aes192CbcDec = cbc::Decryptor<Aes192>;

#[cfg(feature = "std")]
const BLOCK_SIZE: usize = 16;

/// This struct can help you encrypt or decrypt data via AES-192 in a quick way.
#[derive(Clone)]
pub struct MagicCrypt192 {
    key: Key<Aes192CbcEnc>,
    iv:  Iv<Aes192CbcEnc>,
}

impl_cipher_secret_traits!(MagicCrypt192);

impl MagicCryptTrait for MagicCrypt192 {
    fn new<S: AsRef<[u8]>, V: AsRef<[u8]>>(key: S, iv: Option<V>) -> MagicCrypt192 {
        let iv = match iv {
            Some(s) => {
                let mut hasher = Md5::new();
                hasher.update(s.as_ref());

                hasher.finalize()
            },
            None => Array::default(),
        };

        let key = {
            let mut hasher = Tiger::default();
            hasher.update(key.as_ref());

            hasher.finalize()
        };

        MagicCrypt192 {
            key,
            iv,
        }
    }

    #[inline]
    fn encrypt_to_bytes<T: ?Sized + AsRef<[u8]>>(&self, data: &T) -> Vec<u8> {
        let data = data.as_ref();

        let cipher = Aes192CbcEnc::new(&self.key, &self.iv);

        cipher.encrypt_padded_vec::<Pkcs7>(data)
    }

    #[cfg(feature = "std")]
    fn encrypt_reader_to_bytes(&self, reader: &mut dyn Read) -> Result<Vec<u8>, MagicCryptError> {
        use aes::cipher::block_padding::NoPadding;

        let mut final_result = Vec::new();

        let data_length = reader.read_to_end(&mut final_result)?;

        let padding_length = BLOCK_SIZE - (data_length % BLOCK_SIZE);
        let final_length = data_length + padding_length;

        // PKCS7 padding requires that the padding bytes be equal to the number of padding bytes added.
        let padding_byte = padding_length as u8;

        final_result.resize(final_length, padding_byte);

        let cipher = Aes192CbcEnc::new(&self.key, &self.iv);

        cipher.encrypt_padded::<NoPadding>(&mut final_result, final_length).unwrap();

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
        let mut cipher = Aes192CbcEnc::new(&self.key, &self.iv);

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

        let cipher = Aes192CbcDec::new(&self.key, &self.iv);

        let final_result = cipher.decrypt_padded_vec::<Pkcs7>(bytes)?;

        Ok(final_result)
    }

    #[cfg(feature = "std")]
    fn decrypt_reader_to_bytes(&self, reader: &mut dyn Read) -> Result<Vec<u8>, MagicCryptError> {
        let mut final_result = Vec::new();

        reader.read_to_end(&mut final_result)?;

        let cipher = Aes192CbcDec::new(&self.key, &self.iv);

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
        let mut cipher = Aes192CbcDec::new(&self.key, &self.iv);

        decrypt_stream::<N>(reader, writer, BLOCK_SIZE, |buffer| {
            cipher.decrypt_blocks(to_blocks(buffer));
        })
    }
}
