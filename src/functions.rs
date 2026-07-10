#[cfg(feature = "std")]
use std::{
    io::{ErrorKind, IoSlice, Read, Write},
    ptr::copy,
};

#[cfg(feature = "std")]
use cbc::cipher::{
    array::{Array, ArraySize},
    block_padding::{Error as PaddingError, Padding, Pkcs7},
};

#[cfg(feature = "std")]
use crate::MagicCryptError;

#[cfg(feature = "std")]
const MAX_BLOCK_SIZE: usize = 16;

#[cfg(feature = "std")]
#[inline]
unsafe fn move_remaining<N: ArraySize>(buffer: &mut Array<u8, N>, start: usize, length: usize) {
    // SAFETY: The stream helpers ensure that the source and destination ranges stay within the same buffer.
    unsafe {
        copy(buffer.as_ptr().add(start), buffer.as_mut_ptr(), length);
    }
}

#[cfg(feature = "std")]
#[inline]
fn write_all_pair(
    writer: &mut dyn Write,
    first: &[u8],
    second: &[u8],
) -> Result<(), MagicCryptError> {
    if first.is_empty() {
        return Ok(writer.write_all(second)?);
    }

    if second.is_empty() {
        return Ok(writer.write_all(first)?);
    }

    let total_length = first.len() + second.len();
    let mut written_length = 0;

    while written_length < total_length {
        let result = if written_length < first.len() {
            writer.write_vectored(&[IoSlice::new(&first[written_length..]), IoSlice::new(second)])
        } else {
            writer.write(&second[(written_length - first.len())..])
        };

        match result {
            Ok(0) => {
                return Err(MagicCryptError::IOError(std::io::Error::new(
                    ErrorKind::WriteZero,
                    "failed to write the buffered data",
                )));
            },
            Ok(count) => written_length += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {},
            Err(error) => return Err(MagicCryptError::IOError(error)),
        }
    }

    Ok(())
}

#[cfg(feature = "std")]
pub(crate) fn encrypt_reader_to_writer<N: ArraySize>(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    block_size: usize,
    mut encrypt_blocks: impl FnMut(&mut [u8]),
) -> Result<(), MagicCryptError> {
    let mut buffer: Array<u8, N> = Array::default();
    let mut length = 0;

    loop {
        match reader.read(&mut buffer[length..]) {
            Ok(count) => {
                if count == 0 {
                    break;
                }

                length += count;

                if length < block_size {
                    continue;
                }

                let remaining_length = length % block_size;
                let encrypted_length = length - remaining_length;

                encrypt_blocks(&mut buffer[..encrypted_length]);
                writer.write_all(&buffer[..encrypted_length])?;

                unsafe {
                    move_remaining(&mut buffer, encrypted_length, remaining_length);
                }

                length = remaining_length;
            },
            Err(error) if error.kind() == ErrorKind::Interrupted => {},
            Err(error) => return Err(MagicCryptError::IOError(error)),
        }
    }

    let raw_block = &mut buffer[..block_size];

    Pkcs7::raw_pad(raw_block, length);
    encrypt_blocks(raw_block);

    writer.write_all(raw_block)?;

    Ok(writer.flush()?)
}

#[cfg(feature = "std")]
pub(crate) fn decrypt_reader_to_writer<N: ArraySize>(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    block_size: usize,
    mut decrypt_blocks: impl FnMut(&mut [u8]),
) -> Result<(), MagicCryptError> {
    debug_assert!(block_size <= MAX_BLOCK_SIZE);

    let mut buffer: Array<u8, N> = Array::default();
    let mut pending_block = [0; MAX_BLOCK_SIZE];
    let mut has_pending_block = false;
    let mut length = 0;

    loop {
        match reader.read(&mut buffer[length..]) {
            Ok(count) => {
                if count == 0 {
                    if length != 0 || !has_pending_block {
                        return Err(PaddingError.into());
                    }

                    let pending_block = &mut pending_block[..block_size];

                    decrypt_blocks(pending_block);
                    writer.write_all(Pkcs7::raw_unpad(pending_block)?)?;

                    return Ok(writer.flush()?);
                }

                length += count;

                if length < block_size {
                    continue;
                }

                let remaining_length = length % block_size;
                let complete_length = length - remaining_length;
                let last_block_start = complete_length - block_size;

                if has_pending_block {
                    decrypt_blocks(&mut pending_block[..block_size]);
                }

                if last_block_start > 0 {
                    decrypt_blocks(&mut buffer[..last_block_start]);
                }

                write_all_pair(
                    writer,
                    if has_pending_block { &pending_block[..block_size] } else { &[] },
                    &buffer[..last_block_start],
                )?;

                pending_block[..block_size]
                    .copy_from_slice(&buffer[last_block_start..complete_length]);
                has_pending_block = true;

                unsafe {
                    move_remaining(&mut buffer, complete_length, remaining_length);
                }

                length = remaining_length;
            },
            Err(error) if error.kind() == ErrorKind::Interrupted => {},
            Err(error) => return Err(MagicCryptError::IOError(error)),
        }
    }
}

#[cfg(feature = "std")]
#[inline]
pub(crate) fn to_blocks<N>(data: &mut [u8]) -> &mut [Array<u8, N>]
where
    N: ArraySize, {
    let (blocks, remainder) = Array::slice_as_chunks_mut(data);

    debug_assert!(remainder.is_empty());

    blocks
}
