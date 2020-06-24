#[cfg(feature = "std")]
use digest::generic_array::{ArrayLength, GenericArray};

#[cfg(feature = "std")]
#[inline]
pub(crate) fn to_blocks<N>(data: &mut [u8]) -> &mut [GenericArray<u8, N>]
where
    N: ArrayLength<u8>, {
    let n = N::to_usize();

    unsafe {
        core::slice::from_raw_parts_mut(data.as_ptr() as *mut GenericArray<u8, N>, data.len() / n)
    }
}

#[inline]
pub(crate) fn get_aes_cipher_len(data_length: usize) -> usize {
    (data_length + 16) & !0xF
}

#[inline]
pub(crate) fn get_des_cipher_len(data_length: usize) -> usize {
    (data_length + 8) & !0b111
}
