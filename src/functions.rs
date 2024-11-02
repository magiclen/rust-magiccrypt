#[cfg(feature = "std")]
use cbc::cipher::{generic_array::GenericArray, ArrayLength};

#[cfg(feature = "std")]
#[inline]
pub(crate) fn to_blocks<N>(data: &mut [u8]) -> &mut [GenericArray<u8, N>]
where
    N: ArrayLength<u8>, {
    let n = N::USIZE;

    unsafe {
        core::slice::from_raw_parts_mut(data.as_ptr() as *mut GenericArray<u8, N>, data.len() / n)
    }
}
