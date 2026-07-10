#[cfg(feature = "std")]
use cbc::cipher::array::{Array, ArraySize};

#[cfg(feature = "std")]
#[inline]
pub(crate) fn to_blocks<N>(data: &mut [u8]) -> &mut [Array<u8, N>]
where
    N: ArraySize, {
    let (blocks, remainder) = Array::slice_as_chunks_mut(data);

    debug_assert!(remainder.is_empty());

    blocks
}
