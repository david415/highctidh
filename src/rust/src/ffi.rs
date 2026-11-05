//! The raw highctidh CTIDH-1024 functions and their C layouts.

use std::ffi::c_void;

use rand_core::CryptoRng;
use zeroize::Zeroize;

use crate::{PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE};

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RawPublicKey(pub(crate) [u64; PUBLIC_KEY_SIZE / 8]);

#[repr(C)]
#[derive(Clone, Zeroize)]
pub(crate) struct RawPrivateKey(pub(crate) [i8; PRIVATE_KEY_SIZE]);

type FillRandom = extern "C" fn(out: *mut c_void, len: usize, ctx: usize);

unsafe extern "C" {
    fn highctidh_1024_csidh(
        out: *mut RawPublicKey,
        input: *const RawPublicKey,
        private_key: *const RawPrivateKey,
    ) -> bool;
    fn highctidh_1024_validate(input: *const RawPublicKey) -> bool;
    fn highctidh_1024_csidh_private_valid(private_key: *const RawPrivateKey) -> bool;
    fn highctidh_1024_csidh_private_withrng_bytes(
        private_key: *mut RawPrivateKey,
        ctx: usize,
        fill: FillRandom,
    );
}

extern "C" fn fill_from_rng(out: *mut c_void, len: usize, ctx: usize) {
    // SAFETY: `ctx` is the `&mut &mut dyn CryptoRng` that `private_withrng`
    // passes, alive for the whole call, and `out` points to `len` bytes.
    let (rng, out) = unsafe {
        (
            &mut *(ctx as *mut &mut dyn CryptoRng),
            std::slice::from_raw_parts_mut(out.cast::<u8>(), len),
        )
    };
    rng.fill_bytes(out);
}

/// The group action: `private_key` applied to the curve `input`, or `None`
/// when `input` is not a valid curve.
pub(crate) fn group_action(
    private_key: &RawPrivateKey,
    input: &RawPublicKey,
) -> Option<RawPublicKey> {
    let mut out = RawPublicKey::default();
    // SAFETY: all three point to initialized structs of the C layout.
    unsafe { highctidh_1024_csidh(&mut out, input, private_key) }.then_some(out)
}

pub(crate) fn validate(input: &RawPublicKey) -> bool {
    // SAFETY: `input` is an initialized public key.
    unsafe { highctidh_1024_validate(input) }
}

pub(crate) fn private_valid(private_key: &RawPrivateKey) -> bool {
    // SAFETY: `private_key` is an initialized private key.
    unsafe { highctidh_1024_csidh_private_valid(private_key) }
}

pub(crate) fn private_withrng(mut rng: &mut dyn CryptoRng) -> RawPrivateKey {
    let mut raw = RawPrivateKey([0; PRIVATE_KEY_SIZE]);
    let ctx = &mut rng as *mut &mut dyn CryptoRng as usize;
    // SAFETY: `fill_from_rng` reads `ctx` back as the pointer it is.
    unsafe { highctidh_1024_csidh_private_withrng_bytes(&mut raw, ctx, fill_from_rng) };
    raw
}
