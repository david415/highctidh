//! CTIDH bindings to the highctidh C library, one module per field size,
//! with the API and encodings of the Go packages `ctidh511`, `ctidh512`,
//! `ctidh1024` and `ctidh2048`.
//!
//! A public key is the Montgomery coefficient of a supersingular curve as
//! little-endian 64-bit limbs; a private key is one signed exponent byte per
//! prime. The shared secret is the public key the group action reaches.

use std::ffi::c_void;

use base64::Engine as Base64Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand_core::CryptoRng;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    PublicKeyValidation,
    PublicKeySize,
    PrivateKeySize,
    PrivateKeyRange,
    InvalidBase64,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::PublicKeyValidation => "public key validation failure",
            Error::PublicKeySize => "raw public key data size is wrong",
            Error::PrivateKeySize => "raw private key data size is wrong",
            Error::PrivateKeyRange => "private key exceeds a batch bound",
            Error::InvalidBase64 => "invalid base64",
        })
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

type FillRandom = extern "C" fn(out: *mut c_void, len: usize, ctx: usize);

extern "C" fn fill_from_rng(out: *mut c_void, len: usize, ctx: usize) {
    // SAFETY: `ctx` is the `&mut &mut dyn CryptoRng` that `with_rng` passes,
    // alive for the whole call, and `out` points to `len` bytes.
    let (rng, out) = unsafe {
        (
            &mut *(ctx as *mut &mut dyn CryptoRng),
            std::slice::from_raw_parts_mut(out.cast::<u8>(), len),
        )
    };
    rng.fill_bytes(out);
}

/// Calls `f` with the context and callback highctidh's `_withrng` functions
/// take to read from `rng`.
fn with_rng(mut rng: &mut dyn CryptoRng, f: impl FnOnce(usize, FillRandom)) {
    f(&mut rng as *mut &mut dyn CryptoRng as usize, fill_from_rng);
}

fn decode_base64(data: &[u8]) -> Result<Vec<u8>> {
    BASE64.decode(data).map_err(|_| Error::InvalidBase64)
}

macro_rules! ctidh {
    ($name:ident, $bits:literal, $public_key_size:literal, $private_key_size:literal) => {
        #[doc = concat!("CTIDH-", $bits, ", as Go's `", stringify!($name), "` package.")]
        pub mod $name {
            use subtle::ConstantTimeEq;
            use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

            use crate::{BASE64, Base64Engine, Error, FillRandom, Result};

            pub const PUBLIC_KEY_SIZE: usize = $public_key_size;
            pub const PRIVATE_KEY_SIZE: usize = $private_key_size;

            #[repr(C)]
            #[derive(Clone, Copy, Default)]
            struct RawPublicKey([u64; PUBLIC_KEY_SIZE / 8]);

            #[repr(C)]
            #[derive(Clone, Zeroize)]
            struct RawPrivateKey([i8; PRIVATE_KEY_SIZE]);

            unsafe extern "C" {
                #[link_name = concat!("highctidh_", $bits, "_csidh")]
                fn csidh(
                    out: *mut RawPublicKey,
                    input: *const RawPublicKey,
                    private_key: *const RawPrivateKey,
                ) -> bool;
                #[link_name = concat!("highctidh_", $bits, "_validate")]
                fn validate(input: *const RawPublicKey) -> bool;
                #[link_name = concat!("highctidh_", $bits, "_csidh_private")]
                fn csidh_private(private_key: *mut RawPrivateKey);
                #[link_name = concat!("highctidh_", $bits, "_csidh_private_valid")]
                fn csidh_private_valid(private_key: *const RawPrivateKey) -> bool;
                #[link_name = concat!("highctidh_", $bits, "_csidh_private_withrng_bytes")]
                fn csidh_private_withrng_bytes(
                    private_key: *mut RawPrivateKey,
                    ctx: usize,
                    fill: FillRandom,
                );
            }

            pub fn name() -> &'static str {
                concat!("CTIDH-", $bits)
            }

            #[derive(Clone, Copy, Default)]
            pub struct PublicKey(RawPublicKey);

            impl PublicKey {
                /// The all-zero key, the base curve, to be loaded with
                /// `from_bytes`.
                pub fn new_empty() -> Self {
                    Self::default()
                }

                /// Panics if `key` is not a valid public key.
                pub fn new(key: &[u8]) -> Self {
                    let mut p = Self::default();
                    p.from_bytes(key).unwrap();
                    p
                }

                pub fn reset(&mut self) {
                    *self = Self::default();
                }

                pub fn bytes(&self) -> Vec<u8> {
                    self.0
                        .0
                        .iter()
                        .flat_map(|limb| limb.to_le_bytes())
                        .collect()
                }

                /// Accepts only a valid supersingular curve other than the
                /// base curve.
                pub fn from_bytes(&mut self, data: &[u8]) -> Result<()> {
                    if data.len() != PUBLIC_KEY_SIZE {
                        return Err(Error::PublicKeySize);
                    }
                    let mut raw = RawPublicKey::default();
                    for (limb, chunk) in raw.0.iter_mut().zip(data.chunks_exact(8)) {
                        *limb = u64::from_le_bytes(chunk.try_into().unwrap());
                    }
                    // SAFETY: `raw` is an initialized public key.
                    if raw.0 == [0; PUBLIC_KEY_SIZE / 8] || !unsafe { validate(&raw) } {
                        return Err(Error::PublicKeyValidation);
                    }
                    self.0 = raw;
                    Ok(())
                }

                /// Constant time.
                pub fn equal(&self, other: &PublicKey) -> bool {
                    self.bytes().ct_eq(&other.bytes()).into()
                }

                /// Replaces this key with the group action of
                /// `blinding_factor` on it.
                pub fn blind(&mut self, blinding_factor: &PrivateKey) -> Result<()> {
                    *self = blind(blinding_factor, self)?;
                    Ok(())
                }

                pub fn marshal_binary(&self) -> Result<Vec<u8>> {
                    Ok(self.bytes())
                }

                pub fn unmarshal_binary(&mut self, data: &[u8]) -> Result<()> {
                    self.from_bytes(data)
                }

                /// Standard base64 of the bytes.
                pub fn marshal_text(&self) -> Result<Vec<u8>> {
                    Ok(BASE64.encode(self.bytes()).into_bytes())
                }

                pub fn unmarshal_text(&mut self, data: &[u8]) -> Result<()> {
                    self.from_bytes(&crate::decode_base64(data)?)
                }
            }

            impl PartialEq for PublicKey {
                fn eq(&self, other: &Self) -> bool {
                    self.equal(other)
                }
            }

            impl Eq for PublicKey {}

            impl std::fmt::Display for PublicKey {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str(concat!("Ctidh", $bits, "_PublicKey"))
                }
            }

            impl std::fmt::Debug for PublicKey {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    let prefix: String = self.bytes()[..8]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    f.debug_tuple(concat!(stringify!($name), "::PublicKey"))
                        .field(&prefix)
                        .finish()
                }
            }

            /// Zeroed on drop.
            #[derive(Clone, Zeroize, ZeroizeOnDrop)]
            pub struct PrivateKey(RawPrivateKey);

            impl PrivateKey {
                /// The all-zero key, to be loaded with `from_bytes`.
                pub fn new_empty() -> Self {
                    Self(RawPrivateKey([0; PRIVATE_KEY_SIZE]))
                }

                pub fn reset(&mut self) {
                    self.0.zeroize();
                }

                pub fn bytes(&self) -> Zeroizing<Vec<u8>> {
                    Zeroizing::new(self.0.0.iter().map(|&e| e as u8).collect())
                }

                /// Rejects exponents outside the key space.
                pub fn from_bytes(&mut self, data: &[u8]) -> Result<()> {
                    if data.len() != PRIVATE_KEY_SIZE {
                        return Err(Error::PrivateKeySize);
                    }
                    let mut raw = RawPrivateKey([0; PRIVATE_KEY_SIZE]);
                    for (e, b) in raw.0.iter_mut().zip(data) {
                        *e = *b as i8;
                    }
                    // SAFETY: `raw` is an initialized private key.
                    if !unsafe { csidh_private_valid(&raw) } {
                        return Err(Error::PrivateKeyRange);
                    }
                    self.0 = raw;
                    Ok(())
                }

                /// Constant time.
                pub fn equal(&self, other: &PrivateKey) -> bool {
                    self.bytes().ct_eq(&other.bytes()).into()
                }

                pub fn public(&self) -> PublicKey {
                    derive_public_key(self)
                }

                pub fn derive_secret(&self, public_key: &PublicKey) -> Zeroizing<Vec<u8>> {
                    derive_secret(self, public_key)
                }

                pub fn marshal_binary(&self) -> Result<Zeroizing<Vec<u8>>> {
                    Ok(self.bytes())
                }

                pub fn unmarshal_binary(&mut self, data: &[u8]) -> Result<()> {
                    self.from_bytes(data)
                }

                /// Standard base64 of the bytes.
                pub fn marshal_text(&self) -> Result<Zeroizing<Vec<u8>>> {
                    Ok(Zeroizing::new(BASE64.encode(&*self.bytes()).into_bytes()))
                }

                pub fn unmarshal_text(&mut self, data: &[u8]) -> Result<()> {
                    self.from_bytes(&Zeroizing::new(crate::decode_base64(data)?))
                }
            }

            impl PartialEq for PrivateKey {
                fn eq(&self, other: &Self) -> bool {
                    self.equal(other)
                }
            }

            impl Eq for PrivateKey {}

            impl std::fmt::Display for PrivateKey {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str(concat!("Ctidh", $bits, "_PrivateKey"))
                }
            }

            impl std::fmt::Debug for PrivateKey {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.debug_struct(concat!(stringify!($name), "::PrivateKey"))
                        .finish_non_exhaustive()
                }
            }

            pub fn derive_public_key(private_key: &PrivateKey) -> PublicKey {
                group_action(private_key, &PublicKey::new_empty())
            }

            /// Draws the key from the operating system's random source.
            pub fn generate_key_pair() -> (PrivateKey, PublicKey) {
                let mut private_key = PrivateKey::new_empty();
                // SAFETY: `private_key` is an initialized private key.
                unsafe { csidh_private(&mut private_key.0) };
                let public_key = derive_public_key(&private_key);
                (private_key, public_key)
            }

            /// Draws the exponents from `rng` as highctidh's
            /// `csidh_private_withrng_bytes` does, so the same random bytes
            /// give the same key as Go's `GeneratePrivateKey`.
            pub fn generate_private_key(rng: &mut dyn rand_core::CryptoRng) -> PrivateKey {
                let mut private_key = PrivateKey::new_empty();
                crate::with_rng(rng, |ctx, fill| {
                    // SAFETY: `fill` reads `ctx` back as the pointer it is.
                    unsafe { csidh_private_withrng_bytes(&mut private_key.0, ctx, fill) }
                });
                private_key
            }

            pub fn generate_key_pair_with_rng(
                rng: &mut dyn rand_core::CryptoRng,
            ) -> (PrivateKey, PublicKey) {
                let private_key = generate_private_key(rng);
                let public_key = derive_public_key(&private_key);
                (private_key, public_key)
            }

            /// Panics if the C group action fails, as Go does; a
            /// `PublicKey` always holds a valid curve, so it does not.
            pub fn group_action(private_key: &PrivateKey, public_key: &PublicKey) -> PublicKey {
                let mut out = PublicKey::new_empty();
                // SAFETY: all three point to initialized structs of the C layout.
                let ok = unsafe { csidh(&mut out.0, &public_key.0, &private_key.0) };
                assert!(ok, "{}: group action failure", name());
                out
            }

            pub fn derive_secret(
                private_key: &PrivateKey,
                public_key: &PublicKey,
            ) -> Zeroizing<Vec<u8>> {
                Zeroizing::new(group_action(private_key, public_key).bytes())
            }

            pub fn blind(
                blinding_factor: &PrivateKey,
                public_key: &PublicKey,
            ) -> Result<PublicKey> {
                Ok(group_action(blinding_factor, public_key))
            }

            #[cfg(test)]
            mod tests {
                use super::*;

                #[test]
                fn round_trip_and_agreement() {
                    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
                    let (alice, alice_pk) = generate_key_pair_with_rng(&mut rng);
                    let (bob, bob_pk) = generate_key_pair();
                    let mut decoded = PublicKey::new_empty();
                    decoded
                        .unmarshal_text(&alice_pk.marshal_text().unwrap())
                        .unwrap();
                    assert_eq!(decoded, alice_pk);
                    assert_eq!(PublicKey::new(&bob_pk.bytes()), bob_pk);
                    let mut alice2 = PrivateKey::new_empty();
                    alice2
                        .unmarshal_text(&alice.marshal_text().unwrap())
                        .unwrap();
                    assert_eq!(alice2, alice);
                    alice2
                        .unmarshal_binary(&bob.marshal_binary().unwrap())
                        .unwrap();
                    assert_eq!(alice2, bob);
                    assert_eq!(alice.derive_secret(&bob_pk), bob.derive_secret(&alice_pk));
                    assert_eq!(alice.public(), alice_pk);

                    let factor = generate_private_key(&mut rng);
                    let mut blinded = alice_pk;
                    blinded.blind(&factor).unwrap();
                    assert_eq!(blinded, group_action(&alice, &factor.public()));

                    blinded.reset();
                    assert_eq!(blinded, PublicKey::new_empty());
                    alice2.reset();
                    assert_eq!(alice2, PrivateKey::new_empty());
                    assert_eq!(alice2.public(), PublicKey::new_empty());
                }

                #[test]
                fn rejects_invalid_keys() {
                    let mut pk = PublicKey::new_empty();
                    assert_eq!(
                        pk.from_bytes(&[0; PUBLIC_KEY_SIZE]),
                        Err(Error::PublicKeyValidation)
                    );
                    assert_eq!(
                        pk.from_bytes(&[1; PUBLIC_KEY_SIZE]),
                        Err(Error::PublicKeyValidation)
                    );
                    assert_eq!(
                        pk.from_bytes(&[0; PUBLIC_KEY_SIZE - 1]),
                        Err(Error::PublicKeySize)
                    );
                    assert_eq!(pk.unmarshal_text(b"!"), Err(Error::InvalidBase64));
                    let mut sk = PrivateKey::new_empty();
                    assert_eq!(
                        sk.from_bytes(&[127; PRIVATE_KEY_SIZE]),
                        Err(Error::PrivateKeyRange)
                    );
                    assert_eq!(
                        sk.from_bytes(&[0; PRIVATE_KEY_SIZE + 1]),
                        Err(Error::PrivateKeySize)
                    );
                    assert_eq!(pk.to_string(), concat!("Ctidh", $bits, "_PublicKey"));
                    assert_eq!(sk.to_string(), concat!("Ctidh", $bits, "_PrivateKey"));
                    assert_eq!(name(), concat!("CTIDH-", $bits));
                }
            }
        }
    };
}

ctidh!(ctidh511, 511, 64, 74);
ctidh!(ctidh512, 512, 64, 74);
ctidh!(ctidh1024, 1024, 128, 130);
ctidh!(ctidh2048, 2048, 256, 231);
