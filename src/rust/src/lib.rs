//! CTIDH-1024, binding the highctidh C library that the Go `ctidh1024`
//! package uses, with Go's key and secret encodings.
//!
//! A public key is the 128-byte Montgomery coefficient of a supersingular
//! curve, as sixteen little-endian 64-bit limbs; a private key is the 130
//! signed exponents, one byte each. The shared secret is the public key the
//! group action reaches, so it is 128 bytes too.

use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

mod ffi;

use ffi::{RawPrivateKey, RawPublicKey};

pub const PUBLIC_KEY_SIZE: usize = 128;
pub const PRIVATE_KEY_SIZE: usize = 130;
pub const SHARED_SECRET_SIZE: usize = PUBLIC_KEY_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidLength {
        expected: usize,
        actual: usize,
    },
    InvalidKey,
    /// The group action reached the base curve, the all-zero secret.
    LowOrderPoint,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidLength { expected, actual } => {
                write!(f, "invalid length: expected {expected}, got {actual}")
            }
            Error::InvalidKey => f.write_str("invalid key"),
            Error::LowOrderPoint => f.write_str("low order point"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn check_len(bytes: &[u8], expected: usize) -> Result<()> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(Error::InvalidLength {
            expected,
            actual: bytes.len(),
        })
    }
}

fn ct_is_zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0, |acc, b| acc | b).ct_eq(&0).into()
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(RawPublicKey);

impl PublicKey {
    /// Accepts only a valid supersingular curve other than the base curve,
    /// as Go does.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        check_len(bytes, PUBLIC_KEY_SIZE)?;
        let mut raw = RawPublicKey::default();
        for (limb, chunk) in raw.0.iter_mut().zip(bytes.as_chunks::<8>().0) {
            *limb = u64::from_le_bytes(*chunk);
        }
        if ct_is_zero(bytes) || !ffi::validate(&raw) {
            return Err(Error::InvalidKey);
        }
        Ok(Self(raw))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0
            .0
            .iter()
            .flat_map(|limb| limb.to_le_bytes())
            .collect()
    }

    /// The group action of `factor` on this curve, which hpqc's NIKE calls
    /// blinding.
    pub fn blind(&self, factor: &PrivateKey) -> Result<PublicKey> {
        ffi::group_action(&factor.0, &self.0)
            .map(PublicKey)
            .ok_or(Error::InvalidKey)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix: String = self.to_bytes()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        f.debug_tuple("ctidh1024::PublicKey")
            .field(&prefix)
            .finish()
    }
}

/// Zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey(RawPrivateKey);

impl PrivateKey {
    /// Draws the exponents from `rng` the way highctidh's
    /// `csidh_private_withrng_bytes` does, so the same random bytes give the
    /// same key as Go's `GenerateKeyPairFromEntropy`.
    pub fn generate(rng: &mut dyn CryptoRng) -> Self {
        Self(ffi::private_withrng(rng))
    }

    /// Rejects exponents outside the key space.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        check_len(bytes, PRIVATE_KEY_SIZE)?;
        let mut raw = RawPrivateKey([0; PRIVATE_KEY_SIZE]);
        for (e, b) in raw.0.iter_mut().zip(bytes) {
            *e = *b as i8;
        }
        let key = Self(raw);
        if !ffi::private_valid(&key.0) {
            return Err(Error::InvalidKey);
        }
        Ok(key)
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.0.iter().map(|&e| e as u8).collect())
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(
            ffi::group_action(&self.0, &RawPublicKey::default()).expect("the base curve is valid"),
        )
    }

    /// The group action on `public_key`, encoded as a public key, as Go's
    /// `DeriveSecret` returns it.
    pub fn shared_secret(&self, public_key: &PublicKey) -> Result<Zeroizing<Vec<u8>>> {
        let curve = ffi::group_action(&self.0, &public_key.0).ok_or(Error::InvalidKey)?;
        let secret = Zeroizing::new(PublicKey(curve).to_bytes());
        if ct_is_zero(&secret) {
            return Err(Error::LowOrderPoint);
        }
        Ok(secret)
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ctidh1024::PrivateKey")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_agreement() {
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let alice = PrivateKey::generate(&mut rng);
        let bob = PrivateKey::generate(&mut rng);
        let alice_pk = PublicKey::from_bytes(&alice.public_key().to_bytes()).unwrap();
        let bob_pk = PublicKey::from_bytes(&bob.public_key().to_bytes()).unwrap();
        assert_eq!(
            *PrivateKey::from_bytes(&alice.to_bytes())
                .unwrap()
                .to_bytes(),
            *alice.to_bytes()
        );
        assert_eq!(
            *alice.shared_secret(&bob_pk).unwrap(),
            *bob.shared_secret(&alice_pk).unwrap()
        );
    }

    #[test]
    fn rejects_base_curve_and_invalid_keys() {
        assert_eq!(PublicKey::from_bytes(&[0; 128]), Err(Error::InvalidKey));
        assert_eq!(PublicKey::from_bytes(&[1; 128]), Err(Error::InvalidKey));
        assert_eq!(
            PublicKey::from_bytes(&[0; 127]),
            Err(Error::InvalidLength {
                expected: 128,
                actual: 127
            })
        );
        assert!(matches!(
            PrivateKey::from_bytes(&[127; 130]),
            Err(Error::InvalidKey)
        ));
    }
}
