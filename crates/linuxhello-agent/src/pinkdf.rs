//! Stretching a PIN before it reaches the TPM (ADR-0021, decision 2, and its amendment of
//! 2026-11-19 for the parameters).
//!
//! In plain words: a PIN is short, and whatever sits between the Agent and the TPM (a bus trace of
//! TPM commands, a captured command) should not see it, or be able to guess it quickly. So the PIN
//! is never given to the TPM as it is typed. It is first normalised, so that the same PIN typed on
//! two keyboards is the same bytes, and then run through a deliberately slow function, Argon2id,
//! together with a random salt that belongs to the user. What comes out is 32 bytes, and that value
//! is what the TPM is given as the authorisation of the user's root key.
//!
//! Normalisation is Unicode NFKC: a PIN typed with full-width digits is the same as one typed with
//! ordinary digits. The normalised text is kept in a fixed buffer that is wiped on drop and never
//! grows (growing would leave a copy of the PIN behind in freed memory); a PIN whose normal form
//! does not fit is refused. [`Stretched`] has no `Debug`, so it cannot be printed by accident.
//!
//! The parameters travel with the record they were used for ([`Params`]), so they can be raised
//! later without breaking an existing key: a user's root key is created with the parameters in the
//! record, and the next PIN change may write stronger ones.
//!
//! Security property: `pin_buffers_are_cleared_after_use` (the buffers) and the tests of this module.
//!
//! C4 component: `pinManager` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

/// The bytes of the salt: random, one per user, kept with the user's root-key record.
pub const SALT_BYTES: usize = 16;

/// The bytes of the result: the length of a SHA-256 digest, the largest authorisation value a TPM
/// accepts for a key whose name algorithm is SHA-256.
pub const OUTPUT_BYTES: usize = 32;

/// The most bytes a normalised PIN may take. A PIN is at most 256 bytes
/// ([`crate::pinsocket::MAX_PIN_BYTES`]); NFKC can lengthen it, and one character can become many.
const NORMALISED_BYTES: usize = 4096;

/// The cost of stretching: Argon2id's memory in kibibytes, passes and lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Passes over the memory.
    pub passes: u32,
    /// Lanes (parallelism).
    pub lanes: u32,
}

impl Params {
    /// The parameters of ADR-0021's amendment: 64 MiB, 3 passes, 1 lane. The cost on a laptop
    /// is about a tenth of a second (measured in the pull request that added this module).
    pub const DEFAULT: Self = Self {
        memory_kib: 64 * 1024,
        passes: 3,
        lanes: 1,
    };

    /// The weakest parameters that are accepted at all: below these a record is refused rather
    /// than trusted, so that a damaged or forged record cannot make the stretching trivial.
    pub const MINIMUM: Self = Self {
        memory_kib: 16 * 1024,
        passes: 2,
        lanes: 1,
    };

    /// The most that is accepted: above these a record is refused too, so that a forged record
    /// cannot make the Agent allocate gigabytes or compute for minutes.
    pub const MAXIMUM: Self = Self {
        memory_kib: 1024 * 1024,
        passes: 16,
        lanes: 8,
    };

    /// Whether the parameters are between [`Params::MINIMUM`] and [`Params::MAXIMUM`].
    pub fn acceptable(&self) -> bool {
        let (min, max) = (Self::MINIMUM, Self::MAXIMUM);
        (min.memory_kib..=max.memory_kib).contains(&self.memory_kib)
            && (min.passes..=max.passes).contains(&self.passes)
            && (min.lanes..=max.lanes).contains(&self.lanes)
    }
}

/// Why a PIN could not be stretched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfError {
    /// The PIN is empty or not text (UTF-8).
    NotText,
    /// The normal form of the PIN does not fit the buffer.
    TooLong,
    /// The parameters are outside [`Params::MINIMUM`] and [`Params::MAXIMUM`].
    BadParams,
    /// Argon2 refused the input or could not allocate its memory.
    Failed,
}

/// The stretched PIN: what the TPM is given as an authorisation value. It is wiped on drop and
/// has no `Debug`.
pub struct Stretched(Zeroizing<[u8; OUTPUT_BYTES]>);

impl Stretched {
    /// The 32 bytes.
    pub fn as_bytes(&self) -> &[u8; OUTPUT_BYTES] {
        &self.0
    }
}

/// The NFKC normal form of `pin`, in a buffer that is wiped on drop and never grows; the number of
/// bytes in use.
fn normalise(pin: &[u8]) -> Result<(Zeroizing<[u8; NORMALISED_BYTES]>, usize), KdfError> {
    let text = std::str::from_utf8(pin).map_err(|_| KdfError::NotText)?;
    if text.is_empty() {
        return Err(KdfError::NotText);
    }
    let mut buffer = Zeroizing::new([0_u8; NORMALISED_BYTES]);
    let mut used = 0;
    for c in text.nfkc() {
        let width = c.len_utf8();
        if used + width > NORMALISED_BYTES {
            return Err(KdfError::TooLong);
        }
        c.encode_utf8(&mut buffer[used..used + width]);
        used += width;
    }
    Ok((buffer, used))
}

/// Stretches `pin` with `salt` and `params`: NFKC, then Argon2id, 32 bytes out.
///
/// # Errors
///
/// [`KdfError`] for a PIN that is empty, not text or too long, parameters outside the accepted
/// range, or an Argon2 failure.
pub fn stretch(
    pin: &[u8],
    salt: &[u8; SALT_BYTES],
    params: &Params,
) -> Result<Stretched, KdfError> {
    if !params.acceptable() {
        return Err(KdfError::BadParams);
    }
    let (normalised, used) = normalise(pin)?;
    let argon_params = Argon2Params::new(
        params.memory_kib,
        params.passes,
        params.lanes,
        Some(OUTPUT_BYTES),
    )
    .map_err(|_| KdfError::BadParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = Zeroizing::new([0_u8; OUTPUT_BYTES]);
    argon
        .hash_password_into(&normalised[..used], salt, &mut *out)
        .map_err(|_| KdfError::Failed)?;
    // `normalised` is wiped when it goes out of scope; say so for the part that was in use too.
    drop(normalised);
    Ok(Stretched(out))
}

/// Wipes a buffer; for callers that hold a PIN of their own.
pub fn wipe(buffer: &mut [u8]) {
    buffer.zeroize();
}

#[cfg(test)]
mod tests;
