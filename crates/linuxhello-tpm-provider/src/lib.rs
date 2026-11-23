//! The TPM side of Linux Hello: the per-user root key and what is done with it.
//!
//! So far only the key service ([`keys`]): create a user's root key under a storage primary with the
//! stretched PIN as its authorisation, check a PIN against it, and change the PIN in place. The
//! provider interface for passkeys (C4 `tpmProviderApi`) and the sessions of ADR-0021 decision 3 are
//! later slices of #271.
//!
//! The crate has no `unsafe` of its own: `tss-esapi` is the one dependency that talks to the
//! system's TSS2 libraries.
//!
//! C4 container: `tpmProvider` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

#![forbid(unsafe_code)]

pub mod client;
pub mod wire;

#[cfg(feature = "tpm")]
pub mod keys;
#[cfg(feature = "tpm")]
pub mod server;
#[cfg(feature = "testing")]
pub mod testing;
