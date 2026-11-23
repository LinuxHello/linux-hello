//! Tests of the check that a key blob is one this provider made. They need no TPM: the check
//! looks only at the public area.

use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::{
    Digest, Public, PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder,
};
use tss_esapi::structures::{RsaExponent, SymmetricDefinitionObject};

use super::*;

/// A public area like the one `enrol` makes, with the attributes `attributes` builds on top of the
/// standard ones, and an `auth_policy` when asked.
fn public_with(no_da: bool, policy: Option<Vec<u8>>) -> Public {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(true)
        .with_no_da(no_da)
        .build()
        .unwrap();
    let mut builder = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                RsaKeyBits::Rsa2048,
                RsaExponent::default(),
            )
            .build()
            .unwrap(),
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default());
    if let Some(policy) = policy {
        builder = builder.with_auth_policy(Digest::try_from(policy).unwrap());
    }
    builder.build().unwrap()
}

#[test]
fn the_key_that_enrol_makes_is_accepted() {
    assert_eq!(check_template(&public_with(false, None)), Ok(()));
}

#[test]
fn a_key_with_no_da_is_refused() {
    // R-19, #361: such a key never locks, however many wrong PINs are tried.
    assert!(check_template(&public_with(true, None)).is_err());
}

#[test]
fn a_key_with_an_auth_policy_is_refused() {
    assert!(check_template(&public_with(false, Some(vec![7; 32]))).is_err());
}

#[test]
fn a_key_of_another_type_is_refused() {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .build()
        .unwrap();
    let other = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_keyed_hash_parameters(tss_esapi::structures::PublicKeyedHashParameters::new(
            tss_esapi::structures::KeyedHashScheme::HMAC_SHA_256,
        ))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .unwrap();
    assert!(check_template(&other).is_err());
}
