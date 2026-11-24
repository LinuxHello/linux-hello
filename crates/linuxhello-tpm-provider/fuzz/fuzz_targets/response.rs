//! Any bytes as an answer of the TPM provider, as the Agent reads it: reading never panics, and a
//! body that decodes is exactly the canonical encoding of what it decoded to.
#![no_main]

use libfuzzer_sys::fuzz_target;
use linuxhello_tpm_provider::wire::{
    decode_limits, decode_response, encode_limits, encode_response,
};

fuzz_target!(|data: &[u8]| {
    if let Some(response) = decode_response(data) {
        assert_eq!(
            encode_response(&response).as_deref(),
            Some(data),
            "an answer has one encoding"
        );
    }
    if let Some(Ok(limits)) = decode_limits(data) {
        assert_eq!(encode_limits(&limits), data, "limits have one encoding");
    }
});
