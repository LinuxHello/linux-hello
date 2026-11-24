//! Any bytes as a request to the TPM provider: reading never panics, a frame over the limit is
//! refused before it is read, and a body that decodes is exactly the canonical encoding of what it
//! decoded to, so there is one way to say each request and nothing hides in the bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use linuxhello_tpm_provider::wire::{decode_request, encode_request, read_frame, MAX_FRAME};

fuzz_target!(|data: &[u8]| {
    if let Some(request) = decode_request(data) {
        let again = encode_request(&request).expect("a decoded request has fields that fit");
        assert_eq!(&again[..], data, "a request has one encoding");
    }
    // As a frame on a socket: a length, then the body.
    let mut stream = data;
    if let Ok(Some(body)) = read_frame(&mut stream) {
        assert!(!body.is_empty() && body.len() <= MAX_FRAME);
    }
});
