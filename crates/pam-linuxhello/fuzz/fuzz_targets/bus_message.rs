//! Any bytes as a D-Bus message for the PAM module's codec: reading never panics, a length
//! above the limit is refused before anything is read, and a message that reads has a length that
//! matches its header.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pam_linuxhello::client::wire::{parse, total_length, MAX_MESSAGE};

fuzz_target!(|data: &[u8]| {
    if let Some(head) = data.get(..16).and_then(|h| <&[u8; 16]>::try_from(h).ok()) {
        if let Ok(total) = total_length(head) {
            assert!(total <= MAX_MESSAGE);
        }
    }
    if parse(data).is_ok() {
        let head: &[u8; 16] = data[..16].try_into().unwrap();
        assert_eq!(total_length(head), Ok(data.len()));
    }
});
