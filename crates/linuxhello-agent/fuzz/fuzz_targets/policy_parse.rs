//! Property: a policy file of any content is either parsed or refused; the
//! parser never panics, overflows or aborts. A crash here would take the Agent
//! down instead of failing closed to PIN-only.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The Agent refuses non-UTF-8 files before parsing
    // (non_utf8_file_leaves_only_pin); the parser itself takes &str.
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(policy) = linuxhello_agent::policy::schema::parse(input) else {
        return;
    };
    // Every value a parsed policy derives must be computable without panicking.
    for context in policy.context.values() {
        if let Some(duration) = &context.reverify_after {
            let _ = duration.total_seconds();
        }
    }
});
