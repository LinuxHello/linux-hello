//! Property: whatever `busctl` prints for `GetStatus`, reading it never panics, and the answer is
//! either no answer or a list in which every condition has three fields and the list is exactly
//! as long as the reply says (`an_answer_that_cannot_be_read_is_no_answer` in `ask.rs`).
//!
//! `linuxhello-ctl` is a binary crate, so the target includes the two source files it needs: the
//! `Host` trait and the reader of the reply.
#![no_main]
#![allow(dead_code)]

use libfuzzer_sys::fuzz_target;

#[path = "../../src/probe.rs"]
mod probe;

#[path = "../../src/ask.rs"]
mod ask;

/// A machine whose `busctl` prints the fuzzer's text and exits with the fuzzer's code.
struct Printing {
    code: i32,
    text: String,
}

impl probe::Host for Printing {
    fn run(&self, _program: &str, _args: &[&str]) -> Option<(i32, String)> {
        Some((self.code, self.text.clone()))
    }

    fn read(&self, _path: &std::path::Path) -> Option<String> {
        None
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((first, rest)) = data.split_first() else {
        return;
    };
    let host = Printing {
        code: i32::from(*first % 3),
        text: String::from_utf8_lossy(rest).into_owned(),
    };
    let answer = ask::get_status(&host);
    if host.code != 0 {
        assert!(answer.is_none(), "a failed call has no answer");
    }
    if let Some(list) = answer {
        let declared = host
            .text
            .trim()
            .strip_prefix("a(sss) ")
            .and_then(|r| r.split(' ').next())
            .and_then(|n| n.parse::<usize>().ok());
        assert_eq!(declared, Some(list.len()));
    }
});
