//! Property: a user layer never loosens an answer of the policy engine, and no admin layer and user
//! layer make `merge` or a query panic. The input is text: an admin layer, a line that is exactly
//! `---`, and a user layer (without that line the whole text is the admin layer and there is no user
//! layer). A layer that does not parse, or a pair that does not merge, is not what this checks: the
//! loader fails closed to PIN-only for those.
#![no_main]

use libfuzzer_sys::fuzz_target;
use linuxhello_agent::policy::strictness::{at_least_as_strict_decision, at_least_as_strict_rule};
use linuxhello_agent::policy::{merge, parse_layer, Policy};

/// The contexts that are always asked, one of them unknown to every layer.
const CONTEXTS: [&str; 5] = ["login", "unlock", "sudo", "session", "nonexistent"];

/// Splits the text at the first line that is exactly `---`.
fn split(text: &str) -> (&str, &str) {
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        if line.trim_end_matches(['\r', '\n']) == "---" {
            return (&text[..offset], &text[offset + line.len()..]);
        }
        offset += line.len();
    }
    (text, "")
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (admin_text, user_text) = split(text);
    let Ok(admin) = parse_layer(admin_text) else {
        return;
    };
    let user = if user_text.trim().is_empty() {
        None
    } else {
        match parse_layer(user_text) {
            Ok(user) => Some(user),
            Err(_) => return,
        }
    };
    let Ok(base) = merge(std::slice::from_ref(&admin), None) else {
        return;
    };
    let Ok(with_user) = merge(std::slice::from_ref(&admin), user.as_ref()) else {
        return;
    };
    let (base, with_user) = (Policy::Effective(base), Policy::Effective(with_user));

    let mut contexts: Vec<String> = CONTEXTS.iter().map(|c| (*c).to_string()).collect();
    let mut relying_parties = vec!["unmatched.example".to_string()];
    for layer in std::iter::once(&admin).chain(user.as_ref()) {
        contexts.extend(layer.context.keys().cloned());
        for class in layer.rp_class.values() {
            for pattern in &class.match_patterns {
                relying_parties.push(pattern.clone());
                if let Some(domain) = pattern.strip_prefix("*.") {
                    relying_parties.push(domain.to_string());
                    relying_parties.push(format!("x.{domain}"));
                }
            }
        }
    }

    for context in &contexts {
        let (answer, baseline) = (with_user.methods_for(context), base.methods_for(context));
        assert!(
            at_least_as_strict_rule(&answer, &baseline),
            "context {context}: with the user layer {answer:?}, without {baseline:?}"
        );
    }
    for rp in &relying_parties {
        let (answer, baseline) = (with_user.decision_for(rp), base.decision_for(rp));
        assert!(
            at_least_as_strict_decision(&answer, &baseline),
            "relying party {rp}: with the user layer {answer:?}, without {baseline:?}"
        );
    }
});
