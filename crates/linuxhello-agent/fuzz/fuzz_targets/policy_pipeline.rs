//! Property: a user layer never loosens an answer of the policy engine, and no admin layer and user
//! layer make `merge` or a query panic. The input is text: an admin layer, a line that is exactly
//! `---`, and a user layer (without that line the whole text is the admin layer and there is no user
//! layer). The admin text may hold a second admin layer after a line that is exactly `===`: two
//! admin layers merged are at least as strict as either alone (R-14, #356, #375). A layer that does not parse, or a pair that does not merge, is not what this checks: the
//! loader fails closed to PIN-only for those.
#![no_main]

use libfuzzer_sys::fuzz_target;
use linuxhello_agent::policy::strictness::{at_least_as_strict_decision, at_least_as_strict_rule};
use linuxhello_agent::policy::{merge, parse_layer, Policy};

/// The contexts that are always asked, one of them unknown to every layer.
const CONTEXTS: [&str; 5] = ["login", "unlock", "sudo", "session", "nonexistent"];

/// Splits the text at the first line that is exactly `---`.
fn split<'a>(text: &'a str, marker: &str) -> (&'a str, &'a str) {
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        if line.trim_end_matches(['\r', '\n']) == marker {
            return (&text[..offset], &text[offset + line.len()..]);
        }
        offset += line.len();
    }
    (text, "")
}

/// Two admin layers merged answer at least as strictly as each of them alone.
fn check_two_admin_layers(first: &linuxhello_agent::policy::Layer, second_text: &str) {
    let Ok(second) = parse_layer(second_text) else {
        return;
    };
    let both = [first.clone(), second.clone()];
    let Ok(together) = merge(&both, None) else {
        return;
    };
    let together = Policy::Effective(together);
    for alone in [first, &second] {
        let Ok(alone) = merge(std::slice::from_ref(alone), None) else {
            continue;
        };
        let alone = Policy::Effective(alone);
        for context in CONTEXTS {
            let (answer, baseline) = (together.methods_for(context), alone.methods_for(context));
            assert!(
                at_least_as_strict_rule(&answer, &baseline),
                "context {context}: two admin layers {answer:?}, one {baseline:?}"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (admin_texts, user_text) = split(text, "---");
    let (admin_text, second_text) = split(admin_texts, "===");
    let Ok(admin) = parse_layer(admin_text) else {
        return;
    };
    if !second_text.trim().is_empty() {
        check_two_admin_layers(&admin, second_text);
    }
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
