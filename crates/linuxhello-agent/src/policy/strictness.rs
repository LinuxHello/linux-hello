//! Comparing two answers of the policy engine for strictness.
//!
//! "At least as strict" is what the layering rules promise: a user layer can only tighten what the
//! defaults and the admin decide (`docs/architecture/policy-semantics.md`, *Layering*). The comparison
//! is shared by the unit tests below and by the `policy_pipeline` fuzz target, which asserts it for
//! any admin layer and user layer that merge.

use crate::policy::schema::{RpPrompt, RpProvider};
use crate::policy::{MethodRule, RpDecision};

/// A provider's strictness: `any` 0, `keepassxc` 1, `tpm` 2. The same order as `provider_rank` in
/// `query.rs`; `user_layer_never_loosens_an_admin_answer` fails if the two drift apart.
fn provider_rank(provider: RpProvider) -> u8 {
    match provider {
        RpProvider::Any => 0,
        RpProvider::Keepassxc => 1,
        RpProvider::Tpm => 2,
    }
}

/// A prompt's strictness: `none` 0, `presence` 1, `reverify` 2. The same order as `prompt_rank` in
/// `query.rs`; `user_layer_never_loosens_an_admin_answer` fails if the two drift apart.
fn prompt_rank(prompt: RpPrompt) -> u8 {
    match prompt {
        RpPrompt::None => 0,
        RpPrompt::Presence => 1,
        RpPrompt::Reverify => 2,
    }
}

/// Whether `candidate` is at least as strict as `baseline`: the provider and the prompt rank at
/// least as high (provider `any` 0, `keepassxc` 1, `tpm` 2; prompt `none` 0, `presence` 1,
/// `reverify` 2), the factors are at least as many, and a second credential is required unless the
/// baseline does not require one.
pub fn at_least_as_strict_decision(candidate: &RpDecision, baseline: &RpDecision) -> bool {
    provider_rank(candidate.provider) >= provider_rank(baseline.provider)
        && prompt_rank(candidate.prompt) >= prompt_rank(baseline.prompt)
        && candidate.factors >= baseline.factors
        && (candidate.require_second_credential || !baseline.require_second_credential)
}

/// Whether `candidate` is at least as strict as `baseline`: it allows no method the baseline does
/// not, needs at least as many factors, re-verifies at least as often (no limit is the loosest), and
/// is unsatisfiable whenever the baseline is.
pub fn at_least_as_strict_rule(candidate: &MethodRule, baseline: &MethodRule) -> bool {
    let reverify = match (&candidate.reverify_after, &baseline.reverify_after) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(candidate), Some(baseline)) => candidate.total_seconds() <= baseline.total_seconds(),
    };
    candidate
        .methods
        .iter()
        .all(|method| baseline.methods.contains(method))
        && candidate.factors >= baseline.factors
        && reverify
        && (candidate.unsatisfiable || !baseline.unsatisfiable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::schema::{Duration, DurationUnit, RpPrompt, RpProvider};
    use crate::policy::{merge, parse_layer, Policy};

    fn decision(provider: RpProvider, prompt: RpPrompt, factors: u32, second: bool) -> RpDecision {
        RpDecision {
            provider,
            prompt,
            factors,
            require_second_credential: second,
        }
    }

    fn rule(
        methods: &[&str],
        factors: u32,
        reverify: Option<Duration>,
        unsatisfiable: bool,
    ) -> MethodRule {
        MethodRule {
            methods: methods.iter().map(|m| (*m).to_string()).collect(),
            factors,
            reverify_after: reverify,
            unsatisfiable,
        }
    }

    fn after(value: u64, unit: DurationUnit) -> Option<Duration> {
        Some(Duration { value, unit })
    }

    #[test]
    fn a_looser_decision_is_not_at_least_as_strict() {
        use RpPrompt::{None as NoPrompt, Presence, Reverify};
        use RpProvider::{Any, Keepassxc, Tpm};
        let base = decision(Keepassxc, Presence, 2, true);
        assert!(at_least_as_strict_decision(&base, &base));
        for tighter in [
            decision(Tpm, Presence, 2, true),
            decision(Keepassxc, Reverify, 2, true),
            decision(Keepassxc, Presence, 3, true),
        ] {
            assert!(at_least_as_strict_decision(&tighter, &base), "{tighter:?}");
        }
        for looser in [
            decision(Any, Presence, 2, true),
            decision(Keepassxc, NoPrompt, 2, true),
            decision(Keepassxc, Presence, 1, true),
            decision(Keepassxc, Presence, 2, false),
        ] {
            assert!(!at_least_as_strict_decision(&looser, &base), "{looser:?}");
        }
    }

    #[test]
    fn a_looser_method_rule_is_not_at_least_as_strict() {
        let hour = after(1, DurationUnit::Hours);
        let base = rule(&["pin", "fingerprint"], 2, hour.clone(), false);
        assert!(at_least_as_strict_rule(&base, &base));
        for tighter in [
            rule(&["pin"], 2, hour.clone(), true),
            rule(&["pin", "fingerprint"], 3, hour.clone(), true),
            rule(
                &["pin", "fingerprint"],
                2,
                after(30, DurationUnit::Minutes),
                false,
            ),
        ] {
            assert!(at_least_as_strict_rule(&tighter, &base), "{tighter:?}");
        }
        for looser in [
            rule(&["pin", "fingerprint", "face"], 2, hour.clone(), false),
            rule(&["pin", "fingerprint"], 1, hour.clone(), false),
            rule(
                &["pin", "fingerprint"],
                2,
                after(2, DurationUnit::Hours),
                false,
            ),
            rule(&["pin", "fingerprint"], 2, None, false),
        ] {
            assert!(!at_least_as_strict_rule(&looser, &base), "{looser:?}");
        }
        let unsatisfiable = rule(&["pin"], 2, hour.clone(), true);
        let satisfiable = rule(&["pin"], 2, hour, false);
        assert!(!at_least_as_strict_rule(&satisfiable, &unsatisfiable));
    }

    /// Admin layers; each is used alone and the empty layer is used too.
    const ADMIN_LAYERS: [&str; 5] = [
        "[methods]\nbiometrics_allowed = false\n",
        "[context.sudo]\nmethods = [\"pin\", \"fingerprint\"]\nfactors = 2\nreverify_after = \"1h\"\n",
        "[context.session]\nmethods = [\"pin\", \"fingerprint\", \"face\"]\nreverify_after = \"24h\"\n",
        "[rp_class.bank]\nmatch = [\"bank.example\"]\nprovider = \"tpm\"\nprompt = \"reverify\"\nfactors = 2\n",
        "[rp_class.wild]\nmatch = [\"*.bank.example\"]\nprovider = \"keepassxc\"\nrequire_second_credential = true\n",
    ];

    /// User layers, most of which try to loosen something and two of which tighten; the empty layer is
    /// used too. The two that tighten make the comparison tell "stricter" from "equal": without them
    /// every answer with the user layer would equal the answer without it, and a comparison with its
    /// orders reversed would pass.
    const USER_LAYERS: [&str; 7] = [
        "[methods]\nbiometrics_allowed = true\nface_requires_ir = false\n",
        "[context.sudo]\nmethods = [\"pin\", \"fingerprint\", \"face\"]\nfactors = 1\nreverify_after = \"12h\"\n",
        "[context.session]\nmethods = [\"pin\", \"fingerprint\", \"face\"]\nreverify_after = \"30d\"\n",
        "[rp_class.mine]\nmatch = [\"bank.example\"]\nprovider = \"any\"\nprompt = \"none\"\nfactors = 1\n",
        "[rp_class.other]\nmatch = [\"evil.example\"]\nprovider = \"any\"\nprompt = \"none\"\n",
        "[context.sudo]\nmethods = [\"pin\"]\nfactors = 2\nreverify_after = \"1h\"\n",
        "[rp_class.tight]\nmatch = [\"*.bank.example\"]\nprovider = \"tpm\"\nprompt = \"reverify\"\nfactors = 2\n",
    ];

    #[test]
    fn user_layer_never_loosens_an_admin_answer() {
        let contexts = ["login", "unlock", "sudo", "session", "nonexistent"];
        let relying_parties = [
            "bank.example",
            "x.bank.example",
            "evil.example",
            "unmatched.example",
        ];
        for admin_text in std::iter::once("").chain(ADMIN_LAYERS) {
            for user_text in std::iter::once("").chain(USER_LAYERS) {
                let admin = parse_layer(admin_text).expect("the admin layer parses");
                let user = parse_layer(user_text).expect("the user layer parses");
                let base = Policy::Effective(
                    merge(std::slice::from_ref(&admin), None).expect("the admin layer merges"),
                );
                let with_user = Policy::Effective(
                    merge(std::slice::from_ref(&admin), Some(&user)).expect("the layers merge"),
                );
                for context in contexts {
                    let (answer, baseline) =
                        (with_user.methods_for(context), base.methods_for(context));
                    assert!(
                        at_least_as_strict_rule(&answer, &baseline),
                        "a user layer never loosens an admin answer: context {context}\nadmin:\n{admin_text}\nuser:\n{user_text}\nwith the user layer: {answer:?}\nwithout: {baseline:?}"
                    );
                }
                for rp in relying_parties {
                    let (answer, baseline) = (with_user.decision_for(rp), base.decision_for(rp));
                    assert!(
                        at_least_as_strict_decision(&answer, &baseline),
                        "a user layer never loosens an admin answer: relying party {rp}\nadmin:\n{admin_text}\nuser:\n{user_text}\nwith the user layer: {answer:?}\nwithout: {baseline:?}"
                    );
                }
            }
        }
    }
}
