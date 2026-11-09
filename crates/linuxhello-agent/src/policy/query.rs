//! Queries on a loaded `Policy`: which methods and how many factors a context
//! needs (`methods_for`), and which provider, prompt and factors a relying party
//! gets (`decision_for`). Both answer from the effective policy, or from the
//! PIN-only state when loading failed closed (policy-semantics.md, *Queries*).

use crate::policy::load::Policy;
use crate::policy::schema::{Duration, Layer, RpClassPolicy, RpPrompt, RpProvider};

/// What a context requires: the methods it allows and how many of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodRule {
    /// The methods the context allows, `pin` always among them.
    pub methods: Vec<String>,
    /// How many methods must succeed; never lowered to fit `methods`.
    pub factors: u32,
    /// How long a successful authentication counts, if limited.
    pub reverify_after: Option<Duration>,
    /// `factors` exceeds the number of methods: the context cannot be satisfied
    /// until more methods are allowed or enrolled
    /// (`two_factors_with_only_pin_is_reported_unsatisfiable`).
    pub unsatisfiable: bool,
}

/// What a relying party gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpDecision {
    /// Where its passkey lives: device-bound (`tpm`), portable (`keepassxc`) or either.
    pub provider: RpProvider,
    /// What the user is asked at use: nothing, presence, or re-verification.
    pub prompt: RpPrompt,
    /// How many methods must succeed.
    pub factors: u32,
    /// Whether a second credential must be registered.
    pub require_second_credential: bool,
}

/// The decision for a relying party no class matches, and the value of every key
/// a matching class leaves unset (`unmatched_rp_gets_default_decision`).
const NO_MATCH: RpDecision = RpDecision {
    provider: RpProvider::Any,
    prompt: RpPrompt::Presence,
    factors: 1,
    require_second_credential: false,
};

impl Policy {
    /// The rule for `context`, from the effective layer or the PIN-only layer.
    ///
    /// Unset `factors` count as 1. A context name the layer does not have allows
    /// only the PIN, with one factor (`unknown_context_allows_only_pin`).
    pub fn methods_for(&self, context: &str) -> MethodRule {
        let (methods, factors, reverify_after) = match self.layer().context.get(context) {
            Some(ctx) => (
                ctx.methods.clone(),
                ctx.factors.unwrap_or(1),
                ctx.reverify_after.clone(),
            ),
            None => (vec!["pin".to_string()], 1, None),
        };
        let unsatisfiable = usize::try_from(factors).map_or(true, |f| f > methods.len());
        MethodRule {
            methods,
            factors,
            reverify_after,
            unsatisfiable,
        }
    }

    /// The decision for relying party `rp_id`.
    ///
    /// `rp_id` is lower-cased and one trailing dot removed. Among the admin's
    /// classes, the ones with the most specific matching pattern decide (exact
    /// beats wildcard, then the longer domain: `exact_domain_beats_wildcard`,
    /// `longer_suffix_beats_shorter`), merged most restrictive on a tie
    /// (`tied_classes_merge_most_restrictive`). Unset keys and no match give
    /// `NO_MATCH`.
    ///
    /// The user's classes are asked the same way. When one matches, the answer is
    /// the stricter of the two, key by key: a user class tightens and never loosens
    /// (`user_layer_cannot_lower_rp_prompt_below_default`,
    /// `user_class_cannot_shadow_a_stricter_admin_class`).
    ///
    /// In the PIN-only state the answer is at least `tpm`, `reverify`, one factor
    /// (`pin_only_state_requires_tpm_and_reverify`), and stricter where a class
    /// the state kept asks for more
    /// (`pin_only_state_is_never_weaker_than_the_admin_layer`).
    pub fn decision_for(&self, rp_id: &str) -> RpDecision {
        let lower = rp_id.to_ascii_lowercase();
        let id = lower.strip_suffix('.').unwrap_or(&lower);
        match self {
            Policy::PinOnly(pin) => stricter(
                class_decision(pin.layer.rp_class.values(), id).unwrap_or(NO_MATCH),
                RpDecision {
                    provider: pin.rp_provider,
                    prompt: pin.rp_prompt,
                    factors: pin.rp_factors,
                    require_second_credential: false,
                },
            ),
            Policy::Effective(effective) => {
                let admin =
                    class_decision(effective.layer.rp_class.values(), id).unwrap_or(NO_MATCH);
                match class_decision(effective.user_rp_class.values(), id) {
                    Some(user) => stricter(admin, user),
                    None => admin,
                }
            }
        }
    }

    /// The layer the queries read: the effective layer, or the PIN-only layer.
    fn layer(&self) -> &Layer {
        match self {
            Policy::Effective(effective) => &effective.layer,
            Policy::PinOnly(pin) => &pin.layer,
        }
    }
}

/// The decision `classes` give the normalised `id`: the classes with the most
/// specific matching pattern, merged most restrictive on a tie; `None` when no
/// class matches.
fn class_decision<'a>(
    classes: impl Iterator<Item = &'a RpClassPolicy>,
    id: &str,
) -> Option<RpDecision> {
    let matches: Vec<(Specificity, &RpClassPolicy)> = classes
        .filter_map(|class| best_match(class, id).map(|s| (s, class)))
        .collect();
    let best = matches.iter().map(|(s, _)| *s).max()?;
    matches
        .iter()
        .filter(|(s, _)| *s == best)
        .map(|(_, class)| values_of(class))
        .reduce(stricter)
}

/// How specific a pattern's match is: an exact match beats any wildcard
/// (`true` > `false`), then the longer domain wins.
type Specificity = (bool, usize);

/// The specificity of `class`'s most specific pattern that matches the
/// normalised `id`, if any. `*.d` matches a name ending in `.d` with at least
/// one character before the dot, never `d` itself (`wildcard_does_not_match_apex`)
/// and never a look-alike such as `xd` (`wildcard_does_not_match_lookalike_suffix`).
fn best_match(class: &RpClassPolicy, id: &str) -> Option<Specificity> {
    class
        .match_patterns
        .iter()
        .filter_map(|pattern| match pattern.strip_prefix("*.") {
            None => (pattern == id).then_some((true, pattern.len())),
            Some(domain) => id
                .strip_suffix(domain)
                .and_then(|rest| rest.strip_suffix('.'))
                .filter(|label| !label.is_empty())
                .map(|_| (false, domain.len())),
        })
        .max()
}

/// A class's decision on its own: its keys, unset ones taken from `NO_MATCH`.
fn values_of(class: &RpClassPolicy) -> RpDecision {
    RpDecision {
        provider: class.provider.unwrap_or(NO_MATCH.provider),
        prompt: class.prompt.unwrap_or(NO_MATCH.prompt),
        factors: class.factors.unwrap_or(NO_MATCH.factors),
        require_second_credential: class
            .require_second_credential
            .unwrap_or(NO_MATCH.require_second_credential),
    }
}

/// The more restrictive of two decisions, key by key: provider `tpm` over
/// `keepassxc` over `any`; prompt `reverify` over `presence` over `none`; the
/// larger `factors`; a second credential if either requires one.
fn stricter(a: RpDecision, b: RpDecision) -> RpDecision {
    RpDecision {
        provider: if provider_rank(b.provider) > provider_rank(a.provider) {
            b.provider
        } else {
            a.provider
        },
        prompt: if prompt_rank(b.prompt) > prompt_rank(a.prompt) {
            b.prompt
        } else {
            a.prompt
        },
        factors: a.factors.max(b.factors),
        require_second_credential: a.require_second_credential || b.require_second_credential,
    }
}

/// A provider's strictness: `any` 0, `keepassxc` 1, `tpm` 2.
fn provider_rank(provider: RpProvider) -> u8 {
    match provider {
        RpProvider::Any => 0,
        RpProvider::Keepassxc => 1,
        RpProvider::Tpm => 2,
    }
}

/// A prompt's strictness: `none` 0, `presence` 1, `reverify` 2.
fn prompt_rank(prompt: RpPrompt) -> u8 {
    match prompt {
        RpPrompt::None => 0,
        RpPrompt::Presence => 1,
        RpPrompt::Reverify => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::merge::merge;
    use crate::policy::schema::parse_layer;

    fn effective(toml: &str) -> Policy {
        Policy::Effective(merge(&[parse_layer(toml).unwrap()], None).unwrap())
    }

    #[test]
    fn exact_domain_beats_wildcard() {
        let toml = r#"
[rp_class.exact]
match = ["bank.example"]
provider = "tpm"

[rp_class.wildcard]
match = ["*.bank.example"]
provider = "keepassxc"
"#;
        let pol = effective(toml);
        let dec = pol.decision_for("bank.example");
        assert_eq!(dec.provider, RpProvider::Tpm);
    }

    #[test]
    fn longer_suffix_beats_shorter() {
        let toml = r#"
[rp_class.long]
match = ["*.sub.bank.example"]
provider = "tpm"

[rp_class.short]
match = ["*.bank.example"]
provider = "keepassxc"
"#;
        let pol = effective(toml);
        let dec = pol.decision_for("other.sub.bank.example");
        assert_eq!(dec.provider, RpProvider::Tpm);
    }

    #[test]
    fn wildcard_does_not_match_apex() {
        let toml = r#"
[rp_class.wildcard]
match = ["*.bank.example"]
provider = "tpm"
"#;
        let pol = effective(toml);
        let dec = pol.decision_for("bank.example");
        assert_eq!(dec.provider, RpProvider::Any);
    }

    #[test]
    fn wildcard_does_not_match_lookalike_suffix() {
        let toml = r#"
[rp_class.wildcard]
match = ["*.bank.example"]
provider = "tpm"
"#;
        let pol = effective(toml);
        let dec = pol.decision_for("evilbank.example");
        assert_eq!(dec.provider, RpProvider::Any);
    }

    #[test]
    fn rp_ids_compared_case_insensitively() {
        let toml = r#"
[rp_class.bank]
match = ["bank.example"]
provider = "tpm"
"#;
        let pol = effective(toml);
        let dec = pol.decision_for("BANK.EXAMPLE");
        assert_eq!(dec.provider, RpProvider::Tpm);
    }

    #[test]
    fn trailing_dot_is_ignored() {
        let toml = r#"
[rp_class.bank]
match = ["bank.example"]
provider = "tpm"
"#;
        let pol = effective(toml);
        let dec = pol.decision_for("bank.example.");
        assert_eq!(dec.provider, RpProvider::Tpm);
    }

    #[test]
    fn unmatched_rp_gets_default_decision() {
        let pol = effective("");
        let dec = pol.decision_for("unknown.com");
        assert_eq!(dec.provider, RpProvider::Any);
        assert_eq!(dec.prompt, RpPrompt::Presence);
        assert_eq!(dec.factors, 1);
        assert!(!dec.require_second_credential);
    }

    #[test]
    fn tied_classes_merge_most_restrictive() {
        let toml = r#"
[rp_class.c1]
match = ["bank.example"]
provider = "keepassxc"
factors = 1

[rp_class.c2]
match = ["bank.example"]
provider = "tpm"
factors = 2
"#;
        let pol = effective(toml);
        let dec = pol.decision_for("bank.example");
        assert_eq!(dec.provider, RpProvider::Tpm);
        assert_eq!(dec.factors, 2);
    }

    #[test]
    fn matched_class_without_provider_uses_default_values() {
        let toml = r#"
[rp_class.c1]
match = ["bank.example"]
factors = 2
"#;
        let pol = effective(toml);
        let dec = pol.decision_for("bank.example");
        assert_eq!(dec.provider, RpProvider::Any);
        assert_eq!(dec.prompt, RpPrompt::Presence);
        assert_eq!(dec.factors, 2);
        assert!(!dec.require_second_credential);
    }

    #[test]
    fn two_factors_with_only_pin_is_reported_unsatisfiable() {
        let toml = r#"
[methods]
biometrics_allowed = false

[context.sudo]
methods = ["pin", "fingerprint"]
factors = 2
"#;
        let pol = effective(toml);
        let rule = pol.methods_for("sudo");
        // Note: Invariants in merge/invariants.rs might have already stripped fingerprint
        // if biometrics_allowed is false. But the brief says:
        // "Take the context from the policy's layer... unsatisfiable is factors > methods.len()"
        // If invariants stripped it, methods.len() is 1.
        assert_eq!(rule.factors, 2);
        assert!(rule.unsatisfiable);
    }

    #[test]
    fn unknown_context_allows_only_pin() {
        let pol = effective("");
        let rule = pol.methods_for("unknown");
        assert_eq!(rule.methods, vec!["pin".to_string()]);
        assert_eq!(rule.factors, 1);
        assert!(!rule.unsatisfiable);
    }

    #[test]
    fn pin_only_state_requires_tpm_and_reverify() {
        let tmp = tempfile::TempDir::new().unwrap();
        let user_file = tmp.path().join("user.toml");
        std::fs::write(&user_file, "not toml").unwrap();
        let pol = crate::policy::load::load(&tmp.path().join("absent.d"), &user_file, 0);
        assert!(matches!(pol, Policy::PinOnly(_)));

        let dec = pol.decision_for("any.example");
        assert_eq!(dec.provider, RpProvider::Tpm);
        assert_eq!(dec.prompt, RpPrompt::Reverify);
        assert_eq!(dec.factors, 1);
        assert!(!dec.require_second_credential);

        for context in ["login", "unlock", "sudo", "session"] {
            let rule = pol.methods_for(context);
            assert_eq!(rule.methods, vec!["pin".to_string()]);
            assert_eq!(rule.factors, 1);
        }
    }

    #[test]
    fn single_class_keeps_its_own_values() {
        let pol = effective(
            "[rp_class.a]\nmatch = [\"bank.example\"]\nprovider = \"keepassxc\"\nprompt = \"none\"",
        );
        let dec = pol.decision_for("bank.example");
        assert_eq!(dec.provider, RpProvider::Keepassxc);
        assert_eq!(dec.prompt, RpPrompt::None);
    }

    /// The policy of one admin layer and one user layer.
    fn layered(admin: &str, user: &str) -> Policy {
        let admin: Vec<_> = (!admin.is_empty())
            .then(|| parse_layer(admin).unwrap())
            .into_iter()
            .collect();
        Policy::Effective(merge(&admin, Some(&parse_layer(user).unwrap())).unwrap())
    }

    #[test]
    fn user_layer_cannot_lower_rp_prompt_below_default() {
        let pol = layered(
            "",
            "[rp_class.mine]\nmatch = [\"bank.example\"]\nprompt = \"none\"\nprovider = \"any\"",
        );
        let dec = pol.decision_for("bank.example");
        assert_eq!(dec, pol.decision_for("unmatched.example"));
        assert_eq!(dec.prompt, RpPrompt::Presence);
    }

    #[test]
    fn user_layer_can_tighten_an_rp_decision() {
        let pol = layered(
            "",
            "[rp_class.mine]\nmatch = [\"bank.example\"]\nprompt = \"reverify\"\nprovider = \"tpm\"\nfactors = 2",
        );
        let dec = pol.decision_for("bank.example");
        assert_eq!(dec.prompt, RpPrompt::Reverify);
        assert_eq!(dec.provider, RpProvider::Tpm);
        assert_eq!(dec.factors, 2);
        assert_eq!(pol.decision_for("other.example").prompt, RpPrompt::Presence);
    }

    #[test]
    fn user_patterns_do_not_join_an_admin_class() {
        // The admin loosens the prompt for the intranet. A user class of the same
        // name does not bring another relying party under the admin's values.
        let pol = layered(
            "[rp_class.low]\nmatch = [\"intranet.example\"]\nprompt = \"none\"",
            "[rp_class.low]\nmatch = [\"bank.example\"]",
        );
        assert_eq!(pol.decision_for("intranet.example").prompt, RpPrompt::None);
        assert_eq!(pol.decision_for("bank.example").prompt, RpPrompt::Presence);
        let Policy::Effective(effective) = &pol else {
            panic!("expected an effective policy");
        };
        assert_eq!(
            effective.layer.rp_class["low"].match_patterns,
            vec!["intranet.example".to_string()]
        );
    }

    #[test]
    fn user_class_cannot_shadow_a_stricter_admin_class() {
        // The user's exact pattern is more specific than the admin's wildcard, and
        // still cannot take the relying party out of the admin's rule.
        let pol = layered(
            "[rp_class.all]\nmatch = [\"*.example\"]\nprompt = \"reverify\"\nprovider = \"tpm\"\nfactors = 2",
            "[rp_class.mine]\nmatch = [\"bank.example\"]\nprompt = \"none\"\nprovider = \"any\"",
        );
        let dec = pol.decision_for("bank.example");
        assert_eq!(dec.prompt, RpPrompt::Reverify);
        assert_eq!(dec.provider, RpProvider::Tpm);
        assert_eq!(dec.factors, 2);
    }
}
