//! Querying the effective policy for context methods and relying-party decisions.
//!
//! This module provides the mechanism to ask the loaded `Policy` which methods
//! and factors are required for a given context, and what the decision is for
//! a given relying party.

use crate::policy::load::Policy;
use crate::policy::schema::{RpClassPolicy, RpPrompt, RpProvider};

/// The rules for authentication in a specific context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodRule {
    /// The allowed methods.
    pub methods: Vec<String>,
    /// The number of factors required.
    pub factors: u32,
    /// How long the authentication remains valid.
    pub reverify_after: Option<crate::policy::schema::Duration>,
    /// Whether the rule is unsatisfiable (factors > methods.len()).
    pub unsatisfiable: bool,
}

/// The decision for a specific relying party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpDecision {
    /// The provider for the passkey.
    pub provider: RpProvider,
    /// The prompt for the user.
    pub prompt: RpPrompt,
    /// The number of factors required.
    pub factors: u32,
    /// Whether a second credential is required.
    pub require_second_credential: bool,
}

impl Policy {
    /// Returns the authentication rules for a given context name.
    pub fn methods_for(&self, context: &str) -> MethodRule {
        let (methods, factors, reverify_after) = match self {
            Policy::Effective(eff) => {
                if let Some(ctx) = eff.layer.context.get(context) {
                    (
                        ctx.methods.clone(),
                        ctx.factors.unwrap_or(1),
                        ctx.reverify_after.clone(),
                    )
                } else {
                    (vec!["pin".to_string()], 1, None)
                }
            }
            Policy::PinOnly(_) => (vec!["pin".to_string()], 1, None),
        };

        let unsatisfiable = factors > methods.len() as u32;

        MethodRule {
            methods,
            factors,
            reverify_after,
            unsatisfiable,
        }
    }

    /// Returns the decision for a given relying party ID.
    pub fn decision_for(&self, rp_id: &str) -> RpDecision {
        match self {
            Policy::PinOnly(pin) => RpDecision {
                provider: pin.rp_provider,
                prompt: pin.rp_prompt,
                factors: pin.rp_factors,
                require_second_credential: false,
            },
            Policy::Effective(eff) => {
                let normalized_id = rp_id.to_ascii_lowercase();
                let normalized_id = normalized_id.strip_suffix('.').unwrap_or(&normalized_id);

                // Find all matching classes and their best pattern specificity
                let mut matches: Vec<(&RpClassPolicy, usize)> = Vec::new();

                for class in eff.layer.rp_class.values() {
                    let mut best_specificity = None;

                    for pattern in &class.match_patterns {
                        if pattern == normalized_id {
                            // Exact match: highest specificity
                            best_specificity = Some(pattern.len() + 1);
                            break;
                        } else if pattern.starts_with("*.") {
                            let domain = &pattern[2..];
                            if normalized_id.ends_with(domain) && normalized_id.len() > domain.len()
                            {
                                // Ensure the character before the domain is a dot to prevent lookalike suffix matches
                                // e.g., "evilbank.example" should not match "*.bank.example"
                                let prefix_len = normalized_id.len() - domain.len();
                                if normalized_id.as_bytes()[prefix_len - 1] == b'.' {
                                    // Wildcard match: specificity is the length of the domain part
                                    let spec = domain.len();
                                    if best_specificity.map_or(true, |s| spec > s) {
                                        best_specificity = Some(spec);
                                    }
                                }
                            }
                        }
                    }

                    if let Some(spec) = best_specificity {
                        matches.push((class, spec));
                    }
                }

                if matches.is_empty() {
                    return RpDecision {
                        provider: RpProvider::Any,
                        prompt: RpPrompt::Presence,
                        factors: 1,
                        require_second_credential: false,
                    };
                }

                // Sort by specificity descending
                matches.sort_by(|a, b| b.1.cmp(&a.1));
                let max_spec = matches[0].1;

                // Take all classes that share the highest specificity
                let top_classes: Vec<&RpClassPolicy> = matches
                    .iter()
                    .take_while(|(_, spec)| *spec == max_spec)
                    .map(|(class, _)| *class)
                    .collect();

                // Merge top classes
                let mut provider = RpProvider::Any;
                let mut prompt = RpPrompt::Presence;
                let mut factors = 0;
                let mut require_second_credential = false;

                for class in &top_classes {
                    // Provider: tpm > keepassxc > any
                    let p = class.provider.unwrap_or(RpProvider::Any);
                    provider = match (provider, p) {
                        (RpProvider::Tpm, _) | (_, RpProvider::Tpm) => RpProvider::Tpm,
                        (RpProvider::Keepassxc, _) | (_, RpProvider::Keepassxc) => {
                            RpProvider::Keepassxc
                        }
                        _ => RpProvider::Any,
                    };

                    // Prompt: reverify > presence > none
                    let pr = class.prompt.unwrap_or(RpPrompt::Presence);
                    prompt = match (prompt, pr) {
                        (RpPrompt::Reverify, _) | (_, RpPrompt::Reverify) => RpPrompt::Reverify,
                        (RpPrompt::Presence, _) | (_, RpPrompt::Presence) => RpPrompt::Presence,
                        _ => RpPrompt::None,
                    };

                    // Factors: max
                    factors = factors.max(class.factors.unwrap_or(1));

                    // Second credential: any true
                    if class.require_second_credential.unwrap_or(false) {
                        require_second_credential = true;
                    }
                }

                RpDecision {
                    provider,
                    prompt,
                    factors,
                    require_second_credential,
                }
            }
        }
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
        assert_eq!(dec.require_second_credential, false);
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
        assert_eq!(dec.require_second_credential, false);
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
        // Manually construct PinOnly to avoid needing to mock load()
        let pol = Policy::PinOnly(crate::policy::load::PinOnly {
            layer: crate::policy::defaults::default_layer(),
            rp_provider: RpProvider::Tpm,
            rp_prompt: RpPrompt::Reverify,
            rp_factors: 1,
            reason: "test".to_string(),
        });

        let dec = pol.decision_for("any.com");
        assert_eq!(dec.provider, RpProvider::Tpm);
        assert_eq!(dec.prompt, RpPrompt::Reverify);
        assert_eq!(dec.factors, 1);

        let rule = pol.methods_for("sudo");
        assert_eq!(rule.methods, vec!["pin".to_string()]);
        assert_eq!(rule.factors, 1);
    }
}
//! Querying the effective policy for context methods and relying-party decisions.
//!
//! This module provides the mechanism to ask the loaded `Policy` which methods
//! and factors are required for a given context, and what the decision is for
//! a given relying party.

use crate::policy::load::Policy;
use crate::policy::schema::{RpClassPolicy, RpPrompt, RpProvider, Duration};

/// The rules for authentication in a specific context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodRule {
    /// The allowed methods.
    pub methods: Vec<String>,
    /// The number of factors required.
    pub factors: u32,
    /// How long the authentication remains valid.
    pub reverify_after: Option<Duration>,
    /// Whether the rule is unsatisfiable (factors > methods.len()).
    pub unsatisfiable: bool,
}

/// The decision for a specific relying party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpDecision {
    /// The provider for the passkey.
    pub provider: RpProvider,
    /// The prompt for the user.
    pub prompt: RpPrompt,
    /// The number of factors required.
    pub factors: u32,
    /// Whether a second credential is required.
    pub require_second_credential: bool,
}

impl Policy {
    /// Returns the authentication rules for a given context name.
    pub fn methods_for(&self, context: &str) -> MethodRule {
        let (methods, factors, reverify_after) = match self {
            Policy::Effective(eff) => {
                if let Some(ctx) = eff.layer.context.get(context) {
                    (
                        ctx.methods.clone(),
                        ctx.factors.unwrap_or(1),
                        ctx.reverify_after.clone(),
                    )
                } else {
                    (vec!["pin".to_string()], 1, None)
                }
            }
            Policy::PinOnly(_) => (vec!["pin".to_string()], 1, None),
        };

        let unsatisfiable = factors > methods.len() as u32;

        MethodRule {
            methods,
            factors,
            reverify_after,
            unsatisfiable,
        }
    }

    /// Returns the decision for a given relying party ID.
    pub fn decision_for(&self, rp_id: &str) -> RpDecision {
        match self {
            Policy::PinOnly(pin) => RpDecision {
                provider: pin.rp_provider,
                prompt: pin.rp_prompt,
                factors: pin.rp_factors,
                require_second_credential: false,
            },
            Policy::Effective(eff) => {
                let normalized_id = rp_id.to_ascii_lowercase();
                let normalized_id = normalized_id.strip_suffix('.').unwrap_or(&normalized_id);

                // Find all matching classes and their best pattern specificity
                let mut matches: Vec<(&RpClassPolicy, usize)> = Vec::new();

                for class in eff.layer.rp_class.values() {
                    let mut best_specificity = None;

                    for pattern in &class.match_patterns {
                        if pattern == normalized_id {
                            // Exact match: highest specificity
                            best_specificity = Some(pattern.len() + 1);
                            break;
                        } else if let Some(domain) = pattern.strip_prefix("*.") {
                            if normalized_id.ends_with(domain) && normalized_id.len() > domain.len()
                            {
                                // Ensure the character before the domain is a dot to prevent lookalike suffix matches
                                // e.g., "evilbank.example" should not match "*.bank.example"
                                let prefix_len = normalized_id.len() - domain.len();
                                if normalized_id.as_bytes()[prefix_len - 1] == b'.' {
                                    // Wildcard match: specificity is the length of the domain part
                                    let spec = domain.len();
                                    if best_specificity.is_none_or(|s| spec > s) {
                                        best_specificity = Some(spec);
                                    }
                                }
                            }
                        }
                    }

                    if let Some(spec) = best_specificity {
                        matches.push((class, spec));
                    }
                }

                if matches.is_empty() {
                    return RpDecision {
                        provider: RpProvider::Any,
                        prompt: RpPrompt::Presence,
                        factors: 1,
                        require_second_credential: false,
                    };
                }

                // Sort by specificity descending
                matches.sort_by_key(|a| std::cmp::Reverse(a.1));
                let max_spec = matches[0].1;

                // Take all classes that share the highest specificity
                let top_classes: Vec<&RpClassPolicy> = matches
                    .iter()
                    .take_while(|(_, spec)| *spec == max_spec)
                    .map(|(class, _)| *class)
                    .collect();

                // Merge top classes
                let mut provider = RpProvider::Any;
                let mut prompt = RpPrompt::Presence;
                let mut factors = 0;
                let mut require_second_credential = false;

                for class in &top_classes {
                    // Provider: tpm > keepassxc > any
                    let p = class.provider.unwrap_or(RpProvider::Any);
                    provider = match (provider, p) {
                        (RpProvider::Tpm, _) | (_, RpProvider::Tpm) => RpProvider::Tpm,
                        (RpProvider::Keepassxc, _) | (_, RpProvider::Keepassxc) => {
                            RpProvider::Keepassxc
                        }
                        _ => RpProvider::Any,
                    };

                    // Prompt: reverify > presence > none
                    let pr = class.prompt.unwrap_or(RpPrompt::Presence);
                    prompt = match (prompt, pr) {
                        (RpPrompt::Reverify, _) | (_, RpPrompt::Reverify) => RpPrompt::Reverify,
                        (RpPrompt::Presence, _) | (_, RpPrompt::Presence) => RpPrompt::Presence,
                        _ => RpPrompt::None,
                    };

                    // Factors: max
                    factors = factors.max(class.factors.unwrap_or(1));

                    // Second credential: any true
                    if class.require_second_credential.unwrap_or(false) {
                        require_second_credential = true;
                    }
                }

                RpDecision {
                    provider,
                    prompt,
                    factors,
                    require_second_credential,
                }
            }
        }
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
        // Manually construct PinOnly to avoid needing to mock load()
        let pol = Policy::PinOnly(crate::policy::load::PinOnly {
            layer: crate::policy::defaults::default_layer(),
            rp_provider: RpProvider::Tpm,
            rp_prompt: RpPrompt::Reverify,
            rp_factors: 1,
            reason: "test".to_string(),
        });

        let dec = pol.decision_for("any.com");
        assert_eq!(dec.provider, RpProvider::Tpm);
        assert_eq!(dec.prompt, RpPrompt::Reverify);
        assert_eq!(dec.factors, 1);

        let rule = pol.methods_for("sudo");
        assert_eq!(rule.methods, vec!["pin".to_string()]);
        assert_eq!(rule.factors, 1);
    }
}
//! Querying the effective policy for context methods and relying-party decisions.
//!
//! This module provides the mechanism to ask the loaded `Policy` which methods
//! and factors are required for a given context, and what the decision is for
//! a given relying party.

use crate::policy::load::Policy;
use crate::policy::schema::{Duration, RpClassPolicy, RpPrompt, RpProvider};

/// The rules for authentication in a specific context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodRule {
    /// The allowed methods.
    pub methods: Vec<String>,
    /// The number of factors required.
    pub factors: u32,
    /// How long the authentication remains valid.
    pub reverify_after: Option<Duration>,
    /// Whether the rule is unsatisfiable (factors > methods.len()).
    pub unsatisfiable: bool,
}

/// The decision for a specific relying party.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpDecision {
    /// The provider for the passkey.
    pub provider: RpProvider,
    /// The prompt for the user.
    pub prompt: RpPrompt,
    /// The number of factors required.
    pub factors: u32,
    /// Whether a second credential is required.
    pub require_second_credential: bool,
}

impl Policy {
    /// Returns the authentication rules for a given context name.
    pub fn methods_for(&self, context: &str) -> MethodRule {
        let (methods, factors, reverify_after) = match self {
            Policy::Effective(eff) => {
                if let Some(ctx) = eff.layer.context.get(context) {
                    (
                        ctx.methods.clone(),
                        ctx.factors.unwrap_or(1),
                        ctx.reverify_after.clone(),
                    )
                } else {
                    (vec!["pin".to_string()], 1, None)
                }
            }
            Policy::PinOnly(_) => (vec!["pin".to_string()], 1, None),
        };

        let unsatisfiable = factors > methods.len() as u32;

        MethodRule {
            methods,
            factors,
            reverify_after,
            unsatisfiable,
        }
    }

    /// Returns the decision for a given relying party ID.
    pub fn decision_for(&self, rp_id: &str) -> RpDecision {
        match self {
            Policy::PinOnly(pin) => RpDecision {
                provider: pin.rp_provider,
                prompt: pin.rp_prompt,
                factors: pin.rp_factors,
                require_second_credential: false,
            },
            Policy::Effective(eff) => {
                let normalized_id = rp_id.to_ascii_lowercase();
                let normalized_id = normalized_id.strip_suffix('.').unwrap_or(&normalized_id);

                // Find all matching classes and their best pattern specificity
                let mut matches: Vec<(&RpClassPolicy, usize)> = Vec::new();

                for class in eff.layer.rp_class.values() {
                    let mut best_specificity = None;

                    for pattern in &class.match_patterns {
                        if pattern == normalized_id {
                            // Exact match: highest specificity
                            best_specificity = Some(pattern.len() + 1);
                            break;
                        } else if let Some(domain) = pattern.strip_prefix("*.") {
                            if normalized_id.ends_with(domain) && normalized_id.len() > domain.len()
                            {
                                // Ensure the character before the domain is a dot to prevent lookalike suffix matches
                                // e.g., "evilbank.example" should not match "*.bank.example"
                                let prefix_len = normalized_id.len() - domain.len();
                                if normalized_id.as_bytes()[prefix_len - 1] == b'.' {
                                    // Wildcard match: specificity is the length of the domain part
                                    let spec = domain.len();
                                    if best_specificity.map_or(true, |s| spec > s) {
                                        best_specificity = Some(spec);
                                    }
                                }
                            }
                        }
                    }

                    if let Some(spec) = best_specificity {
                        matches.push((class, spec));
                    }
                }

                if matches.is_empty() {
                    return RpDecision {
                        provider: RpProvider::Any,
                        prompt: RpPrompt::Presence,
                        factors: 1,
                        require_second_credential: false,
                    };
                }

                // Sort by specificity descending
                matches.sort_by(|a, b| b.1.cmp(&a.1));
                let max_spec = matches[0].1;

                // Take all classes that share the highest specificity
                let top_classes: Vec<&RpClassPolicy> = matches
                    .iter()
                    .take_while(|(_, spec)| *spec == max_spec)
                    .map(|(class, _)| *class)
                    .collect();

                // Merge top classes
                let mut provider = RpProvider::Any;
                let mut prompt = RpPrompt::Presence;
                let mut factors = 0;
                let mut require_second_credential = false;

                for class in &top_classes {
                    // Provider: tpm > keepassxc > any
                    let p = class.provider.unwrap_or(RpProvider::Any);
                    provider = match (provider, p) {
                        (RpProvider::Tpm, _) | (_, RpProvider::Tpm) => RpProvider::Tpm,
                        (RpProvider::Keepassxc, _) | (_, RpProvider::Keepassxc) => {
                            RpProvider::Keepassxc
                        }
                        _ => RpProvider::Any,
                    };

                    // Prompt: reverify > presence > none
                    let pr = class.prompt.unwrap_or(RpPrompt::Presence);
                    prompt = match (prompt, pr) {
                        (RpPrompt::Reverify, _) | (_, RpPrompt::Reverify) => RpPrompt::Reverify,
                        (RpPrompt::Presence, _) | (_, RpPrompt::Presence) => RpPrompt::Presence,
                        _ => RpPrompt::None,
                    };

                    // Factors: max
                    factors = factors.max(class.factors.unwrap_or(1));

                    // Second credential: any true
                    if class.require_second_credential.unwrap_or(false) {
                        require_second_credential = true;
                    }
                }

                RpDecision {
                    provider,
                    prompt,
                    factors,
                    require_second_credential,
                }
            }
        }
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
        assert_eq!(dec.require_second_credential, false);
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
        assert_eq!(dec.require_second_credential, false);
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
        // Manually construct PinOnly to avoid needing to mock load()
        let pol = Policy::PinOnly(crate::policy::load::PinOnly {
            layer: crate::policy::defaults::default_layer(),
            rp_provider: RpProvider::Tpm,
            rp_prompt: RpPrompt::Reverify,
            rp_factors: 1,
            reason: "test".to_string(),
        });

        let dec = pol.decision_for("any.com");
        assert_eq!(dec.provider, RpProvider::Tpm);
        assert_eq!(dec.prompt, RpPrompt::Reverify);
        assert_eq!(dec.factors, 1);

        let rule = pol.methods_for("sudo");
        assert_eq!(rule.methods, vec!["pin".to_string()]);
        assert_eq!(rule.factors, 1);
    }
}
