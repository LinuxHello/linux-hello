//! Restrictiveness: combines two policy layers key by key into the more
//! restrictive one, and reports a character class one layer requires and the
//! other disallows. `merge` (a later issue) uses it to combine the admin layers
//! and to let a user layer tighten the defaults. Rules:
//! `docs/architecture/policy-semantics.md`, *Restrictiveness*.

use crate::policy::schema::{
    ContextPolicy, Layer, MethodsPolicy, PinPolicy, RpClassPolicy, RpPrompt, RpProvider,
};

/// A set of policy rules no PIN or method can satisfy. Never resolved silently:
/// the caller fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Contradiction {
    /// A character class (digits, lowercase, uppercase, special) is required in one
    /// layer and disallowed in the other.
    ClassConflict(&'static str),
    /// The merged `max_length` is below the merged `min_length`. Reported after
    /// merging, not by `most_restrictive`.
    MaxLengthBelowMinLength,
    /// All four character classes are `disallowed`. Reported after merging, not
    /// by `most_restrictive`.
    AllClassesDisallowed,
}

/// Combines two policy layers key by key into the more restrictive one.
///
/// A key, table, context or relying-party class set in only one layer is kept
/// as is. A key set in both gets the more restrictive value, as
/// `policy-semantics.md` defines it: larger lengths, history, lockout time and
/// factors; smaller maximum length, expiry, lockout attempts and reverify time;
/// a character class `required` or `disallowed` over `allowed`; biometrics off;
/// IR, hardware TPM and a second credential required; methods intersected in
/// `a`'s order; provider `tpm` over `keepassxc` over `any`; prompt `reverify`
/// over `presence` over `none`; `match` patterns united, `a`'s first.
///
/// # Errors
///
/// Returns `Err(Contradiction::ClassConflict)` if a character class is required
/// in one layer and disallowed in the other.
pub fn most_restrictive(a: &Layer, b: &Layer) -> Result<Layer, Contradiction> {
    let mut combined = Layer::default();

    // 1. Combine PinPolicy
    match (&a.pin, &b.pin) {
        (Some(p1), Some(p2)) => {
            let pin = PinPolicy {
                min_length: match (p1.min_length, p2.min_length) {
                    (Some(v1), Some(v2)) => Some(v1.max(v2)),
                    (Some(v), None) | (None, Some(v)) => Some(v),
                    (None, None) => None,
                },
                max_length: match (p1.max_length, p2.max_length) {
                    (Some(v1), Some(v2)) => Some(v1.min(v2)),
                    (Some(v), None) | (None, Some(v)) => Some(v),
                    (None, None) => None,
                },
                digits: combine_classes("digits", &p1.digits, &p2.digits)?,
                lowercase: combine_classes("lowercase", &p1.lowercase, &p2.lowercase)?,
                uppercase: combine_classes("uppercase", &p1.uppercase, &p2.uppercase)?,
                special: combine_classes("special", &p1.special, &p2.special)?,
                history: match (p1.history, p2.history) {
                    (Some(v1), Some(v2)) => Some(v1.max(v2)),
                    (Some(v), None) | (None, Some(v)) => Some(v),
                    (None, None) => None,
                },
                expiry_days: match (p1.expiry_days, p2.expiry_days) {
                    (Some(v1), Some(v2)) => Some(v1.min(v2)),
                    (Some(v), None) | (None, Some(v)) => Some(v),
                    (None, None) => None,
                },
                lockout_attempts: match (p1.lockout_attempts, p2.lockout_attempts) {
                    (Some(v1), Some(v2)) => Some(v1.min(v2)),
                    (Some(v), None) | (None, Some(v)) => Some(v),
                    (None, None) => None,
                },
                lockout_minutes: match (p1.lockout_minutes, p2.lockout_minutes) {
                    (Some(v1), Some(v2)) => Some(v1.max(v2)),
                    (Some(v), None) | (None, Some(v)) => Some(v),
                    (None, None) => None,
                },
            };
            combined.pin = Some(pin);
        }
        (Some(p), None) | (None, Some(p)) => combined.pin = Some(p.clone()),
        (None, None) => {}
    }

    // 2. Combine MethodsPolicy
    match (&a.methods, &b.methods) {
        (Some(m1), Some(m2)) => {
            combined.methods = Some(MethodsPolicy {
                biometrics_allowed: match (m1.biometrics_allowed, m2.biometrics_allowed) {
                    (Some(v1), Some(v2)) => Some(v1 && v2),
                    (Some(v), None) | (None, Some(v)) => Some(v),
                    (None, None) => None,
                },
                face_requires_ir: match (m1.face_requires_ir, m2.face_requires_ir) {
                    (Some(v1), Some(v2)) => Some(v1 || v2),
                    (Some(v), None) | (None, Some(v)) => Some(v),
                    (None, None) => None,
                },
                require_hardware_tpm: match (m1.require_hardware_tpm, m2.require_hardware_tpm) {
                    (Some(v1), Some(v2)) => Some(v1 || v2),
                    (Some(v), None) | (None, Some(v)) => Some(v),
                    (None, None) => None,
                },
            });
        }
        (Some(m), None) | (None, Some(m)) => combined.methods = Some(m.clone()),
        (None, None) => {}
    }

    // 3. Combine ContextPolicy: start from b's contexts, so a name only b has is kept
    // as is; then each of a's names is kept as is or combined with b's.
    combined.context = b.context.clone();
    for (name, c1) in &a.context {
        match b.context.get(name) {
            Some(c2) => {
                // Intersection, in a's order.
                let methods: Vec<String> = c1
                    .methods
                    .iter()
                    .filter(|m| c2.methods.contains(m))
                    .cloned()
                    .collect();

                let factors = match (c1.factors, c2.factors) {
                    (Some(f1), Some(f2)) => Some(f1.max(f2)),
                    (Some(f), None) | (None, Some(f)) => Some(f),
                    (None, None) => None,
                };

                let reverify_after = match (c1.reverify_after.as_ref(), c2.reverify_after.as_ref())
                {
                    (Some(r1), Some(r2)) => {
                        if r1.total_seconds() < r2.total_seconds() {
                            Some(r1.clone())
                        } else {
                            Some(r2.clone())
                        }
                    }
                    (Some(r), None) | (None, Some(r)) => Some(r.clone()),
                    (None, None) => None,
                };

                combined.context.insert(
                    name.clone(),
                    ContextPolicy {
                        methods,
                        factors,
                        reverify_after,
                    },
                );
            }
            None => {
                combined.context.insert(name.clone(), c1.clone());
            }
        }
    }

    // 4. Combine RpClassPolicy, the same way as contexts.
    combined.rp_class = b.rp_class.clone();
    for (name, r1) in &a.rp_class {
        match b.rp_class.get(name) {
            Some(r2) => {
                let mut match_patterns = r1.match_patterns.clone();
                for p in &r2.match_patterns {
                    if !match_patterns.contains(p) {
                        match_patterns.push(p.clone());
                    }
                }

                let provider = match (r1.provider, r2.provider) {
                    (Some(p1), Some(p2)) => {
                        if p1 == RpProvider::Tpm || p2 == RpProvider::Tpm {
                            Some(RpProvider::Tpm)
                        } else if p1 == RpProvider::Keepassxc || p2 == RpProvider::Keepassxc {
                            Some(RpProvider::Keepassxc)
                        } else {
                            Some(RpProvider::Any)
                        }
                    }
                    (Some(p), None) | (None, Some(p)) => Some(p),
                    (None, None) => None,
                };

                let prompt = match (r1.prompt, r2.prompt) {
                    (Some(p1), Some(p2)) => {
                        if p1 == RpPrompt::Reverify || p2 == RpPrompt::Reverify {
                            Some(RpPrompt::Reverify)
                        } else if p1 == RpPrompt::Presence || p2 == RpPrompt::Presence {
                            Some(RpPrompt::Presence)
                        } else {
                            Some(RpPrompt::None)
                        }
                    }
                    (Some(p), None) | (None, Some(p)) => Some(p),
                    (None, None) => None,
                };

                let factors = match (r1.factors, r2.factors) {
                    (Some(f1), Some(f2)) => Some(f1.max(f2)),
                    (Some(f), None) | (None, Some(f)) => Some(f),
                    (None, None) => None,
                };

                let require_second_credential =
                    match (r1.require_second_credential, r2.require_second_credential) {
                        (Some(v1), Some(v2)) => Some(v1 || v2),
                        (Some(v), None) | (None, Some(v)) => Some(v),
                        (None, None) => None,
                    };

                combined.rp_class.insert(
                    name.clone(),
                    RpClassPolicy {
                        match_patterns,
                        provider,
                        prompt,
                        factors,
                        require_second_credential,
                    },
                );
            }
            None => {
                combined.rp_class.insert(name.clone(), r1.clone());
            }
        }
    }

    Ok(combined)
}

/// Combines one character class (`name`) of two layers: equal values stay,
/// `required` or `disallowed` beats `allowed`, and a value set in one layer only
/// is kept.
///
/// # Errors
///
/// `Contradiction::ClassConflict(name)` when one layer requires the class and the
/// other disallows it (`required_against_disallowed_is_a_conflict`).
fn combine_classes<'a>(
    name: &'static str,
    a: &'a Option<String>,
    b: &'a Option<String>,
) -> Result<Option<String>, Contradiction> {
    match (a, b) {
        (Some(v1), Some(v2)) if v1 == v2 => Ok(Some(v1.clone())),
        (Some(v1), Some(v2))
            if (v1 == "required" && v2 == "disallowed")
                || (v1 == "disallowed" && v2 == "required") =>
        {
            Err(Contradiction::ClassConflict(name))
        }
        (Some(v1), Some(v2)) if v1 == "required" || v2 == "required" => {
            Ok(Some("required".to_string()))
        }
        (Some(v1), Some(v2)) if v1 == "disallowed" || v2 == "disallowed" => {
            Ok(Some("disallowed".to_string()))
        }
        (Some(v1), Some(_)) => Ok(Some(v1.clone())),
        (Some(v1), None) | (None, Some(v1)) => Ok(Some(v1.clone())),
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::schema::parse_layer;

    #[test]
    fn conflicting_admin_files_resolve_to_most_restrictive() {
        let check = |a_toml: &str, b_toml: &str, expected_toml: &str| {
            let a = parse_layer(a_toml).unwrap();
            let b = parse_layer(b_toml).unwrap();
            let res = most_restrictive(&a, &b).unwrap();
            let expected = parse_layer(expected_toml).unwrap();
            assert_eq!(res, expected, "{a_toml} with {b_toml}");
            let res_rev = most_restrictive(&b, &a).unwrap();
            assert_eq!(res_rev, expected, "{b_toml} with {a_toml}");
        };

        // Larger
        check(
            "[pin]\nmin_length = 8",
            "[pin]\nmin_length = 10",
            "[pin]\nmin_length = 10",
        );
        check(
            "[pin]\nhistory = 3",
            "[pin]\nhistory = 5",
            "[pin]\nhistory = 5",
        );
        check(
            "[pin]\nlockout_minutes = 15",
            "[pin]\nlockout_minutes = 60",
            "[pin]\nlockout_minutes = 60",
        );
        check(
            "[context.sudo]\nmethods = [\"pin\"]\nfactors = 1",
            "[context.sudo]\nmethods = [\"pin\"]\nfactors = 2",
            "[context.sudo]\nmethods = [\"pin\"]\nfactors = 2",
        );
        check(
            "[rp_class.example]\nmatch = [\"a.example\"]\nfactors = 1",
            "[rp_class.example]\nmatch = [\"a.example\"]\nfactors = 2",
            "[rp_class.example]\nmatch = [\"a.example\"]\nfactors = 2",
        );

        // Smaller
        check(
            "[pin]\nmax_length = 64",
            "[pin]\nmax_length = 32",
            "[pin]\nmax_length = 32",
        );
        check(
            "[pin]\nexpiry_days = 365",
            "[pin]\nexpiry_days = 90",
            "[pin]\nexpiry_days = 90",
        );
        check(
            "[pin]\nlockout_attempts = 10",
            "[pin]\nlockout_attempts = 5",
            "[pin]\nlockout_attempts = 5",
        );
        check(
            "[context.unlock]\nmethods = [\"pin\"]\nreverify_after = \"8h\"",
            "[context.unlock]\nmethods = [\"pin\"]\nreverify_after = \"30m\"",
            "[context.unlock]\nmethods = [\"pin\"]\nreverify_after = \"30m\"",
        );

        // Classes
        check(
            "[pin]\ndigits = \"allowed\"",
            "[pin]\ndigits = \"required\"",
            "[pin]\ndigits = \"required\"",
        );
        check(
            "[pin]\nspecial = \"allowed\"",
            "[pin]\nspecial = \"disallowed\"",
            "[pin]\nspecial = \"disallowed\"",
        );
        check(
            "[pin]\nlowercase = \"allowed\"",
            "[pin]\nlowercase = \"allowed\"",
            "[pin]\nlowercase = \"allowed\"",
        );

        // Booleans
        check(
            "[methods]\nbiometrics_allowed = true",
            "[methods]\nbiometrics_allowed = false",
            "[methods]\nbiometrics_allowed = false",
        );
        check(
            "[methods]\nface_requires_ir = false",
            "[methods]\nface_requires_ir = true",
            "[methods]\nface_requires_ir = true",
        );
        check(
            "[methods]\nrequire_hardware_tpm = false",
            "[methods]\nrequire_hardware_tpm = true",
            "[methods]\nrequire_hardware_tpm = true",
        );
        check(
            "[rp_class.example]\nmatch = [\"a.com\"]\nrequire_second_credential = false",
            "[rp_class.example]\nmatch = [\"a.com\"]\nrequire_second_credential = true",
            "[rp_class.example]\nmatch = [\"a.com\"]\nrequire_second_credential = true",
        );
        check(
            "[rp_class.example]\nmatch = [\"a.com\"]\nrequire_second_credential = false",
            "[rp_class.example]\nmatch = [\"a.com\"]\nrequire_second_credential = false",
            "[rp_class.example]\nmatch = [\"a.com\"]\nrequire_second_credential = false",
        );

        // Methods, Provider, Prompt, Match
        check(
            "[context.sudo]\nmethods = [\"pin\", \"fingerprint\", \"face\"]",
            "[context.sudo]\nmethods = [\"pin\", \"face\"]",
            "[context.sudo]\nmethods = [\"pin\", \"face\"]",
        );
        check(
            "[rp_class.example]\nmatch = [\"a.com\"]\nprovider = \"any\"",
            "[rp_class.example]\nmatch = [\"a.com\"]\nprovider = \"tpm\"",
            "[rp_class.example]\nmatch = [\"a.com\"]\nprovider = \"tpm\"",
        );
        check(
            "[rp_class.example]\nmatch = [\"a.com\"]\nprovider = \"keepassxc\"",
            "[rp_class.example]\nmatch = [\"a.com\"]\nprovider = \"any\"",
            "[rp_class.example]\nmatch = [\"a.com\"]\nprovider = \"keepassxc\"",
        );
        check(
            "[rp_class.example]\nmatch = [\"a.com\"]\nprompt = \"none\"",
            "[rp_class.example]\nmatch = [\"a.com\"]\nprompt = \"presence\"",
            "[rp_class.example]\nmatch = [\"a.com\"]\nprompt = \"presence\"",
        );
        check(
            "[rp_class.example]\nmatch = [\"a.com\"]\nprompt = \"reverify\"",
            "[rp_class.example]\nmatch = [\"a.com\"]\nprompt = \"presence\"",
            "[rp_class.example]\nmatch = [\"a.com\"]\nprompt = \"reverify\"",
        );

        // Match: the union keeps the first argument's patterns first.
        let a = parse_layer("[rp_class.example]\nmatch = [\"a.example\"]").unwrap();
        let b = parse_layer("[rp_class.example]\nmatch = [\"b.example\", \"a.example\"]").unwrap();
        let ab = most_restrictive(&a, &b).unwrap();
        assert_eq!(
            ab.rp_class["example"].match_patterns,
            vec!["a.example", "b.example"]
        );
        let ba = most_restrictive(&b, &a).unwrap();
        assert_eq!(
            ba.rp_class["example"].match_patterns,
            vec!["b.example", "a.example"]
        );
    }

    #[test]
    fn key_set_in_one_layer_only_is_kept() {
        let a_toml = "[pin]\nexpiry_days = 90";
        let b_toml = "[pin]\nmin_length = 8\n[context.login]\nmethods = [\"pin\"]\n[rp_class.example]\nmatch = [\"a.com\"]";
        let a = parse_layer(a_toml).unwrap();
        let b = parse_layer(b_toml).unwrap();

        for res in [
            most_restrictive(&a, &b).unwrap(),
            most_restrictive(&b, &a).unwrap(),
        ] {
            assert_eq!(res.pin.as_ref().unwrap().expiry_days, Some(90));
            assert_eq!(res.pin.as_ref().unwrap().min_length, Some(8));
            assert_eq!(res.context, b.context);
            assert_eq!(res.rp_class, b.rp_class);
        }
    }

    #[test]
    fn required_against_disallowed_is_a_conflict() {
        let a_toml = "[pin]\nuppercase = \"required\"";
        let b_toml = "[pin]\nuppercase = \"disallowed\"";
        let a = parse_layer(a_toml).unwrap();
        let b = parse_layer(b_toml).unwrap();
        let conflict = Err(Contradiction::ClassConflict("uppercase"));
        assert_eq!(most_restrictive(&a, &b), conflict);
        assert_eq!(most_restrictive(&b, &a), conflict);
    }
}
