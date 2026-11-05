//! The policy invariants enforcement.
//!
//! This module ensures that the effective policy adheres to core security
//! properties: the PIN is always available, and disabling biometrics
//! correctly restricts contexts to PIN-only. It is called by `merge`.

use crate::policy::merge::Effective;
use crate::policy::restrict::Contradiction;

/// Applies security invariants to an effective policy.
///
/// 1. If `pin.max_length` < `pin.min_length`: `Err(Contradiction::MaxLengthBelowMinLength)`.
/// 2. If `digits`, `lowercase`, `uppercase` and `special` are all `"disallowed"`: `Err(Contradiction::AllClassesDisallowed)`.
/// 3. If `methods.biometrics_allowed` is false: remove `"fingerprint"` and `"face"` from every context's `methods`.
/// 4. Add `"pin"` to every context's `methods` where it is missing, as the first element.
pub fn apply_invariants(mut effective: Effective) -> Result<Effective, Contradiction> {
    let layer = &mut effective.layer;

    // 1. Check PIN length invariant
    if let Some(pin) = &layer.pin {
        if let (Some(min), Some(max)) = (pin.min_length, pin.max_length) {
            if max < min {
                return Err(Contradiction::MaxLengthBelowMinLength);
            }
        }

        // 2. Check character class invariant
        let classes = [&pin.digits, &pin.lowercase, &pin.uppercase, &pin.special];
        if classes.iter().all(|c| c.as_deref() == Some("disallowed")) {
            return Err(Contradiction::AllClassesDisallowed);
        }
    }

    // 3 & 4. Adjust context methods based on biometrics and PIN availability
    let biometrics_allowed = layer
        .methods
        .as_ref()
        .and_then(|m| m.biometrics_allowed)
        .unwrap_or(true);

    for context in layer.context.values_mut() {
        if !biometrics_allowed {
            context
                .methods
                .retain(|m| m != "fingerprint" && m != "face");
        }

        if !context.methods.contains(&"pin".to_string()) {
            context.methods.insert(0, "pin".to_string());
        }
    }

    Ok(effective)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::merge::merge;
    use crate::policy::schema::parse_layer;

    #[test]
    fn pin_is_always_allowed() {
        let admin = parse_layer("[context.sudo]\nmethods = [\"face\"]").unwrap();
        let res = merge(&[admin], None).unwrap();
        let res = apply_invariants(res).unwrap();
        let sudo = res.layer.context.get("sudo").unwrap();
        assert!(sudo.methods.contains(&"pin".to_string()));
        assert!(sudo.methods.contains(&"face".to_string()));
    }

    #[test]
    fn biometrics_disabled_leaves_only_pin() {
        let admin = parse_layer(
            "[methods]\nbiometrics_allowed = false\n[context.login]\nmethods = [\"pin\", \"face\"]",
        )
        .unwrap();
        let res = merge(&[admin], None).unwrap();
        let res = apply_invariants(res).unwrap();
        for context in res.layer.context.values() {
            assert_eq!(context.methods, vec!["pin".to_string()]);
        }
    }

    #[test]
    fn contradictory_merge_is_reported() {
        // MaxLengthBelowMinLength
        let admin = parse_layer("[pin]\nmax_length = 8").unwrap();
        let user = parse_layer("[pin]\nmin_length = 10").unwrap();
        let res = merge(&[admin], Some(&user));
        assert_eq!(res, Err(Contradiction::MaxLengthBelowMinLength));

        // AllClassesDisallowed
        let admin = parse_layer(
            "[pin]\ndigits = \"disallowed\"\nlowercase = \"disallowed\"\nuppercase = \"disallowed\"\nspecial = \"disallowed\"",
        )
        .unwrap();
        let res = merge(&[admin], None);
        assert_eq!(res, Err(Contradiction::AllClassesDisallowed));

        // ClassConflict (via merge, not apply_invariants)
        let admin1 = parse_layer("[pin]\nuppercase = \"required\"").unwrap();
        let admin2 = parse_layer("[pin]\nuppercase = \"disallowed\"").unwrap();
        let res = merge(&[admin1, admin2], None);
        assert_eq!(res, Err(Contradiction::ClassConflict("uppercase")));
    }

    #[test]
    fn two_factors_with_only_pin_keep_two_factors() {
        let admin = parse_layer(
            "[methods]\nbiometrics_allowed = false\n[context.sudo]\nmethods = [\"pin\", \"fingerprint\"]\nfactors = 2",
        )
        .unwrap();
        let res = merge(&[admin], None).unwrap();
        let res = apply_invariants(res).unwrap();
        let sudo = res.layer.context.get("sudo").unwrap();
        assert_eq!(sudo.methods, vec!["pin".to_string()]);
        assert_eq!(sudo.factors, Some(2));
    }
}
