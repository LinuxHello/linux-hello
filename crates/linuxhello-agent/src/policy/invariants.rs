//! Policy invariants.
//!
//! This module enforces core security invariants on the effective policy,
//! ensuring that the PIN is always a valid fallback and that contradictions
//! are reported. It is called by `merge` as the final step.
//!
//! C4 component: `policyEngine`

use crate::policy::merge::Effective;
use crate::policy::restrict::Contradiction;

/// Applies core security invariants to an effective policy.
///
/// 1. If `pin.max_length` < `pin.min_length`: `Err(Contradiction::MaxLengthBelowMinLength)`.
/// 2. If `digits`, `lowercase`, `uppercase` and `special` are all `"disallowed"`: `Err(Contradiction::AllClassesDisallowed)`.
/// 3. If `methods.biometrics_allowed` is false: remove `"fingerprint"` and `"face"` from every context's `methods`.
/// 4. Add `"pin"` to every context's `methods` where it is missing, as the first element.
pub fn apply_invariants(mut effective: Effective) -> Result<Effective, Contradiction> {
    let pin = effective
        .layer
        .pin
        .as_ref()
        .ok_or(Contradiction::AllClassesDisallowed)?;

    // 1. Max length vs Min length
    if let (Some(max), Some(min)) = (pin.max_length, pin.min_length) {
        if max < min {
            return Err(Contradiction::MaxLengthBelowMinLength);
        }
    }

    // 2. All classes disallowed
    let digits_disallowed = pin.digits.as_deref() == Some("disallowed");
    let lowercase_disallowed = pin.lowercase.as_deref() == Some("disallowed");
    let uppercase_disallowed = pin.uppercase.as_deref() == Some("disallowed");
    let special_disallowed = pin.special.as_deref() == Some("disallowed");

    if digits_disallowed && lowercase_disallowed && uppercase_disallowed && special_disallowed {
        return Err(Contradiction::AllClassesDisallowed);
    }

    // 3 & 4. Biometrics and PIN fallback
    let biometrics_allowed = effective
        .layer
        .methods
        .as_ref()
        .is_none_or(|m| m.biometrics_allowed.unwrap_or(true));

    for context in effective.layer.context.values_mut() {
        if !biometrics_allowed {
            // Remove fingerprint and face
            context
                .methods
                .retain(|m| m != "fingerprint" && m != "face");
        }

        // Ensure PIN is present as the first element
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
        let admin_toml = r#"
[context.sudo]
methods = ["face"]
"#;
        let admin = parse_layer(admin_toml).unwrap();
        let res = merge(&[admin], None).unwrap();
        let effective = apply_invariants(res).unwrap();
        let sudo = &effective.layer.context["sudo"];
        assert!(sudo.methods.contains(&"pin".to_string()));
        assert!(sudo.methods.contains(&"face".to_string()));
        assert_eq!(sudo.methods[0], "pin");
    }

    #[test]
    fn biometrics_disabled_leaves_only_pin() {
        let admin_toml = r#"
[methods]
biometrics_allowed = false

[context.sudo]
methods = ["pin", "fingerprint", "face"]
"#;
        let admin = parse_layer(admin_toml).unwrap();
        let res = merge(&[admin], None).unwrap();
        let effective = apply_invariants(res).unwrap();
        let sudo = &effective.layer.context["sudo"];
        assert_eq!(sudo.methods, vec!["pin".to_string()]);
    }

    #[test]
    fn contradictory_merge_is_reported() {
        // Max length < Min length
        {
            let admin1 = parse_layer("[pin]\nmax_length = 8").unwrap();
            let admin2 = parse_layer("[pin]\nmin_length = 10").unwrap();
            let res = merge(&[admin1, admin2], None);
            assert!(matches!(res, Err(Contradiction::MaxLengthBelowMinLength)));
        }

        // All classes disallowed
        {
            let admin = parse_layer(
                r#"
[pin]
digits = "disallowed"
lowercase = "disallowed"
uppercase = "disallowed"
special = "disallowed"
"#,
            )
            .unwrap();
            let res = merge(&[admin], None);
            assert!(matches!(res, Err(Contradiction::AllClassesDisallowed)));
        }

        // Class conflict (handled by merge/most_restrictive)
        {
            let admin1 = parse_layer("[pin]\nuppercase = \"required\"").unwrap();
            let admin2 = parse_layer("[pin]\nuppercase = \"disallowed\"").unwrap();
            let res = merge(&[admin1, admin2], None);
            assert!(matches!(
                res,
                Err(Contradiction::ClassConflict("uppercase"))
            ));
        }
    }

    #[test]
    fn two_factors_with_only_pin_keep_two_factors() {
        let admin_toml = r#"
[methods]
biometrics_allowed = false

[context.sudo]
methods = ["pin", "fingerprint"]
factors = 2
"#;
        let admin = parse_layer(admin_toml).unwrap();
        let res = merge(&[admin], None).unwrap();
        let effective = apply_invariants(res).unwrap();
        let sudo = &effective.layer.context["sudo"];
        assert_eq!(sudo.methods, vec!["pin".to_string()]);
        assert_eq!(sudo.factors, Some(2));
    }
}
