//! Policy invariants: the rules that hold for every effective policy, whatever
//! the layers say. `merge` applies them as its last step, so every caller of
//! `merge` gets a policy in which the PIN is always allowed, biometrics off means
//! PIN only, and a PIN rule no PIN can meet is reported instead of returned.

use crate::policy::merge::Effective;
use crate::policy::restrict::Contradiction;

/// Applies the invariants to an effective policy, in this order:
///
/// 1. `pin.max_length` below `pin.min_length` is `MaxLengthBelowMinLength`.
/// 2. `digits`, `lowercase`, `uppercase` and `special` all `"disallowed"` is
///    `AllClassesDisallowed`.
/// 3. `methods.biometrics_allowed = false` removes `"fingerprint"` and `"face"`
///    from every context (`biometrics_disabled_leaves_only_pin`).
/// 4. Every context allows `"pin"`; where it is missing it is added as the first
///    method (`pin_is_always_allowed`, invariant 1).
/// 5. `factors` stay as merged, even when `pin` is the only method left: the
///    context is then unsatisfiable rather than weakened
///    (`two_factors_with_only_pin_keep_two_factors`, invariant 3).
///
/// `managed` is not changed. Without a `[pin]` table rules 1 and 2 have nothing
/// to check (`missing_pin_table_is_not_a_contradiction`).
///
/// # Errors
///
/// `Contradiction::MaxLengthBelowMinLength` or `Contradiction::AllClassesDisallowed`
/// when the merged PIN rule cannot be met (`contradictory_merge_is_reported`).
pub fn apply_invariants(mut effective: Effective) -> Result<Effective, Contradiction> {
    if let Some(pin) = &effective.layer.pin {
        if let (Some(max), Some(min)) = (pin.max_length, pin.min_length) {
            if max < min {
                return Err(Contradiction::MaxLengthBelowMinLength);
            }
        }
        let classes = [&pin.digits, &pin.lowercase, &pin.uppercase, &pin.special];
        if classes.iter().all(|c| c.as_deref() == Some("disallowed")) {
            return Err(Contradiction::AllClassesDisallowed);
        }
    }

    // 3 & 4. Biometrics and PIN fallback
    let biometrics_allowed = effective
        .layer
        .methods
        .as_ref()
        .is_none_or(|m| m.biometrics_allowed.unwrap_or(true));

    for context in effective.layer.context.values_mut() {
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
    use crate::policy::schema::{parse_layer, Layer};

    #[test]
    fn pin_is_always_allowed() {
        let admin_toml = r#"
[context.sudo]
methods = ["face"]
"#;
        let admin = parse_layer(admin_toml).unwrap();
        let effective = merge(&[admin], None).unwrap();
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
        let effective = merge(&[admin], None).unwrap();
        let sudo = &effective.layer.context["sudo"];
        assert_eq!(sudo.methods, vec!["pin".to_string()]);
    }

    #[test]
    fn contradictory_merge_is_reported() {
        // Max length < Min length
        {
            let admin = parse_layer("[pin]\nmax_length = 8").unwrap();
            let user = parse_layer("[pin]\nmin_length = 10").unwrap();
            let res = merge(&[admin], Some(&user));
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
    fn missing_pin_table_is_not_a_contradiction() {
        let effective = Effective {
            layer: Layer::default(),
            managed: Default::default(),
            user_rp_class: Default::default(),
        };
        assert_eq!(apply_invariants(effective.clone()), Ok(effective));
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
        let effective = merge(&[admin], None).unwrap();
        let sudo = &effective.layer.context["sudo"];
        assert_eq!(sudo.methods, vec!["pin".to_string()]);
        assert_eq!(sudo.factors, Some(2));
    }
}
