//! The policy merging logic.
//!
//! This module provides the mechanism to combine multiple policy layers
//! (admin, user, and default) into a single effective policy.

use crate::policy::defaults::default_layer;
use crate::policy::restrict::{most_restrictive, Contradiction};
use crate::policy::schema::Layer;
use std::collections::BTreeSet;

/// The effective policy resulting from merging admin and user layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    /// Every effective value.
    pub layer: Layer,
    /// The keys an admin set, as paths (e.g., `pin.min_length`).
    pub managed: BTreeSet<String>,
}

/// Merges admin and user policy layers into an effective policy.
///
/// 1. Admin layers are combined using `most_restrictive`, starting from `Layer::default()`.
/// 2. The user layer is merged with the default layer using `most_restrictive`.
/// 3. Admin settings override the combined default/user layer.
pub fn merge(admin: &[Layer], user: Option<&Layer>) -> Result<Effective, Contradiction> {
    // 1. Combine admin layers
    let mut admin_combined = Layer::default();
    for layer in admin {
        admin_combined = most_restrictive(&admin_combined, layer)?;
    }

    // 2. Combine default and user
    let default = default_layer();
    let user_layer = user.cloned().unwrap_or_default();
    let base = most_restrictive(&default, &user_layer)?;

    // 3. Apply admin overrides
    let mut effective_layer = base.clone();
    let mut managed = BTreeSet::new();

    apply_admin_overrides(&mut effective_layer, &admin_combined, &mut managed)?;

    Ok(Effective {
        layer: effective_layer,
        managed,
    })
}

/// Applies overrides from the admin layer to the target layer, recording managed paths.
fn apply_admin_overrides(
    target: &mut Layer,
    admin: &Layer,
    managed: &mut BTreeSet<String>,
) -> Result<(), Contradiction> {
    // PIN overrides
    if let Some(admin_pin) = &admin.pin {
        // If admin_pin is just Default (all None), it sets nothing.
        // However, the logic for "what an admin sets" might be slightly more nuanced.
        // The brief says: "An admin [pin] that sets only min_length leaves every other PIN key at base's value."
        // This means we only apply fields that are Some.

        if let Some(target_pin) = &mut target.pin {
            if let Some(v) = admin_pin.min_length {
                target_pin.min_length = Some(v);
                managed.insert("pin.min_length".to_string());
            }
            if let Some(v) = admin_pin.max_length {
                target_pin.max_length = Some(v);
                managed.insert("pin.max_length".to_string());
            }
            if let Some(v) = &admin_pin.digits {
                target_pin.digits = Some(v.clone());
                managed.insert("pin.digits".to_string());
            }
            if let Some(v) = &admin_pin.lowercase {
                target_pin.lowercase = Some(v.clone());
                managed.insert("pin.lowercase".to_string());
            }
            if let Some(v) = &admin_pin.uppercase {
                target_pin.uppercase = Some(v.clone());
                managed.insert("pin.uppercase".to_string());
            }
            if let Some(v) = &admin_pin.special {
                target_pin.special = Some(v.clone());
                managed.insert("pin.special".to_string());
            }
            if let Some(v) = admin_pin.history {
                target_pin.history = Some(v);
                managed.insert("pin.history".to_string());
            }
            if let Some(v) = admin_pin.expiry_days {
                target_pin.expiry_days = Some(v);
                managed.insert("pin.expiry_days".to_string());
            }
            if let Some(v) = admin_pin.lockout_attempts {
                target_pin.lockout_attempts = Some(v);
                managed.insert("pin.lockout_attempts".to_string());
            }
            if let Some(v) = admin_pin.lockout_minutes {
                target_pin.lockout_minutes = Some(v);
                managed.insert("pin.lockout_minutes".to_string());
            }
        } else {
            // Admin sets a PIN policy where there wasn't one before.
            // But default_layer() always has a PIN policy.
            // If the base doesn't have one (it shouldn't, since default_layer has one),
            // we'd need to create it.
            target.pin = Some(admin_pin.clone());
            managed.insert("pin".to_string()); // Simplification, but shouldn't happen.
        }
    }

    // Methods overrides
    if let Some(admin_methods) = &admin.methods {
        if let Some(target_methods) = &mut target.methods {
            if let Some(v) = admin_methods.biometrics_allowed {
                target_methods.biometrics_allowed = Some(v);
                managed.insert("methods.biometrics_allowed".to_string());
            }
            if let Some(v) = admin_methods.face_requires_ir {
                target_methods.face_requires_ir = Some(v);
                managed.insert("methods.face_requires_ir".to_string());
            }
            if let Some(v) = admin_methods.require_hardware_tpm {
                target_methods.require_hardware_tpm = Some(v);
                managed.insert("methods.require_hardware_tpm".to_string());
            }
        } else {
            target.methods = Some(admin_methods.clone());
            managed.insert("methods".to_string());
        }
    }

    // Context overrides
    for (name, admin_ctx) in &admin.context {
        if let Some(target_ctx) = target.context.get_mut(name) {
            // For context, the admin's values replace base's.
            // But wait, what about "methods"? The brief says:
            // "For every key admin sets: the effective value is the admin's, replacing base's, and its path goes into managed."
            // "Contexts login, unlock, sudo, session: methods ["pin", "fingerprint", "face"], factors 1, reverify_after none."
            // This implies "methods" is a key.

            if !admin_ctx.methods.is_empty() {
                target_ctx.methods = admin_ctx.methods.clone();
                managed.insert(format!("context.{}.methods", name));
            }
            if admin_ctx.factors.is_some() {
                target_ctx.factors = admin_ctx.factors;
                managed.insert(format!("context.{}.factors", name));
            }
            if admin_ctx.reverify_after.is_some() {
                target_ctx.reverify_after = admin_ctx.reverify_after.clone();
                managed.insert(format!("context.{}.reverify_after", name));
            }
        } else {
            // Admin provides a context not in base.
            target.context.insert(name.clone(), admin_ctx.clone());
            managed.insert(format!("context.{}", name));
        }
    }

    // RpClass overrides
    for (name, admin_rp) in &admin.rp_class {
        if let Some(target_rp) = target.rp_class.get_mut(name) {
            if !admin_rp.match_patterns.is_empty() {
                // The brief says: "Exception, rp_class match: the union of the admin's patterns and base's, managed."
                // This is a bit contradictory to "For every key admin sets: the effective value is the admin's...".
                // But it specifically calls out the exception for `match`.
                let mut union_patterns = target_rp.match_patterns.clone();
                for p in &admin_rp.match_patterns {
                    if !union_patterns.contains(p) {
                        union_patterns.push(p.clone());
                    }
                }
                target_rp.match_patterns = union_patterns;
                managed.insert(format!("rp_class.{}.match", name));
            }
            if admin_rp.provider.is_some() {
                target_rp.provider = admin_rp.provider;
                managed.insert(format!("rp_class.{}.provider", name));
            }
            if admin_rp.prompt.is_some() {
                target_rp.prompt = admin_rp.prompt;
                managed.insert(format!("rp_class.{}.prompt", name));
            }
            if admin_rp.factors.is_some() {
                target_rp.factors = admin_rp.factors;
                managed.insert(format!("rp_class.{}.factors", name));
            }
            if admin_rp.require_second_credential.is_some() {
                target_rp.require_second_credential = admin_rp.require_second_credential;
                managed.insert(format!("rp_class.{}.require_second_credential", name));
            }
        } else {
            target.rp_class.insert(name.clone(), admin_rp.clone());
            managed.insert(format!("rp_class.{}", name));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::schema::parse_layer;

    #[test]
    fn no_layers_give_the_defaults() {
        let res = merge(&[], None).unwrap();
        assert_eq!(res.layer, default_layer());
        assert!(res.managed.is_empty());
    }

    #[test]
    fn user_can_tighten_a_default() {
        let user_toml = r#"
[pin]
min_length = 8
"#;
        let user = parse_layer(user_toml).unwrap();
        let res = merge(&[], Some(&user)).unwrap();
        assert_eq!(res.layer.pin.as_ref().unwrap().min_length, Some(8));
        assert!(res.managed.is_empty());
    }

    #[test]
    fn user_cannot_loosen_a_default() {
        let user_toml = r#"
[pin]
min_length = 4
lockout_attempts = 10
"#;
        let user = parse_layer(user_toml).unwrap();
        let res = merge(&[], Some(&user)).unwrap();
        assert_eq!(res.layer.pin.as_ref().unwrap().min_length, Some(6));
        assert_eq!(res.layer.pin.as_ref().unwrap().lockout_attempts, Some(5));
    }

    #[test]
    fn user_cannot_override_admin_setting() {
        let admin_toml = r#"
[pin]
min_length = 4
"#;
        let user_toml = r#"
[pin]
min_length = 8
"#;
        let admin = parse_layer(admin_toml).unwrap();
        let user = parse_layer(user_toml).unwrap();
        let res = merge(&[admin], Some(&user)).unwrap();
        assert_eq!(res.layer.pin.as_ref().unwrap().min_length, Some(4));
        assert!(res.managed.contains("pin.min_length"));
    }

    #[test]
    fn admin_key_leaves_other_defaults_in_place() {
        let admin_toml = r#"
[pin]
min_length = 8
"#;
        let admin = parse_layer(admin_toml).unwrap();
        let res = merge(&[admin], None).unwrap();
        let pin = res.layer.pin.as_ref().unwrap();
        assert_eq!(pin.min_length, Some(8));
        assert_eq!(pin.digits, Some("required".to_string()));
        assert_eq!(pin.max_length, Some(127));
        assert_eq!(pin.lockout_attempts, Some(5));
        assert_eq!(pin.lockout_minutes, Some(15));
        assert_eq!(res.managed, BTreeSet::from(["pin.min_length".to_string()]));
    }

    #[test]
    fn admin_layers_combine_most_restrictive_before_layering() {
        let admin1 = parse_layer("[pin]\nmin_length = 8").unwrap();
        let admin2 = parse_layer("[pin]\nmin_length = 10").unwrap();
        let res = merge(&[admin1, admin2], None).unwrap();
        assert_eq!(res.layer.pin.as_ref().unwrap().min_length, Some(10));
        assert!(res.managed.contains("pin.min_length"));
    }

    #[test]
    fn user_disallowing_a_required_default_is_a_contradiction() {
        let user_toml = r#"
[pin]
digits = "disallowed"
"#;
        let user = parse_layer(user_toml).unwrap();
        let res = merge(&[], Some(&user));
        assert!(matches!(res, Err(Contradiction::ClassConflict("digits"))));
    }
}
