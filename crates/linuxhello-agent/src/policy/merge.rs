//! The policy merging logic.
//!
//! This module provides the mechanism to combine multiple policy layers
//! (admin, user, and default) into a single effective policy.

use crate::policy::defaults::default_layer;
use crate::policy::restrict::{most_restrictive, Contradiction};
use crate::policy::schema::{ContextPolicy, Layer, MethodsPolicy, PinPolicy, RpClassPolicy};
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

    apply_admin_overrides(&mut effective_layer, &admin_combined, &mut managed);

    Ok(Effective {
        layer: effective_layer,
        managed,
    })
}

/// Applies every key the combined admin layer sets to `target`, replacing the
/// base value, and records the key's path in `managed`
/// (`admin_key_leaves_other_defaults_in_place`,
/// `admin_only_rp_class_is_managed_per_key`).
///
/// Key by key: a key the admin leaves unset keeps the base value, so an admin
/// `[pin]` that sets only `min_length` never resets the other PIN keys. A table
/// the base does not have (an rp_class only the admin defines) starts empty and
/// takes the admin's keys, each managed under its own path. An rp_class's `match`
/// is the union of the admin's and the base's patterns, base patterns first.
fn apply_admin_overrides(target: &mut Layer, admin: &Layer, managed: &mut BTreeSet<String>) {
    if let Some(a) = &admin.pin {
        let t = target.pin.get_or_insert_with(empty_pin);
        set(&mut t.min_length, a.min_length, "pin.min_length", managed);
        set(&mut t.max_length, a.max_length, "pin.max_length", managed);
        set(&mut t.digits, a.digits.clone(), "pin.digits", managed);
        set(
            &mut t.lowercase,
            a.lowercase.clone(),
            "pin.lowercase",
            managed,
        );
        set(
            &mut t.uppercase,
            a.uppercase.clone(),
            "pin.uppercase",
            managed,
        );
        set(&mut t.special, a.special.clone(), "pin.special", managed);
        set(&mut t.history, a.history, "pin.history", managed);
        set(
            &mut t.expiry_days,
            a.expiry_days,
            "pin.expiry_days",
            managed,
        );
        set(
            &mut t.lockout_attempts,
            a.lockout_attempts,
            "pin.lockout_attempts",
            managed,
        );
        set(
            &mut t.lockout_minutes,
            a.lockout_minutes,
            "pin.lockout_minutes",
            managed,
        );
    }

    if let Some(a) = &admin.methods {
        let t = target.methods.get_or_insert_with(empty_methods);
        let biometrics = "methods.biometrics_allowed";
        set(
            &mut t.biometrics_allowed,
            a.biometrics_allowed,
            biometrics,
            managed,
        );
        set(
            &mut t.face_requires_ir,
            a.face_requires_ir,
            "methods.face_requires_ir",
            managed,
        );
        let tpm = "methods.require_hardware_tpm";
        set(
            &mut t.require_hardware_tpm,
            a.require_hardware_tpm,
            tpm,
            managed,
        );
    }

    for (name, a) in &admin.context {
        let t = target
            .context
            .entry(name.clone())
            .or_insert_with(empty_context);
        if !a.methods.is_empty() {
            t.methods = a.methods.clone();
            managed.insert(format!("context.{name}.methods"));
        }
        set(
            &mut t.factors,
            a.factors,
            &format!("context.{name}.factors"),
            managed,
        );
        let reverify = format!("context.{name}.reverify_after");
        set(
            &mut t.reverify_after,
            a.reverify_after.clone(),
            &reverify,
            managed,
        );
    }

    for (name, a) in &admin.rp_class {
        let t = target
            .rp_class
            .entry(name.clone())
            .or_insert_with(empty_rp_class);
        if !a.match_patterns.is_empty() {
            for pattern in &a.match_patterns {
                if !t.match_patterns.contains(pattern) {
                    t.match_patterns.push(pattern.clone());
                }
            }
            managed.insert(format!("rp_class.{name}.match"));
        }
        set(
            &mut t.provider,
            a.provider,
            &format!("rp_class.{name}.provider"),
            managed,
        );
        set(
            &mut t.prompt,
            a.prompt,
            &format!("rp_class.{name}.prompt"),
            managed,
        );
        set(
            &mut t.factors,
            a.factors,
            &format!("rp_class.{name}.factors"),
            managed,
        );
        let second = format!("rp_class.{name}.require_second_credential");
        set(
            &mut t.require_second_credential,
            a.require_second_credential,
            &second,
            managed,
        );
    }
}

/// Replaces `target` with the admin's `value` when the admin set it, and records
/// `path` as managed. An unset admin value leaves `target` as it is.
fn set<T>(target: &mut Option<T>, value: Option<T>, path: &str, managed: &mut BTreeSet<String>) {
    if let Some(v) = value {
        *target = Some(v);
        managed.insert(path.to_string());
    }
}

/// A `[pin]` table with no key set: the start for an admin `[pin]` when the base
/// has none. The defaults always set one, so this is a safeguard.
fn empty_pin() -> PinPolicy {
    PinPolicy {
        min_length: None,
        max_length: None,
        digits: None,
        lowercase: None,
        uppercase: None,
        special: None,
        history: None,
        expiry_days: None,
        lockout_attempts: None,
        lockout_minutes: None,
    }
}

/// A `[methods]` table with no key set; see [`empty_pin`].
fn empty_methods() -> MethodsPolicy {
    MethodsPolicy {
        biometrics_allowed: None,
        face_requires_ir: None,
        require_hardware_tpm: None,
    }
}

/// A context with no key set, for an admin context the base lacks.
fn empty_context() -> ContextPolicy {
    ContextPolicy {
        methods: Vec::new(),
        factors: None,
        reverify_after: None,
    }
}

/// An rp_class with no key set, for an rp_class only the admin defines.
fn empty_rp_class() -> RpClassPolicy {
    RpClassPolicy {
        match_patterns: Vec::new(),
        provider: None,
        prompt: None,
        factors: None,
        require_second_credential: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::schema::parse_layer;

    #[test]
    fn admin_only_rp_class_is_managed_per_key() {
        let admin = parse_layer(
            "[rp_class.bank]\nmatch = [\"bank.example\"]\nprovider = \"tpm\"\nfactors = 2",
        )
        .unwrap();
        let res = merge(&[admin], None).unwrap();
        let bank = &res.layer.rp_class["bank"];
        assert_eq!(bank.match_patterns, vec!["bank.example".to_string()]);
        assert_eq!(bank.factors, Some(2));
        let expected: BTreeSet<String> = [
            "rp_class.bank.factors",
            "rp_class.bank.match",
            "rp_class.bank.provider",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(res.managed, expected);
    }

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
