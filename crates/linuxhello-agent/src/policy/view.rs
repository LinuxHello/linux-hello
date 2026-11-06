//! The policy view: provides a structured way to inspect the effective policy
//! or the PIN-only state, including PIN rules and a list of all active settings.
//!
//! C4 component: `policyEngine` ([workspace.dsl](https://github.com/LinuxHello/architecture/blob/main/workspace.dsl))

use crate::policy::defaults::default_layer;
use crate::policy::load::Policy;
use crate::policy::schema::{
    ContextPolicy, Layer, MethodsPolicy, PinPolicy, RpClassPolicy, RpPrompt, RpProvider,
};

/// The rules governing the PIN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinRules {
    /// Minimum PIN length.
    pub min_length: u32,
    /// Maximum PIN length.
    pub max_length: u32,
    /// Digits requirement: `"required"`, `"allowed"`, or `"disallowed"`.
    pub digits: String,
    /// Lowercase requirement: `"required"`, `"allowed"`, or `"disallowed"`.
    pub lowercase: String,
    /// Uppercase requirement: `"required"`, `"allowed"`, or `"disallowed"`.
    pub uppercase: String,
    /// Special character requirement: `"required"`, `"allowed"`, or `"disallowed"`.
    pub special: String,
    /// Number of previous PINs that may not be reused.
    pub history: u32,
    /// Days until the PIN must be changed. `None` means it never expires.
    pub expiry_days: Option<u32>,
    /// Number of wrong entries before lockout.
    pub lockout_attempts: u32,
    /// Minutes a lockout lasts.
    pub lockout_minutes: u32,
}

/// A single setting in the effective policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// The path to the setting (e.g., `"pin.min_length"`).
    pub path: String,
    /// The value in TOML syntax.
    pub value: String,
    /// Whether this setting was provided by an admin layer.
    pub managed: bool,
}

/// A view of the effective policy or the PIN-only state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveView {
    /// All active settings, sorted by path.
    pub settings: Vec<Setting>,
    /// The reason for failing closed, if in the PIN-only state.
    pub pin_only_reason: Option<String>,
}

impl Policy {
    /// Returns the PIN rules for this policy.
    ///
    /// If the `[pin]` table is missing or incomplete, it falls back to the
    /// values in `default_layer()`.
    pub fn pin_rules(&self) -> PinRules {
        let layer = match self {
            Policy::Effective(eff) => &eff.layer,
            Policy::PinOnly(pin) => &pin.layer,
        };

        let def = default_layer().pin.unwrap();

        let pin = layer.pin.as_ref();

        PinRules {
            min_length: pin
                .and_then(|p| p.min_length)
                .unwrap_or(def.min_length.unwrap_or(6)),
            max_length: pin
                .and_then(|p| p.max_length)
                .unwrap_or(def.max_length.unwrap_or(127)),
            digits: pin
                .and_then(|p| p.digits.clone())
                .unwrap_or_else(|| def.digits.unwrap_or_else(|| "allowed".to_string())),
            lowercase: pin
                .and_then(|p| p.lowercase.clone())
                .unwrap_or_else(|| def.lowercase.unwrap_or_else(|| "allowed".to_string())),
            uppercase: pin
                .and_then(|p| p.uppercase.clone())
                .unwrap_or_else(|| def.uppercase.unwrap_or_else(|| "allowed".to_string())),
            special: pin
                .and_then(|p| p.special.clone())
                .unwrap_or_else(|| def.special.unwrap_or_else(|| "allowed".to_string())),
            history: pin
                .and_then(|p| p.history)
                .unwrap_or(def.history.unwrap_or(0)),
            expiry_days: pin.and_then(|p| p.expiry_days).or_else(|| def.expiry_days),
            lockout_attempts: pin
                .and_then(|p| p.lockout_attempts)
                .unwrap_or(def.lockout_attempts.unwrap_or(5)),
            lockout_minutes: pin
                .and_then(|p| p.lockout_minutes)
                .unwrap_or(def.lockout_minutes.unwrap_or(15)),
        }
    }

    /// Returns a view of the effective settings and the PIN-only reason.
    pub fn effective(&self) -> EffectiveView {
        let mut settings = Vec::new();
        let mut pin_only_reason = None;

        match self {
            Policy::Effective(eff) => {
                let layer = &eff.layer;
                let managed = &eff.managed;

                // 1. Pin settings
                if let Some(pin) = &layer.pin {
                    if let Some(v) = pin.min_length {
                        settings.push(create_setting(
                            "pin.min_length",
                            v.to_string(),
                            managed.contains("pin.min_length"),
                        ));
                    }
                    if let Some(v) = pin.max_length {
                        settings.push(create_setting(
                            "pin.max_length",
                            v.to_string(),
                            managed.contains("pin.max_length"),
                        ));
                    }
                    if let Some(v) = &pin.digits {
                        settings.push(create_setting(
                            "pin.digits",
                            format!("\"{}\"", v),
                            managed.contains("pin.digits"),
                        ));
                    }
                    if let Some(v) = &pin.lowercase {
                        settings.push(create_setting(
                            "pin.lowercase",
                            format!("\"{}\"", v),
                            managed.contains("pin.lowercase"),
                        ));
                    }
                    if let Some(v) = &pin.uppercase {
                        settings.push(create_setting(
                            "pin.uppercase",
                            format!("\"{}\"", v),
                            managed.contains("pin.uppercase"),
                        ));
                    }
                    if let Some(v) = &pin.special {
                        settings.push(create_setting(
                            "pin.special",
                            format!("\"{}\"", v),
                            managed.contains("pin.special"),
                        ));
                    }
                    if let Some(v) = pin.history {
                        settings.push(create_setting(
                            "pin.history",
                            v.to_string(),
                            managed.contains("pin.history"),
                        ));
                    }
                    if let Some(v) = pin.expiry_days {
                        settings.push(create_setting(
                            "pin.expiry_days",
                            v.to_string(),
                            managed.contains("pin.expiry_days"),
                        ));
                    }
                    if let Some(v) = pin.lockout_attempts {
                        settings.push(create_setting(
                            "pin.lockout_attempts",
                            v.to_string(),
                            managed.contains("pin.lockout_attempts"),
                        ));
                    }
                    if let Some(v) = pin.lockout_minutes {
                        settings.push(create_setting(
                            "pin.lockout_minutes",
                            v.to_string(),
                            managed.contains("pin.lockout_minutes"),
                        ));
                    }
                }

                // 2. Methods settings
                if let Some(m) = &layer.methods {
                    if let Some(v) = m.biometrics_allowed {
                        settings.push(create_setting(
                            "methods.biometrics_allowed",
                            v.to_string(),
                            managed.contains("methods.biometrics_allowed"),
                        ));
                    }
                    if let Some(v) = m.face_requires_ir {
                        settings.push(create_setting(
                            "methods.face_requires_ir",
                            v.to_string(),
                            managed.contains("methods.face_requires_ir"),
                        ));
                    }
                    if let Some(v) = m.require_hardware_tpm {
                        settings.push(create_setting(
                            "methods.require_hardware_tpm",
                            v.to_string(),
                            managed.contains("methods.require_hardware_tpm"),
                        ));
                    }
                }

                // 3. Context settings
                for (name, ctx) in &layer.context {
                    if !ctx.methods.is_empty() {
                        let methods_val = format!("[\"{}\"]", ctx.methods.join("\", \""));
                        settings.push(create_setting(
                            &format!("context.{name}.methods"),
                            methods_val,
                            managed.contains(&format!("context.{name}.methods")),
                        ));
                    }
                    if let Some(v) = ctx.factors {
                        settings.push(create_setting(
                            &format!("context.{name}.factors"),
                            v.to_string(),
                            managed.contains(&format!("context.{name}.factors")),
                        ));
                    }
                    if let Some(dur) = &ctx.reverify_after {
                        settings.push(create_setting(
                            &format!("context.{name}.reverify_after"),
                            format!("\"{}{}\"", dur.value, format_unit(dur.unit)),
                            managed.contains(&format!("context.{name}.reverify_after")),
                        ));
                    }
                }

                // 4. RpClass settings
                for (name, rp) in &layer.rp_class {
                    if !rp.match_patterns.is_empty() {
                        let patterns_val = format!("[\"{}\"]", rp.match_patterns.join("\", \""));
                        settings.push(create_setting(
                            &format!("rp_class.{name}.match"),
                            patterns_val,
                            managed.contains(&format!("rp_class.{name}.match")),
                        ));
                    }
                    if let Some(v) = &rp.provider {
                        settings.push(create_setting(
                            &format!("rp_class.{name}.provider"),
                            format!("\"{}\"", format_provider(v)),
                            managed.contains(&format!("rp_class.{name}.provider")),
                        ));
                    }
                    if let Some(v) = &rp.prompt {
                        settings.push(create_setting(
                            &format!("rp_class.{name}.prompt"),
                            format!("\"{}\"", format_prompt(v)),
                            managed.contains(&format!("rp_class.{name}.prompt")),
                        ));
                    }
                    if let Some(v) = rp.factors {
                        settings.push(create_setting(
                            &format!("rp_class.{name}.factors"),
                            v.to_string(),
                            managed.contains(&format!("rp_class.{name}.factors")),
                        ));
                    }
                    if let Some(v) = rp.require_second_credential {
                        settings.push(create_setting(
                            &format!("rp_class.{name}.require_second_credential"),
                            v.to_string(),
                            managed.contains(&format!("rp_class.{name}.require_second_credential")),
                        ));
                    }
                }
            }
            Policy::PinOnly(pin) => {
                pin_only_reason = Some(pin.reason.clone());
            }
        }

        settings.sort_by(|a, b| a.path.cmp(&b.path));
        EffectiveView {
            settings,
            pin_only_reason,
        }
    }
}

fn create_setting(path: &str, value: String, managed: bool) -> Setting {
    Setting {
        path: path.to_string(),
        value,
        managed,
    }
}

fn format_unit(unit: crate::policy::schema::DurationUnit) -> char {
    match unit {
        crate::policy::schema::DurationUnit::Seconds => 's',
        crate::policy::schema::DurationUnit::Minutes => 'm',
        crate::policy::schema::DurationUnit::Hours => 'h',
        crate::policy::schema::DurationUnit::Days => 'd',
    }
}

fn format_provider(provider: &RpProvider) -> &str {
    match provider {
        RpProvider::Tpm => "tpm",
        RpProvider::Keepassxc => "keepassxc",
        RpProvider::Any => "any",
    }
}

fn format_prompt(prompt: &RpPrompt) -> &str {
    match prompt {
        RpPrompt::None => "none",
        RpPrompt::Presence => "presence",
        RpPrompt::Reverify => "reverify",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::load::load;
    use crate::policy::merge::merge;
    use crate::policy::schema::parse_layer;
    use tempfile::TempDir;

    #[test]
    fn pin_rules_are_the_defaults_without_policy_files() {
        let pol = Policy::Effective(merge(&[], None).unwrap());
        let rules = pol.pin_rules();
        assert_eq!(rules.min_length, 6);
        assert_eq!(rules.max_length, 127);
        assert_eq!(rules.digits, "required");
        assert_eq!(rules.lowercase, "allowed");
        assert_eq!(rules.uppercase, "allowed");
        assert_eq!(rules.special, "allowed");
        assert_eq!(rules.history, 0);
        assert_eq!(rules.expiry_days, None);
        assert_eq!(rules.lockout_attempts, 5);
        assert_eq!(rules.lockout_minutes, 15);
    }

    #[test]
    fn pin_rules_follow_the_effective_policy() {
        let toml = "[pin]\nmin_length = 8";
        let pol = Policy::Effective(merge(&[parse_layer(toml).unwrap()], None).unwrap());
        let rules = pol.pin_rules();
        assert_eq!(rules.min_length, 8);
        assert_eq!(rules.max_length, 127);
        assert_eq!(rules.digits, "required");
    }

    #[test]
    fn pin_only_state_has_the_default_pin_rules() {
        let tmp = TempDir::new().unwrap();
        let user_file = tmp.path().join("user.toml");
        std::fs::write(&user_file, "invalid = toml").unwrap();
        let pol = load(&tmp.path().join("absent.d"), &user_file, 0);
        let rules = pol.pin_rules();
        assert_eq!(rules.min_length, 6);
        assert_eq!(rules.max_length, 127);
        assert_eq!(rules.digits, "required");
    }

    #[test]
    fn admin_keys_are_marked_managed() {
        let toml = "[pin]\nmin_length = 8";
        let pol = Policy::Effective(merge(&[parse_layer(toml).unwrap()], None).unwrap());
        let view = pol.effective();
        let min_len = view
            .settings
            .iter()
            .find(|s| s.path == "pin.min_length")
            .unwrap();
        assert_eq!(min_len.value, "8");
        assert!(min_len.managed);

        let max_len = view
            .settings
            .iter()
            .find(|s| s.path == "pin.max_length")
            .unwrap();
        assert_eq!(max_len.value, "127");
        assert!(!max_len.managed);
    }

    #[test]
    fn settings_are_sorted_and_listed_once() {
        let toml = r#"
[pin]
min_length = 8
[methods]
biometrics_allowed = true
"#;
        let pol = Policy::Effective(merge(&[parse_layer(toml).unwrap()], None).unwrap());
        let view = pol.effective();
        let paths: Vec<String> = view.settings.iter().map(|s| s.path.clone()).collect();

        // Check uniqueness
        let mut unique_paths = paths.clone();
        unique_paths.sort();
        unique_paths.dedup();
        assert_eq!(paths.len(), unique_paths.len(), "Paths are not unique");

        // Check sorting
        let mut sorted_paths = paths.clone();
        sorted_paths.sort();
        assert_eq!(paths, sorted_paths, "Paths are not sorted");
    }

    #[test]
    fn values_are_rendered_as_toml() {
        let toml = r#"
[context.unlock]
methods = ["pin", "face"]
reverify_after = "8h"

[rp_class.bank]
match = ["bank.example"]
provider = "tpm"

[pin]
digits = "required"

[methods]
biometrics_allowed = true
"#;
        let pol = Policy::Effective(merge(&[parse_layer(toml).unwrap()], None).unwrap());
        let view = pol.effective();

        let find = |p: &str| view.settings.iter().find(|s| s.path == p).unwrap();

        assert_eq!(find("context.unlock.methods").value, "[\"pin\", \"face\"]");
        assert_eq!(find("context.unlock.reverify_after").value, "\"8h\"");
        assert_eq!(find("rp_class.bank.match").value, "[\"bank.example\"]");
        assert_eq!(find("rp_class.bank.provider").value, "\"tpm\"");
        assert_eq!(find("pin.digits").value, "\"required\"");
        assert_eq!(find("methods.biometrics_allowed").value, "true");
    }

    #[test]
    fn unset_keys_are_not_listed() {
        let pol = Policy::Effective(merge(&[], None).unwrap());
        let view = pol.effective();
        assert!(view.settings.iter().all(|s| s.path != "pin.expiry_days"));
    }

    #[test]
    fn pin_only_view_carries_the_reason() {
        let tmp = TempDir::new().unwrap();
        let user_file = tmp.path().join("user.toml");
        std::fs::write(&user_file, "invalid = toml").unwrap();
        let pol = load(&tmp.path().join("absent.d"), &user_file, 0);
        let view = pol.effective();
        assert!(view.pin_only_reason.as_ref().unwrap().contains("user.toml"));
        assert!(view.settings.is_empty() || view.settings.iter().all(|s| !s.managed));
    }
}
//! The policy view: provides a structured way to inspect the effective policy
//! or the PIN-only state, including PIN rules and a list of all active settings.
//!
//! C4 component: `policyEngine` ([workspace.dsl](https://github.com/LinuxHello/architecture/blob/main/workspace.dsl))

use crate::policy::defaults::default_layer;
use crate::policy::load::Policy;
use crate::policy::schema::{
    ContextPolicy, Layer, MethodsPolicy, PinPolicy, RpClassPolicy, RpPrompt, RpProvider,
};

/// The rules governing the PIN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinRules {
    /// Minimum PIN length.
    pub min_length: u32,
    /// Maximum PIN length.
    pub max_length: u32,
    /// Digits requirement: `"required"`, `"allowed"`, or `"disallowed"`.
    pub digits: String,
    /// Lowercase requirement: `"required"`, `"allowed"`, or `"disallowed"`.
    pub lowercase: String,
    /// Uppercase requirement: `"required"`, `"allowed"`, or `"disallowed"`.
    pub uppercase: String,
    /// Special character requirement: `"required"`, `"allowed"`, or `"disallowed"`.
    pub special: String,
    /// Number of previous PINs that may not be reused.
    pub history: u32,
    /// Days until the PIN must be changed. `None` means it never expires.
    pub expiry_days: Option<u32>,
    /// Number of wrong entries before lockout.
    pub lockout_attempts: u32,
    /// Minutes a lockout lasts.
    pub lockout_minutes: u32,
}

/// A single setting in the effective policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// The path to the setting (e.g., `"pin.min_length"`, `"context.sudo.methods"`, `"rp_class.bank.match"`).
    pub path: String,
    /// The value in TOML syntax.
    pub value: String,
    /// Whether this setting was provided by an admin layer.
    pub managed: bool,
}

/// A view of the effective policy or the PIN-only state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveView {
    /// All active settings, sorted by path.
    pub settings: Vec<Setting>,
    /// The reason for failing closed, if in the PIN-only state.
    pub pin_only_reason: Option<String>,
}

impl Policy {
    /// Returns the PIN rules for this policy.
    ///
    /// If the `[pin]` table is missing or incomplete, it falls back to the
    /// values in `default_layer()`.
    pub fn pin_rules(&self) -> PinRules {
        let layer = match self {
            Policy::Effective(eff) => &eff.layer,
            Policy::PinOnly(pin) => &pin.layer,
        };

        let def = default_layer().pin.unwrap();

        let pin = layer.pin.as_ref();

        PinRules {
            min_length: pin
                .and_then(|p| p.min_length)
                .unwrap_or(def.min_length.unwrap_or(6)),
            max_length: pin
                .and_then(|p| p.max_length)
                .unwrap_or(def.max_length.unwrap_or(127)),
            digits: pin
                .and_then(|p| p.digits.clone())
                .unwrap_or_else(|| def.digits.unwrap_or_else(|| "allowed".to_string())),
            lowercase: pin
                .and_then(|p| p.lowercase.clone())
                .unwrap_or_else(|| def.lowercase.unwrap_or_else(|| "allowed".to_string())),
            uppercase: pin
                .and_then(|p| p.uppercase.clone())
                .unwrap_or_else(|| def.uppercase.unwrap_or_else(|| "allowed".to_string())),
            special: pin
                .and_then(|p| p.special.clone())
                .unwrap_or_else(|| def.special.unwrap_or_else(|| "allowed".to_string())),
            history: pin
                .and_then(|p| p.history)
                .unwrap_or(def.history.unwrap_or(0)),
            expiry_days: pin.and_then(|p| p.expiry_days).or(def.expiry_days),
            lockout_attempts: pin
                .and_then(|p| p.lockout_attempts)
                .unwrap_or(def.lockout_attempts.unwrap_or(5)),
            lockout_minutes: pin
                .and_then(|p| p.lockout_minutes)
                .unwrap_or(def.lockout_minutes.unwrap_or(15)),
        }
    }

    /// Returns a view of the effective settings and the PIN-only reason.
    pub fn effective(&self) -> EffectiveView {
        let mut settings = Vec::new();
        let mut pin_only_reason = None;

        match self {
            Policy::Effective(eff) => {
                let layer = &eff.layer;
                let managed = &eff.managed;

                // 1. Pin settings
                if let Some(pin) = &layer.pin {
                    if let Some(v) = pin.min_length {
                        settings.push(create_setting(
                            "pin.min_length",
                            v.to_string(),
                            managed.contains("pin.min_length"),
                        ));
                    }
                    if let Some(v) = pin.max_length {
                        settings.push(create_setting(
                            "pin.max_length",
                            v.to_string(),
                            managed.contains("pin.max_length"),
                        ));
                    }
                    if let Some(v) = &pin.digits {
                        settings.push(create_setting(
                            "pin.digits",
                            format!("\"{}\"", v),
                            managed.contains("pin.digits"),
                        ));
                    }
                    if let Some(v) = &pin.lowercase {
                        settings.push(create_setting(
                            "pin.lowercase",
                            format!("\"{}\"", v),
                            managed.contains("pin.lowercase"),
                        ));
                    }
                    if let Some(v) = &pin.uppercase {
                        settings.push(create_setting(
                            "pin.uppercase",
                            format!("\"{}\"", v),
                            managed.contains("pin.uppercase"),
                        ));
                    }
                    if let Some(v) = &pin.special {
                        settings.push(create_setting(
                            "pin.special",
                            format!("\"{}\"", v),
                            managed.contains("pin.special"),
                        ));
                    }
                    if let Some(v) = pin.history {
                        settings.push(create_setting(
                            "pin.history",
                            v.to_string(),
                            managed.contains("pin.history"),
                        ));
                    }
                    if let Some(v) = pin.expiry_days {
                        settings.push(create_setting(
                            "pin.expiry_days",
                            v.to_string(),
                            managed.contains("pin.expiry_days"),
                        ));
                    }
                    if let Some(v) = pin.lockout_attempts {
                        settings.push(create_setting(
                            "pin.lockout_attempts",
                            v.to_string(),
                            managed.contains("pin.lockout_attempts"),
                        ));
                    }
                    if let Some(v) = pin.lockout_minutes {
                        settings.push(create_setting(
                            "pin.lockout_minutes",
                            v.to_string(),
                            managed.contains("pin.lockout_minutes"),
                        ));
                    }
                }

                // 2. Methods settings
                if let Some(m) = &layer.methods {
                    if let Some(v) = m.biometrics_allowed {
                        settings.push(create_setting(
                            "methods.biometrics_allowed",
                            v.to_string(),
                            managed.contains("methods.biometrics_allowed"),
                        ));
                    }
                    if let Some(v) = m.face_requires_ir {
                        settings.push(create_setting(
                            "methods.face_requires_ir",
                            v.to_string(),
                            managed.contains("methods.face_requires_ir"),
                        ));
                    }
                    if let Some(v) = m.require_hardware_tpm {
                        settings.push(create_setting(
                            "methods.require_hardware_tpm",
                            v.to_string(),
                            managed.contains("methods.require_hardware_tpm"),
                        ));
                    }
                }

                // 3. Context settings
                for (name, ctx) in &layer.context {
                    if !ctx.methods.is_empty() {
                        let methods_val = format!("[\"{}\"]", ctx.methods.join("\", \""));
                        settings.push(create_setting(
                            &format!("context.{name}.methods"),
                            methods_val,
                            managed.contains(&format!("context.{name}.methods")),
                        ));
                    }
                    if let Some(v) = ctx.factors {
                        settings.push(create_setting(
                            &format!("context.{name}.factors"),
                            v.to_string(),
                            managed.contains(&format!("context.{name}.factors")),
                        ));
                    }
                    if let Some(dur) = &ctx.reverify_after {
                        settings.push(create_setting(
                            &format!("context.{name}.reverify_after"),
                            format!("\"{}{}\"", dur.value, format_unit(dur.unit)),
                            managed.contains(&format!("context.{name}.reverify_after")),
                        ));
                    }
                }

                // 4. RpClass settings
                for (name, rp) in &layer.rp_class {
                    if !rp.match_patterns.is_empty() {
                        let patterns_val = format!("[\"{}\"]", rp.match_patterns.join("\", \""));
                        settings.push(create_setting(
                            &format!("rp_class.{name}.match"),
                            patterns_val,
                            managed.contains(&format!("rp_class.{name}.match")),
                        ));
                    }
                    if let Some(v) = &rp.provider {
                        settings.push(create_setting(
                            &format!("rp_class.{name}.provider"),
                            format!("\"{}\"", format_provider(v)),
                            managed.contains(&format!("rp_class.{name}.provider")),
                        ));
                    }
                    if let Some(v) = &rp.prompt {
                        settings.push(create_setting(
                            &format!("rp_class.{name}.prompt"),
                            format!("\"{}\"", format_prompt(v)),
                            managed.contains(&format!("rp_class.{name}.prompt")),
                        ));
                    }
                    if let Some(v) = rp.factors {
                        settings.push(create_setting(
                            &format!("rp_class.{name}.factors"),
                            v.to_string(),
                            managed.contains(&format!("rp_class.{name}.factors")),
                        ));
                    }
                    if let Some(v) = rp.require_second_credential {
                        settings.push(create_setting(
                            &format!("rp_class.{name}.require_second_credential"),
                            v.to_string(),
                            managed.contains(&format!("rp_class.{name}.require_second_credential")),
                        ));
                    }
                }
            }
            Policy::PinOnly(pin) => {
                pin_only_reason = Some(pin.reason.clone());
            }
        }

        settings.sort_by(|a, b| a.path.cmp(&b.path));
        EffectiveView {
            settings,
            pin_only_reason,
        }
    }
}

/// Creates a new `Setting`.
fn create_setting(path: &str, value: String, managed: bool) -> Setting {
    Setting {
        path: path.to_string(),
        value,
        managed,
    }
}

/// Formats a `DurationUnit` as its single-letter suffix.
fn format_unit(unit: crate::policy::schema::DurationUnit) -> char {
    match unit {
        crate::policy::schema::DurationUnit::Seconds => 's',
        crate::policy::schema::DurationUnit::Minutes => 'm',
        crate::policy::schema::DurationUnit::Hours => 'h',
        crate::policy::schema::DurationUnit::Days => 'd',
    }
}

/// Formats an `RpProvider` as a lower-case string.
fn format_provider(provider: &RpProvider) -> &str {
    match provider {
        RpProvider::Tpm => "tpm",
        RpProvider::Keepassxc => "keepassxc",
        RpProvider::Any => "any",
    }
}

/// Formats an `RpPrompt` as a lower-case string.
fn format_prompt(prompt: &RpPrompt) -> &str {
    match prompt {
        RpPrompt::None => "none",
        RpPrompt::Presence => "presence",
        RpPrompt::Reverify => "reverify",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::load::load;
    use crate::policy::merge::merge;
    use crate::policy::schema::parse_layer;
    use tempfile::TempDir;

    #[test]
    fn pin_rules_are_the_defaults_without_policy_files() {
        let pol = Policy::Effective(merge(&[], None).unwrap());
        let rules = pol.pin_rules();
        assert_eq!(rules.min_length, 6);
        assert_eq!(rules.max_length, 127);
        assert_eq!(rules.digits, "required");
        assert_eq!(rules.lowercase, "allowed");
        assert_eq!(rules.uppercase, "allowed");
        assert_eq!(rules.special, "allowed");
        assert_eq!(rules.history, 0);
        assert_eq!(rules.expiry_days, None);
        assert_eq!(rules.lockout_attempts, 5);
        assert_eq!(rules.lockout_minutes, 15);
    }

    #[test]
    fn pin_rules_follow_the_effective_policy() {
        let toml = "[pin]\nmin_length = 8";
        let pol = Policy::Effective(merge(&[parse_layer(toml).unwrap()], None).unwrap());
        let rules = pol.pin_rules();
        assert_eq!(rules.min_length, 8);
        assert_eq!(rules.max_length, 127);
        assert_eq!(rules.digits, "required");
    }

    #[test]
    fn pin_only_state_has_the_default_pin_rules() {
        let tmp = TempDir::new().unwrap();
        let user_file = tmp.path().join("user.toml");
        std::fs::write(&user_file, "invalid = toml").unwrap();
        let pol = load(&tmp.path().join("absent.d"), &user_file, 0);
        let rules = pol.pin_rules();
        assert_eq!(rules.min_length, 6);
        assert_eq!(rules.max_length, 127);
        assert_eq!(rules.digits, "required");
    }

    #[test]
    fn admin_keys_are_marked_managed() {
        let toml = "[pin]\nmin_length = 8";
        let pol = Policy::Effective(merge(&[parse_layer(toml).unwrap()], None).unwrap());
        let view = pol.effective();
        let min_len = view
            .settings
            .iter()
            .find(|s| s.path == "pin.min_length")
            .unwrap();
        assert_eq!(min_len.value, "8");
        assert!(min_len.managed);

        let max_len = view
            .settings
            .iter()
            .find(|s| s.path == "pin.max_length")
            .unwrap();
        assert_eq!(max_len.value, "127");
        assert!(!max_len.managed);
    }

    #[test]
    fn settings_are_sorted_and_listed_once() {
        let toml = r#"
[pin]
min_length = 8
[methods]
biometrics_allowed = true
"#;
        let pol = Policy::Effective(merge(&[parse_layer(toml).unwrap()], None).unwrap());
        let view = pol.effective();
        let paths: Vec<String> = view.settings.iter().map(|s| s.path.clone()).collect();

        // Check uniqueness
        let mut unique_paths = paths.clone();
        unique_paths.sort();
        unique_paths.dedup();
        assert_eq!(paths.len(), unique_paths.len(), "Paths are not unique");

        // Check sorting
        let mut sorted_paths = paths.clone();
        sorted_paths.sort();
        assert_eq!(paths, sorted_paths);
    }

    #[test]
    fn values_are_rendered_as_toml() {
        let toml = r#"
[context.unlock]
methods = ["pin", "face"]
reverify_after = "8h"

[rp_class.bank]
match = ["bank.example"]
provider = "tpm"

[pin]
digits = "required"

[methods]
biometrics_allowed = true
"#;
        let pol = Policy::Effective(merge(&[parse_layer(toml).unwrap()], None).unwrap());
        let view = pol.effective();

        let find = |p: &str| view.settings.iter().find(|s| s.path == p).unwrap();

        assert_eq!(find("context.unlock.methods").value, "[\"pin\", \"face\"]");
        assert_eq!(find("context.unlock.reverify_after").value, "\"8h\"");
        assert_eq!(find("rp_class.bank.match").value, "[\"bank.example\"]");
        assert_eq!(find("rp_class.bank.provider").value, "\"tpm\"");
        assert_eq!(find("pin.digits").value, "\"required\"");
        assert_eq!(find("methods.biometrics_allowed").value, "true");
    }

    #[test]
    fn unset_keys_are_not_listed() {
        let pol = Policy::Effective(merge(&[], None).unwrap());
        let view = pol.effective();
        assert!(view.settings.iter().all(|s| s.path != "pin.expiry_days"));
    }

    #[test]
    fn pin_only_view_carries_the_reason() {
        let tmp = TempDir::new().unwrap();
        let user_file = tmp.path().join("user.toml");
        std::fs::write(&user_file, "invalid = toml").unwrap();
        let pol = load(&tmp.path().join("absent.d"), &user_file, 0);
        let view = pol.effective();
        assert!(view.pin_only_reason.as_ref().unwrap().contains("user.toml"));
        assert!(view.settings.is_empty() || view.settings.iter().all(|s| !s.managed));
    }
}
