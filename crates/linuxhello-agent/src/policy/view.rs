//! Reporting a loaded `Policy`: its PIN rules with every gap filled from the
//! built-in defaults (`pin_rules`), and every key its layer sets with whether an
//! admin set it, plus the reason when loading failed closed (`effective`). Values
//! are shown in TOML syntax (policy-semantics.md, *Queries*).

use std::collections::BTreeSet;

use crate::policy::defaults::default_layer;
use crate::policy::load::Policy;
use crate::policy::schema::{DurationUnit, Layer, RpPrompt, RpProvider};

/// The PIN rules in force, every value resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinRules {
    /// Shortest allowed PIN.
    pub min_length: u32,
    /// Longest allowed PIN.
    pub max_length: u32,
    /// Digits: `"required"`, `"allowed"` or `"disallowed"`.
    pub digits: String,
    /// Lower-case letters: `"required"`, `"allowed"` or `"disallowed"`.
    pub lowercase: String,
    /// Upper-case letters: `"required"`, `"allowed"` or `"disallowed"`.
    pub uppercase: String,
    /// Special characters: `"required"`, `"allowed"` or `"disallowed"`.
    pub special: String,
    /// How many previous PINs may not be reused.
    pub history: u32,
    /// Days until the PIN must be changed; `None`: it never expires.
    pub expiry_days: Option<u32>,
    /// Wrong entries before a lockout.
    pub lockout_attempts: u32,
    /// Minutes a lockout lasts.
    pub lockout_minutes: u32,
}

/// One key of the effective policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// The key's path, e.g. `pin.min_length`, `context.sudo.methods`, `rp_class.bank.match`.
    pub path: String,
    /// The value in TOML syntax, e.g. `8`, `true`, `"required"`, `["pin", "face"]`, `"8h"`.
    pub value: String,
    /// An admin set it; always false in the PIN-only state.
    pub managed: bool,
}

/// Every key of the effective policy, and why the policy failed closed, if it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveView {
    /// Every key the layer sets, sorted by path, each path once.
    pub settings: Vec<Setting>,
    /// The PIN-only reason; `None` unless loading failed closed.
    pub pin_only_reason: Option<String>,
}

impl Policy {
    /// The PIN rules of the effective or PIN-only layer. A key the layer leaves
    /// unset takes the built-in default's value, and the type's fallback only if
    /// that is unset too (`pin_rules_are_the_defaults_without_policy_files`,
    /// `pin_only_state_has_the_default_pin_rules`).
    pub fn pin_rules(&self) -> PinRules {
        let defaults = default_layer().pin;
        let ours = self.view_layer().pin.as_ref();
        let pick = |get: fn(&crate::policy::schema::PinPolicy) -> Option<u32>, fallback: u32| {
            ours.and_then(get)
                .or_else(|| defaults.as_ref().and_then(get))
                .unwrap_or(fallback)
        };
        let class = |get: fn(&crate::policy::schema::PinPolicy) -> &Option<String>| {
            ours.and_then(|p| get(p).clone())
                .or_else(|| defaults.as_ref().and_then(|p| get(p).clone()))
                .unwrap_or_else(|| "allowed".to_string())
        };
        PinRules {
            min_length: pick(|p| p.min_length, 6),
            max_length: pick(|p| p.max_length, 127),
            digits: class(|p| &p.digits),
            lowercase: class(|p| &p.lowercase),
            uppercase: class(|p| &p.uppercase),
            special: class(|p| &p.special),
            history: pick(|p| p.history, 0),
            expiry_days: ours
                .and_then(|p| p.expiry_days)
                .or_else(|| defaults.as_ref().and_then(|p| p.expiry_days)),
            lockout_attempts: pick(|p| p.lockout_attempts, 5),
            lockout_minutes: pick(|p| p.lockout_minutes, 15),
        }
    }

    /// Every key the effective or PIN-only layer sets, sorted by path, with its
    /// value in TOML syntax and whether an admin set it
    /// (`admin_keys_are_marked_managed`, `values_are_rendered_as_toml`); in the
    /// PIN-only state the PIN-only layer, none managed, and the reason
    /// (`pin_only_view_lists_the_pin_only_layer`).
    pub fn effective(&self) -> EffectiveView {
        let (managed, pin_only_reason) = match self {
            Policy::Effective(effective) => (Some(&effective.managed), None),
            Policy::PinOnly(pin) => (None, Some(pin.reason.clone())),
        };
        let mut settings = settings_of(self.view_layer(), managed);
        settings.sort_by(|a, b| a.path.cmp(&b.path));
        EffectiveView {
            settings,
            pin_only_reason,
        }
    }

    /// The layer the reports read: the effective layer, or the PIN-only layer.
    fn view_layer(&self) -> &Layer {
        match self {
            Policy::Effective(effective) => &effective.layer,
            Policy::PinOnly(pin) => &pin.layer,
        }
    }
}

/// One `Setting` per key `layer` sets, in no particular order; `managed` is the
/// set of admin paths, or `None` when nothing is managed.
fn settings_of(layer: &Layer, managed: Option<&BTreeSet<String>>) -> Vec<Setting> {
    let mut out = Vec::new();
    let mut add = |path: String, value: Option<String>| {
        if let Some(value) = value {
            let managed = managed.is_some_and(|m| m.contains(&path));
            out.push(Setting {
                path,
                value,
                managed,
            });
        }
    };
    if let Some(pin) = &layer.pin {
        add(
            "pin.min_length".into(),
            pin.min_length.map(|v| v.to_string()),
        );
        add(
            "pin.max_length".into(),
            pin.max_length.map(|v| v.to_string()),
        );
        add("pin.digits".into(), pin.digits.as_deref().map(quoted));
        add("pin.lowercase".into(), pin.lowercase.as_deref().map(quoted));
        add("pin.uppercase".into(), pin.uppercase.as_deref().map(quoted));
        add("pin.special".into(), pin.special.as_deref().map(quoted));
        add("pin.history".into(), pin.history.map(|v| v.to_string()));
        add(
            "pin.expiry_days".into(),
            pin.expiry_days.map(|v| v.to_string()),
        );
        add(
            "pin.lockout_attempts".into(),
            pin.lockout_attempts.map(|v| v.to_string()),
        );
        add(
            "pin.lockout_minutes".into(),
            pin.lockout_minutes.map(|v| v.to_string()),
        );
    }
    if let Some(methods) = &layer.methods {
        let flag = |v: Option<bool>| v.map(|b| b.to_string());
        add(
            "methods.biometrics_allowed".into(),
            flag(methods.biometrics_allowed),
        );
        add(
            "methods.face_requires_ir".into(),
            flag(methods.face_requires_ir),
        );
        add(
            "methods.require_hardware_tpm".into(),
            flag(methods.require_hardware_tpm),
        );
    }
    for (name, ctx) in &layer.context {
        add(format!("context.{name}.methods"), list(&ctx.methods));
        add(
            format!("context.{name}.factors"),
            ctx.factors.map(|v| v.to_string()),
        );
        add(
            format!("context.{name}.reverify_after"),
            ctx.reverify_after
                .as_ref()
                .map(|d| quoted(&format!("{}{}", d.value, unit_letter(d.unit)))),
        );
    }
    for (name, rp) in &layer.rp_class {
        add(format!("rp_class.{name}.match"), list(&rp.match_patterns));
        add(
            format!("rp_class.{name}.provider"),
            rp.provider.map(|p| quoted(provider_name(p))),
        );
        add(
            format!("rp_class.{name}.prompt"),
            rp.prompt.map(|p| quoted(prompt_name(p))),
        );
        add(
            format!("rp_class.{name}.factors"),
            rp.factors.map(|v| v.to_string()),
        );
        add(
            format!("rp_class.{name}.require_second_credential"),
            rp.require_second_credential.map(|b| b.to_string()),
        );
    }
    out
}

/// `text` as a TOML string. Policy strings are validated names, domains and
/// class values, so they hold no quote or backslash to escape.
fn quoted(text: &str) -> String {
    format!("\"{text}\"")
}

/// A non-empty list as a TOML array of strings, `["a", "b"]`; `None` when empty,
/// so an empty list is not listed as set.
fn list(items: &[String]) -> Option<String> {
    if items.is_empty() {
        return None;
    }
    let quoted_items: Vec<String> = items.iter().map(|i| quoted(i)).collect();
    Some(format!("[{}]", quoted_items.join(", ")))
}

/// The duration unit's letter in a policy file: `s`, `m`, `h` or `d`.
fn unit_letter(unit: DurationUnit) -> char {
    match unit {
        DurationUnit::Seconds => 's',
        DurationUnit::Minutes => 'm',
        DurationUnit::Hours => 'h',
        DurationUnit::Days => 'd',
    }
}

/// The provider as written in a policy file.
fn provider_name(provider: RpProvider) -> &'static str {
    match provider {
        RpProvider::Tpm => "tpm",
        RpProvider::Keepassxc => "keepassxc",
        RpProvider::Any => "any",
    }
}

/// The prompt as written in a policy file.
fn prompt_name(prompt: RpPrompt) -> &'static str {
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
    #[test]
    fn pin_only_view_lists_the_pin_only_layer() {
        let tmp = tempfile::TempDir::new().unwrap();
        let user_file = tmp.path().join("user.toml");
        std::fs::write(&user_file, "not toml").unwrap();
        let view = load(&tmp.path().join("absent.d"), &user_file, 0).effective();
        let value = |path: &str| {
            view.settings
                .iter()
                .find(|s| s.path == path)
                .map(|s| s.value.clone())
        };
        assert_eq!(value("context.sudo.methods").as_deref(), Some("[\"pin\"]"));
        assert_eq!(value("context.sudo.factors").as_deref(), Some("1"));
        assert_eq!(
            value("methods.biometrics_allowed").as_deref(),
            Some("false")
        );
        assert_eq!(value("pin.min_length").as_deref(), Some("6"));
        assert!(view.settings.iter().all(|s| !s.managed));
    }
}
