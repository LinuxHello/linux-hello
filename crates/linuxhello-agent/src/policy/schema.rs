use std::collections::HashMap;

use serde::Deserialize;

/// A fully parsed and validated admin-layer policy layer.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer {
    #[serde(default)]
    pub pin: Option<PinPolicy>,
    #[serde(default)]
    pub methods: Option<MethodsPolicy>,
    #[serde(default)]
    pub context: HashMap<String, ContextPolicy>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinPolicy {
    #[serde(default)]
    pub min_length: Option<u32>,
    #[serde(default)]
    pub max_length: Option<u32>,
    #[serde(default)]
    pub digits: Option<String>,
    #[serde(default)]
    pub lowercase: Option<String>,
    #[serde(default)]
    pub uppercase: Option<String>,
    #[serde(default)]
    pub special: Option<String>,
    #[serde(default)]
    pub history: Option<u32>,
    #[serde(default)]
    pub expiry_days: Option<u32>,
    #[serde(default)]
    pub lockout_attempts: Option<u32>,
    #[serde(default)]
    pub lockout_minutes: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MethodsPolicy {
    #[serde(default)]
    pub biometrics_allowed: Option<bool>,
    #[serde(default)]
    pub face_requires_ir: Option<bool>,
    #[serde(default)]
    pub require_hardware_tpm: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPolicy {
    pub methods: Vec<String>,
    #[serde(default)]
    pub factors: Option<u32>,
    #[serde(default)]
    pub reverify_after: Option<Duration>,
}

/// A duration expressed as a positive integer followed by a unit suffix (s, m, h, d).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Duration {
    pub value: u64,
    pub unit: DurationUnit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurationUnit {
    Seconds,
    Minutes,
    Hours,
    Days,
}

impl DurationUnit {
    fn seconds(self) -> u64 {
        match self {
            DurationUnit::Seconds => 1,
            DurationUnit::Minutes => 60,
            DurationUnit::Hours => 3600,
            DurationUnit::Days => 86_400,
        }
    }
}

impl Duration {
    /// The duration in seconds. `parse` refuses any duration whose seconds do
    /// not fit in a `u64`, so for a parsed policy this never saturates.
    pub fn total_seconds(&self) -> u64 {
        self.value.saturating_mul(self.unit.seconds())
    }
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_duration(&s).map_err(serde::de::Error::custom)
    }
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    if s.is_empty() {
        return Err("duration must not be empty".into());
    }
    let bytes = s.as_bytes();
    let split = bytes
        .iter()
        .position(|b| !b.is_ascii_digit())
        .ok_or_else(|| format!("duration '{s}' has no unit suffix"))?;
    let value: u64 = s[..split]
        .parse()
        .map_err(|_| format!("duration '{s}' has invalid numeric part"))?;
    if value == 0 {
        return Err("duration value must be greater than zero".into());
    }
    let unit = match bytes[split] {
        b's' => DurationUnit::Seconds,
        b'm' => DurationUnit::Minutes,
        b'h' => DurationUnit::Hours,
        b'd' => DurationUnit::Days,
        other => {
            return Err(format!(
                "duration '{s}' has unknown unit '{}'",
                other as char
            ))
        }
    };
    if split + 1 != bytes.len() {
        return Err(format!("duration '{s}' has trailing characters after unit"));
    }
    if value.checked_mul(unit.seconds()).is_none() {
        return Err(format!("duration '{s}' is too large"));
    }
    Ok(Duration { value, unit })
}

fn is_valid_context_name(name: &str) -> bool {
    matches!(name, "login" | "unlock" | "sudo" | "session")
}

fn is_valid_method(name: &str) -> bool {
    matches!(name, "pin" | "face" | "fingerprint")
}

fn is_valid_pin_class_value(value: &str) -> bool {
    matches!(value, "required" | "allowed" | "disallowed")
}

/// Parse and validate a TOML policy layer.
///
/// Returns an error if the file contains unknown keys, out-of-range values,
/// invalid patterns, duplicate methods, or any other schema violation.
pub fn parse_layer(input: &str) -> Result<Layer, String> {
    let layer: Layer = toml::from_str(input).map_err(|e| format!("TOML parse error: {e}"))?;
    validate(&layer)?;
    Ok(layer)
}

fn validate(layer: &Layer) -> Result<(), String> {
    if let Some(pin) = &layer.pin {
        if let Some(ml) = pin.min_length {
            if !(4..=64).contains(&ml) {
                return Err(format!("pin.min_length must be 4–64, got {ml}"));
            }
        }
        if let Some(ml) = pin.max_length {
            if !(4..=127).contains(&ml) {
                return Err(format!("pin.max_length must be 4–127, got {ml}"));
            }
        }
        for (key, val) in [
            ("digits", &pin.digits),
            ("lowercase", &pin.lowercase),
            ("uppercase", &pin.uppercase),
            ("special", &pin.special),
        ] {
            if let Some(v) = val {
                if !is_valid_pin_class_value(v) {
                    return Err(format!(
                        "pin.{key} must be one of required|allowed|disallowed, got '{v}'"
                    ));
                }
            }
        }
        if let Some(h) = pin.history {
            if h > 50 {
                return Err(format!("pin.history must be 0–50, got {h}"));
            }
        }
        if let Some(e) = pin.expiry_days {
            if !(1..=730).contains(&e) {
                return Err(format!("pin.expiry_days must be 1–730, got {e}"));
            }
        }
        if let Some(la) = pin.lockout_attempts {
            if !(1..=32).contains(&la) {
                return Err(format!("pin.lockout_attempts must be 1–32, got {la}"));
            }
        }
        if let Some(lm) = pin.lockout_minutes {
            if !(1..=1440).contains(&lm) {
                return Err(format!("pin.lockout_minutes must be 1–1440, got {lm}"));
            }
        }
    }

    for (name, ctx) in &layer.context {
        if !is_valid_context_name(name) {
            return Err(format!(
                "context name '{name}' must be one of login|unlock|sudo|session"
            ));
        }
        if ctx.methods.is_empty() {
            return Err(format!("context.{name}.methods must not be empty"));
        }
        let mut seen = std::collections::HashSet::new();
        for m in &ctx.methods {
            if !is_valid_method(m) {
                return Err(format!(
                    "context.{name}.methods contains unknown method '{m}'"
                ));
            }
            if !seen.insert(m.as_str()) {
                return Err(format!(
                    "context.{name}.methods contains duplicate method '{m}'"
                ));
            }
        }
        if let Some(f) = ctx.factors {
            if !(1..=2).contains(&f) {
                return Err(format!("context.{name}.factors must be 1–2, got {f}"));
            }
        }
        if let Some(dur) = &ctx.reverify_after {
            let total = dur.total_seconds();
            if !(1..=2_592_000).contains(&total) {
                return Err(format!(
                    "context.{name}.reverify_after must be between 1s and 30d, got {total}s"
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_key_makes_file_unparseable() {
        let toml_str = r#"
[pin]
min_length = 6
bogus_key = 42
"#;
        let err = parse_layer(toml_str).unwrap_err();
        assert!(
            err.contains("unknown field") || err.contains("bogus_key"),
            "expected unknown-field error, got: {err}"
        );
    }

    #[test]
    fn out_of_range_value_makes_file_unparseable() {
        let toml_str = r#"
[pin]
min_length = 2
"#;
        let err = parse_layer(toml_str).unwrap_err();
        assert!(
            err.contains("min_length"),
            "expected range error, got: {err}"
        );
    }

    #[test]
    fn duplicate_method_makes_file_unparseable() {
        let toml_str = r#"
[context.unlock]
methods = ["pin", "pin"]
"#;
        let err = parse_layer(toml_str).unwrap_err();
        assert!(
            err.contains("duplicate method"),
            "expected duplicate error, got: {err}"
        );
    }

    #[test]
    fn overflowing_duration_makes_file_unparseable() {
        // u64::MAX / 86_400 + 1 = 213_503_982_334_602 days does not fit in u64 seconds.
        let toml_str = r#"
[context.unlock]
methods = ["pin"]
reverify_after = "213503982334602d"
"#;
        let err = parse_layer(toml_str).unwrap_err();
        assert!(
            err.contains("too large"),
            "expected overflow error, got: {err}"
        );
    }

    #[test]
    fn reverify_after_parses_units() {
        let toml_str = r#"
[context.unlock]
methods = ["pin"]
reverify_after = "8h"
"#;
        let layer = parse_layer(toml_str).unwrap();
        let ctx = layer.context.get("unlock").unwrap();
        let dur = ctx.reverify_after.as_ref().unwrap();
        assert_eq!(dur.value, 8);
        assert_eq!(dur.unit, DurationUnit::Hours);
        assert_eq!(dur.total_seconds(), 8 * 3600);

        let toml_str = r#"
[context.unlock]
methods = ["pin"]
reverify_after = "30m"
"#;
        let layer = parse_layer(toml_str).unwrap();
        let ctx = layer.context.get("unlock").unwrap();
        let dur = ctx.reverify_after.as_ref().unwrap();
        assert_eq!(dur.value, 30);
        assert_eq!(dur.unit, DurationUnit::Minutes);
        assert_eq!(dur.total_seconds(), 30 * 60);

        let toml_str = r#"
[context.unlock]
methods = ["pin"]
reverify_after = "1d"
"#;
        let layer = parse_layer(toml_str).unwrap();
        let ctx = layer.context.get("unlock").unwrap();
        let dur = ctx.reverify_after.as_ref().unwrap();
        assert_eq!(dur.value, 1);
        assert_eq!(dur.unit, DurationUnit::Days);
        assert_eq!(dur.total_seconds(), 86_400);
    }

    #[test]
    fn empty_file_is_an_empty_layer() {
        let layer = parse_layer("").unwrap();
        assert!(layer.pin.is_none());
        assert!(layer.methods.is_none());
        assert!(layer.context.is_empty());
    }

    // ── Brief tests ──────────────────────────────────────────────────────

    #[test]
    fn pin_methods_and_context_keys_of_the_schema_parse() {
        let toml_str = r#"
[pin]
min_length = 4
max_length = 127
digits = "required"
lowercase = "allowed"
uppercase = "disallowed"
special = "required"
history = 50
expiry_days = 730
lockout_attempts = 32
lockout_minutes = 1440

[methods]
biometrics_allowed = true
face_requires_ir = true
require_hardware_tpm = true

[context.login]
methods = ["pin"]
factors = 1

[context.unlock]
methods = ["face", "fingerprint", "pin"]
factors = 2
reverify_after = "30d"

[context.sudo]
methods = ["pin"]
factors = 1
reverify_after = "1s"

[context.session]
methods = ["pin", "face"]
factors = 2
reverify_after = "8h"
"#;
        let layer = parse_layer(toml_str).unwrap();

        let pin = layer.pin.as_ref().unwrap();
        assert_eq!(pin.min_length, Some(4));
        assert_eq!(pin.max_length, Some(127));
        assert_eq!(pin.digits.as_deref(), Some("required"));
        assert_eq!(pin.lowercase.as_deref(), Some("allowed"));
        assert_eq!(pin.uppercase.as_deref(), Some("disallowed"));
        assert_eq!(pin.special.as_deref(), Some("required"));
        assert_eq!(pin.history, Some(50));
        assert_eq!(pin.expiry_days, Some(730));
        assert_eq!(pin.lockout_attempts, Some(32));
        assert_eq!(pin.lockout_minutes, Some(1440));

        let methods = layer.methods.as_ref().unwrap();
        assert_eq!(methods.biometrics_allowed, Some(true));
        assert_eq!(methods.face_requires_ir, Some(true));
        assert_eq!(methods.require_hardware_tpm, Some(true));

        assert_eq!(layer.context.len(), 4);
        let login = layer.context.get("login").unwrap();
        assert_eq!(login.methods, vec!["pin"]);
        assert_eq!(login.factors, Some(1));

        let unlock = layer.context.get("unlock").unwrap();
        assert_eq!(unlock.methods, vec!["face", "fingerprint", "pin"]);
        assert_eq!(unlock.factors, Some(2));
        assert_eq!(
            unlock.reverify_after.as_ref().unwrap().total_seconds(),
            30 * 86_400
        );

        let sudo = layer.context.get("sudo").unwrap();
        assert_eq!(sudo.reverify_after.as_ref().unwrap().total_seconds(), 1);

        let session = layer.context.get("session").unwrap();
        assert_eq!(session.methods, vec!["pin", "face"]);
        assert_eq!(session.factors, Some(2));
    }

    #[test]
    fn pin_class_value_outside_the_schema_makes_file_unparseable() {
        let toml_str = r#"
[pin]
digits = "optional"
"#;
        let err = parse_layer(toml_str).unwrap_err();
        assert!(
            err.contains("required|allowed|disallowed"),
            "expected class-value error, got: {err}"
        );

        let toml_str = r#"
[pin]
special = "forbidden"
"#;
        let err = parse_layer(toml_str).unwrap_err();
        assert!(
            err.contains("required|allowed|disallowed"),
            "expected class-value error, got: {err}"
        );

        let toml_str = r#"
[pin]
lowercase = "yes"
"#;
        let err = parse_layer(toml_str).unwrap_err();
        assert!(
            err.contains("required|allowed|disallowed"),
            "expected class-value error, got: {err}"
        );
    }

    #[test]
    fn pin_and_context_value_out_of_range_makes_file_unparseable() {
        // min_length: below and above
        for val in [3u32, 65] {
            let s = format!("[pin]\nmin_length = {val}\n");
            let err = parse_layer(&s).unwrap_err();
            assert!(err.contains("min_length"), "got: {err}");
        }
        // max_length: below and above
        for val in [3u32, 128] {
            let s = format!("[pin]\nmax_length = {val}\n");
            let err = parse_layer(&s).unwrap_err();
            assert!(err.contains("max_length"), "got: {err}");
        }
        // history: above
        let s = "[pin]\nhistory = 51\n";
        let err = parse_layer(s).unwrap_err();
        assert!(err.contains("history"), "got: {err}");
        // expiry_days: below and above
        for val in [0u32, 731] {
            let s = format!("[pin]\nexpiry_days = {val}\n");
            let err = parse_layer(&s).unwrap_err();
            assert!(err.contains("expiry_days"), "got: {err}");
        }
        // lockout_attempts: below and above
        for val in [0u32, 33] {
            let s = format!("[pin]\nlockout_attempts = {val}\n");
            let err = parse_layer(&s).unwrap_err();
            assert!(err.contains("lockout_attempts"), "got: {err}");
        }
        // lockout_minutes: below and above
        for val in [0u32, 1441] {
            let s = format!("[pin]\nlockout_minutes = {val}\n");
            let err = parse_layer(&s).unwrap_err();
            assert!(err.contains("lockout_minutes"), "got: {err}");
        }
        // factors: below and above
        for val in [0u32, 3] {
            let s = format!("[context.unlock]\nmethods = [\"pin\"]\nfactors = {val}\n");
            let err = parse_layer(&s).unwrap_err();
            assert!(err.contains("factors"), "got: {err}");
        }
    }

    #[test]
    fn unknown_context_name_makes_file_unparseable() {
        let toml_str = r#"
[context.bogus]
methods = ["pin"]
"#;
        let err = parse_layer(toml_str).unwrap_err();
        assert!(
            err.contains("login|unlock|sudo|session"),
            "expected context-name error, got: {err}"
        );

        let toml_str = r#"
[context.Sudo]
methods = ["pin"]
"#;
        let err = parse_layer(toml_str).unwrap_err();
        assert!(
            err.contains("login|unlock|sudo|session"),
            "expected context-name error, got: {err}"
        );
    }

    #[test]
    fn reverify_after_outside_one_second_to_thirty_days_makes_file_unparseable() {
        for dur in ["31d", "721h", "2592001s"] {
            let s = format!("[context.unlock]\nmethods = [\"pin\"]\nreverify_after = \"{dur}\"\n");
            let err = parse_layer(&s).unwrap_err();
            assert!(
                err.contains("reverify_after"),
                "expected range error for '{dur}', got: {err}"
            );
        }
        // Boundary values still parse.
        for dur in ["30d", "1s"] {
            let s = format!("[context.unlock]\nmethods = [\"pin\"]\nreverify_after = \"{dur}\"\n");
            let layer = parse_layer(&s).unwrap();
            let ctx = layer.context.get("unlock").unwrap();
            assert!(ctx.reverify_after.is_some());
        }
    }
}
