//! The policy file schema: the types one TOML policy layer parses into, and the
//! validation that rejects anything outside the schema in
//! `docs/architecture/policy-semantics.md`. Parsing is strict: an unknown key, a
//! value out of range or a malformed duration makes the whole file unparseable.

use std::collections::HashMap;

use serde::Deserialize;

/// A fully parsed and validated admin-layer policy layer.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer {
    /// The `[pin]` table: PIN rules. Absent: the layer sets no PIN rule.
    #[serde(default)]
    pub pin: Option<PinPolicy>,
    /// The `[methods]` table: which kinds of method are allowed at all.
    #[serde(default)]
    pub methods: Option<MethodsPolicy>,
    /// The `[context.<name>]` tables, keyed by context name (`login`, `unlock`, `sudo`, `session`).
    #[serde(default)]
    pub context: HashMap<String, ContextPolicy>,
        #[serde(default)]
    pub rp_class: HashMap<String, RpClassPolicy>,
}

/// The `[pin]` table: length, character classes, history, expiry and lockout of the PIN.
/// Every key is optional; an absent key leaves the value to other layers or the default.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinPolicy {
    #[serde(default)]
    /// Shortest allowed PIN, 4–64 characters.
    pub min_length: Option<u32>,
    #[serde(default)]
    /// Longest allowed PIN, 4–127 characters.
    pub max_length: Option<u32>,
    #[serde(default)]
    /// Digits: `required`, `allowed` or `disallowed`.
    pub digits: Option<String>,
    #[serde(default)]
    /// Lower-case letters: `required`, `allowed` or `disallowed`.
    pub lowercase: Option<String>,
    #[serde(default)]
    /// Upper-case letters: `required`, `allowed` or `disallowed`.
    pub uppercase: Option<String>,
    #[serde(default)]
    /// Special characters: `required`, `allowed` or `disallowed`.
    pub special: Option<String>,
    #[serde(default)]
    /// How many previous PINs may not be reused, 0–50 (0: no history).
    pub history: Option<u32>,
    #[serde(default)]
    /// Days until the PIN must be changed, 1–730. Absent: the PIN never expires.
    pub expiry_days: Option<u32>,
    #[serde(default)]
    /// Wrong PIN entries before lockout, 1–32.
    pub lockout_attempts: Option<u32>,
    #[serde(default)]
    /// Minutes a lockout lasts, 1–1440.
    pub lockout_minutes: Option<u32>,
}

/// The `[methods]` table: switches that apply to every context.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MethodsPolicy {
    #[serde(default)]
    /// Whether face and fingerprint may be used at all; false means PIN only.
    pub biometrics_allowed: Option<bool>,
    #[serde(default)]
    /// Whether face recognition needs an infrared camera.
    pub face_requires_ir: Option<bool>,
    #[serde(default)]
    /// Whether a hardware TPM is required, refusing a software TPM.
    pub require_hardware_tpm: Option<bool>,
}

/// One `[context.<name>]` table: how the user authenticates in that context.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPolicy {
    /// Allowed methods: a non-empty list of `pin`, `fingerprint` and `face`, without duplicates.
    pub methods: Vec<String>,
    /// How many different methods must succeed, 1–2.
    #[serde(default)]
    pub factors: Option<u32>,
    /// How long an authentication stays valid before the user must verify again, 1 s to 30 d.
    #[serde(default)]
    pub reverify_after: Option<Duration>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpClassPolicy {
    pub match_patterns: Vec<String>,
    pub provider: RpProvider,
    pub prompt: RpPrompt,
    #[serde(default)]
    pub factors: Option<u32>,
    #[serde(default)]
    pub require_second_credential: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RpProvider {
    Tpm,
    Keepassxc,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RpPrompt {
    None,
    Presence,
    Reverify,
}

/// A duration expressed as a positive integer followed by a unit suffix (s, m, h, d).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Duration {
    /// The number before the suffix; greater than zero.
    pub value: u64,
    /// The unit the suffix names.
    pub unit: DurationUnit,
}

/// The unit of a [`Duration`], named by its suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurationUnit {
    /// Suffix `s`.
    Seconds,
    /// Suffix `m`.
    Minutes,
    /// Suffix `h`.
    Hours,
    /// Suffix `d`.
    Days,
}

impl DurationUnit {
    /// The length of one unit in seconds.
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

/// Parse a duration string such as `8h`: digits, then exactly one unit suffix.
/// Refuses an empty string, zero, an unknown or missing suffix, trailing characters,
/// and any duration whose seconds do not fit in a `u64`.
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

/// Whether `name` is a context the schema knows.
fn is_valid_context_name(name: &str) -> bool {
    matches!(name, "login" | "unlock" | "sudo" | "session")
}

/// Whether `name` is an authentication method the schema knows.
fn is_valid_method(name: &str) -> bool {
    matches!(name, "pin" | "face" | "fingerprint")
}

/// Whether `value` is a setting a PIN character class may take.
fn is_valid_pin_class_value(value: &str) -> bool {
    matches!(value, "required" | "allowed" | "disallowed")
}

fn is_valid_rp_class_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn is_valid_rp_pattern(pattern: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    if let Some(domain) = pattern.strip_prefix("*.") {
        !domain.is_empty()
            && domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    } else if !pattern.contains('*') {
        pattern
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    } else {
        false
    }
}

#[allow(dead_code)]
fn normalize_rp_pattern(pattern: &str) -> Result<String, String> {
    if pattern.is_empty() {
        return Err("pattern must not be empty".into());
    }
    if let Some(domain) = pattern.strip_prefix("*.") {
        if domain.is_empty() {
            return Err("pattern must have a domain after '*.'".into());
        }
        Ok(format!("*.{}", domain.to_lowercase().trim_end_matches('.')))
    } else if !pattern.contains('*') {
        Ok(pattern.to_lowercase().trim_end_matches('.').to_string())
    } else {
        Err(format!("invalid rp pattern '{pattern}'"))
    }
}

/// Parse and validate a TOML policy layer.
///
/// Returns an error if the file contains unknown keys, out-of-range values,
/// invalid patterns, duplicate methods, or any other schema violation.
pub fn parse_layer(input: &str) -> Result<Layer, String> {
    let mut layer: Layer = toml::from_str(input).map_err(|e| format!("TOML parse error: {e}"))?;
    validate(&mut layer)?;
    Ok(layer)
}

/// Check the value ranges and lists the TOML types cannot express; the first
/// violation found is the error.
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

    for (name, ctx) in &mut layer.context {
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

    for (name, rp_class) in &mut layer.rp_class {
        if !is_valid_rp_class_name(name) {
            return Err(format!("rp_class name '{name}' is invalid"));
        }
        if let Some(f) = rp_class.factors {
            if !(1..=2).contains(&f) {
                return Err(format!("rp_class.{name}.factors must be 1–2, got {f}"));
            }
        }
        for pattern in &mut rp_class.match_patterns {
            if !is_valid_rp_pattern(pattern) {
                return Err(format!(
                    "rp_class.{name}.match contains invalid pattern '{pattern}'"
                ));
            } else {
                *pattern = normalize_rp_pattern(pattern).map_err(|e| {
                    format!(
                        "rp_class.{name}.match contains invalid pattern '{pattern}': {e}",
                        pattern = pattern
                    )
                })?;
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

    #[test]
    fn rp_class_keys_of_the_schema_parse() {
        let toml_str = r#"
[rp_class.example]
provider = "tpm"
prompt = "presence"
match_patterns = []
"#;
        let layer = parse_layer(toml_str).unwrap();
        let rp_class = &layer.rp_class;
        let policy = rp_class.get("example").unwrap();
        assert_eq!(policy.provider, RpProvider::Tpm);
        assert_eq!(policy.prompt, RpPrompt::Presence);
    }

    #[test]
    fn rp_class_value_outside_the_schema_makes_file_unparseable() {
        let toml_str = r#"
[rp_class.example]
provider = "invalid"
prompt = "presence"
match_patterns = []
"#;
        let err = parse_layer(toml_str).unwrap_err();
        assert!(
            err.contains("provider"),
            "expected provider error, got: {err}"
        );
    }

    #[test]
    fn invalid_rp_class_name_makes_file_unparseable() {
        let toml_str = r#"
[rp_class."invalid name!"]
provider = "tpm"
prompt = "presence"
match_patterns = []
"#;
        let err = parse_layer(toml_str).unwrap_err();
        assert!(
            err.contains("rp_class name"),
            "expected name error, got: {err}"
        );
    }

    #[test]
    fn rp_pattern_outside_the_schema_makes_file_unparseable() {
        let toml_str = r#"
[rp_class.example]
provider = "tpm"
prompt = "presence"
match_patterns = ["invalid*pattern"]
"#;
        let err = parse_layer(toml_str).unwrap_err();
        assert!(
            err.contains("pattern"),
            "expected pattern error, got: {err}"
        );
    }

    #[test]
    fn rp_patterns_are_stored_lower_case_without_trailing_dot() {
        let toml_str = r#"
[rp_class.example]
provider = "tpm"
prompt = "presence"
match_patterns = ["Pattern.With.Dot."]
"#;
        let layer = parse_layer(toml_str).unwrap();
        let rp_class = &layer.rp_class;
        let policy = rp_class.get("example").unwrap();
        assert_eq!(policy.prompt, RpPrompt::Presence);
        assert_eq!(policy.match_patterns, vec!["pattern.with.dot".to_string()]);
    }

    #[test]
    fn rp_class_keys_of_the_schema_parse_with_extra_fields() {
        let toml_str = r#"
[rp_class.example]
provider = "tpm"
prompt = "presence"
match_patterns = []
require_second_credential = true
factors = 2
"#;
        let layer = parse_layer(toml_str).unwrap();
        let rp_class = &layer.rp_class;
        let policy = rp_class.get("example").unwrap();
        assert_eq!(policy.provider, RpProvider::Tpm);
        assert_eq!(policy.prompt, RpPrompt::Presence);
        assert_eq!(policy.require_second_credential, Some(true));
        assert_eq!(policy.factors, Some(2));
    }

    #[test]
    fn require_second_credential_makes_file_unparseable() {
        let toml_str = r#"
[rp_class.example]
provider = "tpm"
prompt = "presence"
match_patterns = []
require_second_credential = "not_a_bool"
"#;
        let err = parse_layer(toml_str).unwrap_err();
        assert!(
            err.contains("require_second_credential"),
            "expected error for non-boolean require_second_credential, got: {err}"
        );
    }

    #[test]
    fn require_second_credential_is_validated_for_factors_range() {
        // Factors must be 1-2
        for val in [0u32, 3] {
            let s = format!(
                "[rp_class.example]\nprovider=\"tpm\"\nprompt=\"presence\"\nmatch_patterns=[]\nrequire_second_credential=true\nfactors={val}\n"
            );
            let err = parse_layer(&s).unwrap_err();
            assert!(
                err.contains("factors"),
                "expected factors error, got: {err}"
            );
        }
    }
}
