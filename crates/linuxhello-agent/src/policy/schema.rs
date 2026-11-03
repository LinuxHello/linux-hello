use std::collections::HashMap;

use serde::Deserialize;

/// A fully parsed and validated admin-layer policy layer.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub pin: Option<PinPolicy>,
    #[serde(default)]
    pub methods: Option<MethodsPolicy>,
    #[serde(default)]
    pub context: HashMap<String, ContextPolicy>,
    #[serde(default)]
    pub rp_class: HashMap<String, RpClassPolicy>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinPolicy {
    #[serde(default)]
    pub min_length: Option<u32>,
    #[serde(default)]
    pub digits: Option<String>,
    #[serde(default)]
    pub special: Option<String>,
    #[serde(default)]
    pub lockout_attempts: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MethodsPolicy {
    #[serde(default)]
    pub biometrics_allowed: Option<bool>,
    #[serde(default)]
    pub face_requires_ir: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPolicy {
    pub methods: Vec<String>,
    #[serde(default)]
    pub reverify_after: Option<Duration>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpClassPolicy {
    #[serde(rename = "match")]
    pub match_patterns: Vec<String>,
    pub provider: String,
    pub factors: u32,
    #[serde(default)]
    pub require_second_credential: Option<bool>,
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

fn is_valid_domain_glob(pattern: &str) -> bool {
    !pattern.is_empty()
        && pattern
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '*')
}

fn is_valid_method(name: &str) -> bool {
    matches!(name, "pin" | "face" | "fingerprint")
}

fn is_valid_provider(name: &str) -> bool {
    matches!(name, "tpm" | "kpxc")
}

fn is_valid_pin_option(value: &str) -> bool {
    matches!(value, "required" | "optional" | "forbidden" | "allowed")
}

/// Parse and validate a TOML policy layer.
///
/// Returns an error if the file contains unknown keys, out-of-range values,
/// invalid patterns, duplicate methods, or any other schema violation.
pub fn parse(input: &str) -> Result<Policy, String> {
    let policy: Policy = toml::from_str(input).map_err(|e| format!("TOML parse error: {e}"))?;
    validate(&policy)?;
    Ok(policy)
}

fn validate(policy: &Policy) -> Result<(), String> {
    if let Some(pin) = &policy.pin {
        if let Some(ml) = pin.min_length {
            if ml < 4 {
                return Err(format!("pin.min_length must be >= 4, got {ml}"));
            }
        }
        if let Some(la) = pin.lockout_attempts {
            if la < 1 {
                return Err(format!("pin.lockout_attempts must be >= 1, got {la}"));
            }
        }
        if let Some(d) = &pin.digits {
            if !is_valid_pin_option(d) {
                return Err(format!(
                    "pin.digits must be one of required|optional|forbidden, got '{d}'"
                ));
            }
        }
        if let Some(s) = &pin.special {
            if !is_valid_pin_option(s) {
                return Err(format!(
                    "pin.special must be one of allowed|forbidden, got '{s}'"
                ));
            }
        }
    }

    for (name, ctx) in &policy.context {
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
    }

    for (name, rp) in &policy.rp_class {
        if rp.match_patterns.is_empty() {
            return Err(format!("rp_class.{name}.match must not be empty"));
        }
        for pattern in &rp.match_patterns {
            if !is_valid_domain_glob(pattern) {
                return Err(format!(
                    "rp_class.{name}.match contains invalid domain pattern '{pattern}'"
                ));
            }
        }
        if !is_valid_provider(&rp.provider) {
            return Err(format!(
                "rp_class.{name}.provider must be 'tpm' or 'kpxc', got '{}'",
                rp.provider
            ));
        }
        if rp.factors < 1 {
            return Err(format!(
                "rp_class.{name}.factors must be >= 1, got {}",
                rp.factors
            ));
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
        let err = parse(toml_str).unwrap_err();
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
        let err = parse(toml_str).unwrap_err();
        assert!(
            err.contains("min_length") && err.contains(">= 4"),
            "expected range error, got: {err}"
        );
    }

    #[test]
    fn invalid_rp_pattern_makes_file_unparseable() {
        let toml_str = r#"
[rp_class.banking]
match = ["!!invalid!!"]
provider = "tpm"
factors = 2
"#;
        let err = parse(toml_str).unwrap_err();
        assert!(
            err.contains("invalid domain pattern"),
            "expected pattern error, got: {err}"
        );
    }

    #[test]
    fn duplicate_method_makes_file_unparseable() {
        let toml_str = r#"
[context.unlock]
methods = ["pin", "pin"]
"#;
        let err = parse(toml_str).unwrap_err();
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
        let err = parse(toml_str).unwrap_err();
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
        let policy = parse(toml_str).unwrap();
        let ctx = policy.context.get("unlock").unwrap();
        let dur = ctx.reverify_after.as_ref().unwrap();
        assert_eq!(dur.value, 8);
        assert_eq!(dur.unit, DurationUnit::Hours);
        assert_eq!(dur.total_seconds(), 8 * 3600);

        let toml_str = r#"
[context.unlock]
methods = ["pin"]
reverify_after = "30m"
"#;
        let policy = parse(toml_str).unwrap();
        let ctx = policy.context.get("unlock").unwrap();
        let dur = ctx.reverify_after.as_ref().unwrap();
        assert_eq!(dur.value, 30);
        assert_eq!(dur.unit, DurationUnit::Minutes);
        assert_eq!(dur.total_seconds(), 30 * 60);

        let toml_str = r#"
[context.unlock]
methods = ["pin"]
reverify_after = "1d"
"#;
        let policy = parse(toml_str).unwrap();
        let ctx = policy.context.get("unlock").unwrap();
        let dur = ctx.reverify_after.as_ref().unwrap();
        assert_eq!(dur.value, 1);
        assert_eq!(dur.unit, DurationUnit::Days);
        assert_eq!(dur.total_seconds(), 86_400);
    }

    #[test]
    fn example_policy_parses() {
        let toml_str = r#"
[pin]
min_length = 6
digits = "required"
special = "allowed"
lockout_attempts = 5

[methods]
biometrics_allowed = true
face_requires_ir = true

[context.sudo]
methods = ["pin"]

[context.unlock]
methods = ["face", "fingerprint", "pin"]
reverify_after = "8h"

[rp_class.banking]
match = ["*.bank.example"]
provider = "tpm"
factors = 2
require_second_credential = true
"#;
        let policy = parse(toml_str).unwrap();

        let pin = policy.pin.as_ref().unwrap();
        assert_eq!(pin.min_length, Some(6));
        assert_eq!(pin.digits.as_deref(), Some("required"));
        assert_eq!(pin.special.as_deref(), Some("allowed"));
        assert_eq!(pin.lockout_attempts, Some(5));

        let methods = policy.methods.as_ref().unwrap();
        assert_eq!(methods.biometrics_allowed, Some(true));
        assert_eq!(methods.face_requires_ir, Some(true));

        assert_eq!(policy.context.len(), 2);
        let sudo = policy.context.get("sudo").unwrap();
        assert_eq!(sudo.methods, vec!["pin"]);

        let unlock = policy.context.get("unlock").unwrap();
        assert_eq!(unlock.methods, vec!["face", "fingerprint", "pin"]);
        assert_eq!(
            unlock.reverify_after.as_ref().unwrap().total_seconds(),
            8 * 3600
        );

        assert_eq!(policy.rp_class.len(), 1);
        let banking = policy.rp_class.get("banking").unwrap();
        assert_eq!(banking.match_patterns, vec!["*.bank.example"]);
        assert_eq!(banking.provider, "tpm");
        assert_eq!(banking.factors, 2);
        assert_eq!(banking.require_second_credential, Some(true));
    }

    #[test]
    fn empty_file_is_an_empty_layer() {
        let policy = parse("").unwrap();
        assert!(policy.pin.is_none());
        assert!(policy.methods.is_none());
        assert!(policy.context.is_empty());
        assert!(policy.rp_class.is_empty());
    }
}
