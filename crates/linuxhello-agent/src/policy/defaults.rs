//! The default policy layer.
//!
//! This module provides a single source of truth for the base policy settings
//! used by the system when no other layers are provided.

use crate::policy::schema::{
    ContextPolicy, Duration, DurationUnit, Layer, MethodsPolicy, PinPolicy,
};
use std::collections::HashMap;

/// Returns the default policy layer as defined by the system requirements.
pub fn default_layer() -> Layer {
    let mut context = HashMap::new();

    let default_methods = vec![
        "pin".to_string(),
        "fingerprint".to_string(),
        "face".to_string(),
    ];

    context.insert(
        "login".to_string(),
        ContextPolicy {
            methods: default_methods.clone(),
            factors: Some(1),
            reverify_after: None,
        },
    );
    context.insert(
        "unlock".to_string(),
        ContextPolicy {
            methods: default_methods.clone(),
            factors: Some(1),
            reverify_after: None,
        },
    );
    context.insert(
        "sudo".to_string(),
        ContextPolicy {
            methods: vec!["pin".to_string(), "fingerprint".to_string()],
            factors: Some(1),
            reverify_after: None,
        },
    );
    context.insert(
        "session".to_string(),
        ContextPolicy {
            methods: default_methods,
            factors: Some(1),
            reverify_after: Some(Duration {
                value: 8,
                unit: DurationUnit::Hours,
            }),
        },
    );

    Layer {
        pin: Some(PinPolicy {
            min_length: Some(6),
            max_length: Some(127),
            digits: Some("required".to_string()),
            lowercase: Some("allowed".to_string()),
            uppercase: Some("allowed".to_string()),
            special: Some("allowed".to_string()),
            history: Some(0),
            expiry_days: None,
            lockout_attempts: Some(5),
            lockout_minutes: Some(15),
        }),
        methods: Some(MethodsPolicy {
            biometrics_allowed: Some(true),
            face_requires_ir: Some(true),
            require_hardware_tpm: Some(true),
        }),
        context,
        rp_class: HashMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::load::Policy;
    use crate::policy::merge::merge;
    use crate::policy::schema::{parse_layer, RpPrompt, RpProvider};

    fn effective(toml: &str) -> Policy {
        Policy::Effective(merge(&[parse_layer(toml).unwrap()], None).unwrap())
    }

    fn layered(admin: &str, user: &str) -> Policy {
        let admin_layers = if admin.is_empty() {
            vec![]
        } else {
            vec![parse_layer(admin).unwrap()]
        };
        Policy::Effective(merge(&admin_layers, Some(&parse_layer(user).unwrap())).unwrap())
    }

    #[test]
    fn default_layer_matches_policy_semantics() {
        let layer = default_layer();
        let pin = layer.pin.as_ref().unwrap();
        assert_eq!(pin.min_length, Some(6));
        assert_eq!(pin.max_length, Some(127));
        assert_eq!(pin.digits.as_deref(), Some("required"));
        assert_eq!(pin.lowercase.as_deref(), Some("allowed"));
        assert_eq!(pin.uppercase.as_deref(), Some("allowed"));
        assert_eq!(pin.special.as_deref(), Some("allowed"));
        assert_eq!(pin.history, Some(0));
        assert_eq!(pin.expiry_days, None);
        assert_eq!(pin.lockout_attempts, Some(5));
        assert_eq!(pin.lockout_minutes, Some(15));

        let methods = layer.methods.as_ref().unwrap();
        assert_eq!(methods.biometrics_allowed, Some(true));
        assert_eq!(methods.face_requires_ir, Some(true));
        assert_eq!(methods.require_hardware_tpm, Some(true));

        let login = layer.context.get("login").unwrap();
        assert_eq!(login.methods, vec!["pin", "fingerprint", "face"]);
        assert_eq!(login.factors, Some(1));
        assert_eq!(login.reverify_after, None);

        let unlock = layer.context.get("unlock").unwrap();
        assert_eq!(unlock.methods, vec!["pin", "fingerprint", "face"]);
        assert_eq!(unlock.factors, Some(1));

        let sudo = layer.context.get("sudo").unwrap();
        assert_eq!(sudo.methods, vec!["pin", "fingerprint"]);
        assert_eq!(sudo.factors, Some(1));

        let session = layer.context.get("session").unwrap();
        assert_eq!(session.methods, vec!["pin", "fingerprint", "face"]);
        assert_eq!(session.factors, Some(1));
        assert_eq!(
            session.reverify_after.as_ref().unwrap().total_seconds(),
            8 * 3600
        );

        assert!(layer.rp_class.is_empty());
    }

    #[test]
    fn face_alone_does_not_authorise_sudo_by_default() {
        let pol = effective("");
        let sudo = pol.methods_for("sudo");
        assert_eq!(sudo.methods, vec!["pin", "fingerprint"]);
        assert_eq!(sudo.factors, 1);

        let login = pol.methods_for("login");
        assert_eq!(login.methods, vec!["pin", "fingerprint", "face"]);
        let unlock = pol.methods_for("unlock");
        assert_eq!(unlock.methods, vec!["pin", "fingerprint", "face"]);
        let session = pol.methods_for("session");
        assert_eq!(session.methods, vec!["pin", "fingerprint", "face"]);

        let admin_pol = layered(
            "[context.sudo]\nmethods = [\"pin\", \"fingerprint\", \"face\"]\nfactors = 1",
            "",
        );
        let sudo_admin = admin_pol.methods_for("sudo");
        assert!(sudo_admin.methods.contains(&"face".to_string()));
    }

    #[test]
    fn session_unlock_expires_by_default() {
        let pol = effective("");
        let session = pol.methods_for("session");
        assert_eq!(
            session.reverify_after.as_ref().unwrap().total_seconds(),
            28800
        );
        assert_eq!(pol.methods_for("login").reverify_after, None);
        assert_eq!(pol.methods_for("unlock").reverify_after, None);
        assert_eq!(pol.methods_for("sudo").reverify_after, None);

        // User cannot raise it
        let user_pol = layered("", "[context.session]\nmethods = [\"pin\", \"fingerprint\", \"face\"]\nreverify_after = \"12h\"");
        assert_eq!(
            user_pol
                .methods_for("session")
                .reverify_after
                .as_ref()
                .unwrap()
                .total_seconds(),
            28800
        );

        // User can lower it
        let user_pol_lower = layered("", "[context.session]\nmethods = [\"pin\", \"fingerprint\", \"face\"]\nreverify_after = \"1h\"");
        assert_eq!(
            user_pol_lower
                .methods_for("session")
                .reverify_after
                .as_ref()
                .unwrap()
                .total_seconds(),
            3600
        );

        // Admin can loosen it
        let admin_pol_loosen = layered("[context.session]\nmethods = [\"pin\", \"fingerprint\", \"face\"]\nreverify_after = \"24h\"", "");
        assert_eq!(
            admin_pol_loosen
                .methods_for("session")
                .reverify_after
                .as_ref()
                .unwrap()
                .total_seconds(),
            86400
        );
    }

    #[test]
    fn unmatched_rp_is_device_bound_by_default() {
        let pol = effective("");
        let dec = pol.decision_for("unknown.com");
        assert_eq!(dec.provider, RpProvider::Tpm);
        assert_eq!(dec.prompt, RpPrompt::Presence);
        assert_eq!(dec.factors, 1);
        assert!(!dec.require_second_credential);

        // User class cannot loosen it
        let user_pol = layered(
            "",
            "[rp_class.u]\nmatch = [\"unknown.com\"]\nprovider = \"any\"",
        );
        assert_eq!(
            user_pol.decision_for("unknown.com").provider,
            RpProvider::Tpm
        );

        // Admin class can loosen it
        let admin_pol = layered(
            "[rp_class.a]\nmatch = [\"unknown.com\"]\nprovider = \"any\"",
            "",
        );
        assert_eq!(
            admin_pol.decision_for("unknown.com").provider,
            RpProvider::Any
        );
    }
}
