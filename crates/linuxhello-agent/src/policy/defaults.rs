//! The default policy layer.
//!
//! This module provides a single source of truth for the base policy settings
//! used by the system when no other layers are provided.

use crate::policy::schema::{ContextPolicy, Layer, MethodsPolicy, PinPolicy};
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
            methods: default_methods.clone(),
            factors: Some(1),
            reverify_after: None,
        },
    );
    context.insert(
        "session".to_string(),
        ContextPolicy {
            methods: default_methods,
            factors: Some(1),
            reverify_after: None,
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
        assert_eq!(sudo.methods, vec!["pin", "fingerprint", "face"]);
        assert_eq!(sudo.factors, Some(1));

        let session = layer.context.get("session").unwrap();
        assert_eq!(session.methods, vec!["pin", "fingerprint", "face"]);
        assert_eq!(session.factors, Some(1));

        assert!(layer.rp_class.is_empty());
    }
}
