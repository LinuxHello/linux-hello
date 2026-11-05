//! The Routing Policy Engine: loads the default, user and admin policy layers and
//! answers which methods, providers and prompts apply. It fails closed: a policy it
//! cannot parse allows the PIN only. Semantics: `docs/architecture/policy-semantics.md`.
//!
//! C4 component: `policyEngine` ([workspace.dsl](https://github.com/LinuxHello/architecture/blob/main/workspace.dsl))

/// The built-in default policy layer (`default_layer`).
pub mod defaults;
/// The invariants that hold after layering: the PIN is always allowed, biometrics
/// off means PIN only, and a PIN rule no PIN can meet is an error (`apply_invariants`).
pub mod invariants;
/// The policy loading logic.
pub mod load;
/// Admin-over-user layering into the effective policy (`merge`, `Effective`).
pub mod merge;
pub mod restrict;
pub mod schema;

pub use defaults::default_layer;
pub use load::{load, PinOnly, Policy};
pub use merge::{merge, Effective};
pub use restrict::{most_restrictive, Contradiction};
pub use schema::{parse_layer, Layer};
