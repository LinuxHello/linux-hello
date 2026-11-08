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
/// Querying the effective policy for context methods and relying-party decisions.
pub mod query;
/// Restrictiveness: combines two policy layers key by key into the more
/// restrictive one, and reports a character class one layer requires and the
/// other disallows. `merge` (a later issue) uses it to combine the admin layers
/// and to let a user layer tighten the defaults. Rules:
/// `docs/architecture/policy-semantics.md`, *Restrictiveness*.
pub mod restrict;
/// The policy file schema: the types one TOML policy layer parses into, and the
/// validation that rejects anything outside the schema in
/// `docs/architecture/policy-semantics.md`. Parsing is strict: an unknown key, a
/// value out of range or a malformed duration makes the whole file unparseable.
pub mod schema;
/// The user policy store for managing per-user policy files.
pub mod user_store;
/// Reports on a loaded policy: its PIN rules and every effective value with its `managed` flag (`pin_rules`, `effective`).
pub mod view;

pub use defaults::default_layer;
pub use load::{load, PinOnly, Policy};
pub use merge::{merge, Effective};
pub use query::{MethodRule, RpDecision};
pub use restrict::{most_restrictive, Contradiction};
pub use schema::{parse_layer, Layer};
pub use user_store::{StoreError, UserPolicyStore};
pub use view::{EffectiveView, PinRules, Setting};
