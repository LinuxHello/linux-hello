//! The Routing Policy Engine: loads the default, user and admin policy layers and
//! answers which methods, providers and prompts apply. It fails closed: a policy it
//! cannot parse allows the PIN only. Semantics: `docs/architecture/policy-semantics.md`.
//!
//! C4 component: `policyEngine` ([workspace.dsl](https://github.com/LinuxHello/architecture/blob/main/workspace.dsl))

pub mod defaults;
/// The default policy layer.
pub mod merge;
/// The policy merging logic.
pub mod restrict;
/// Restrictiveness: combines two policy layers key by key into the more
/// restrictive one, and reports a character class one layer requires and the
/// other disallows. `merge` (a later issue) uses it to combine the admin layers
/// and to let a user layer tighten the defaults.
pub mod schema;
/// The policy file schema: the types one TOML policy layer parses into, and the
/// validation that rejects anything outside the schema in
/// `docs/architecture/policy-semantics.md`. Parsing is strict: an unknown key, a
/// value out of range or a malformed duration makes the whole file unparseable.
pub use defaults::default_layer;
pub use merge::{merge, Effective};
pub use restrict::{most_restrictive, Contradiction};
pub use schema::{parse_layer, Layer};
