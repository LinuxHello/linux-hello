//! The Routing Policy Engine: loads the default, user and admin policy layers and
//! answers which methods, providers and prompts apply. It fails closed: a policy it
//! cannot parse allows the PIN only. Semantics: `docs/architecture/policy-semantics.md`.
//!
//! C4 component: `policyEngine` ([workspace.dsl](https://github.com/LinuxHello/linux-hello/blob/main/docs/architecture/workspace.dsl))

pub mod restrict;
pub mod schema;

pub use restrict::{most_restrictive, Contradiction};
pub use schema::{parse_layer, Layer};
