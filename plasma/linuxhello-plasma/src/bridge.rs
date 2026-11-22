//! The cxx-qt bridge declaration of the `AgentLink` QML object, and nothing else. cxx-qt's macro
//! expands it into `unsafe` glue between Rust and C++ inside this crate, so this is the one module
//! of the crate allowed `unsafe` code (ADR-0028; listed in `scripts/ci/unsafe-allowlist.txt`).
//! The Rust behind the object is in `link`, under `deny(unsafe_code)`.
#![allow(unsafe_code)]

// cxx-qt wants the Rust type directly beside the bridge (`super::T`); it is defined in `link`.
pub use crate::link::AgentLinkRust;

/// The QML side of the Agent Link.
#[cxx_qt::bridge]
pub mod qobject {
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        /// Qt's string.
        type QString = cxx_qt_lib::QString;
    }

    // QML names in camelCase (`stateJson`, `stateJsonChanged`), as Qt's own types use.
    #[auto_cxx_name]
    extern "RustQt" {
        #[qobject]
        #[qml_element]
        #[qproperty(QString, state_json)]
        #[qproperty(bool, reachable)]
        type AgentLink = super::AgentLinkRust;

        #[qinvokable]
        fn ping(self: Pin<&mut AgentLink>);

        #[qinvokable]
        fn watch(self: Pin<&mut AgentLink>);

        #[qinvokable]
        fn follow(self: Pin<&mut AgentLink>, prompt_id: &QString);
    }

    impl cxx_qt::Threading for AgentLink {}
}
