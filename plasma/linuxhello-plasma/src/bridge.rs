//! The cxx-qt bridge declarations of the `AgentLink` and `Greetd` QML objects, and nothing else. cxx-qt's macro
//! expands it into `unsafe` glue between Rust and C++ inside this crate, so this is the one module
//! of the crate allowed `unsafe` code (ADR-0028; listed in `scripts/ci/unsafe-allowlist.txt`).
//! The Rust behind the objects is in `link` and `greeter`, under `deny(unsafe_code)`.
#![allow(unsafe_code)]

// cxx-qt wants the Rust type directly beside the bridge (`super::T`); it is defined in `link`.
pub use crate::greeter::GreetdRust;
pub use crate::link::AgentLinkRust;

/// The QML side of the Agent Link and of the greeter's link to greetd.
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

    #[auto_cxx_name]
    extern "RustQt" {
        #[qobject]
        #[qml_element]
        #[qproperty(QString, phase)]
        #[qproperty(QString, question)]
        #[qproperty(bool, secret)]
        #[qproperty(QString, lines_json)]
        #[qproperty(QString, desktops_json)]
        #[qproperty(QString, people_json)]
        type Greetd = super::GreetdRust;

        #[qinvokable]
        fn load(self: Pin<&mut Greetd>);

        #[qinvokable]
        fn begin(self: Pin<&mut Greetd>, account: &QString);

        #[qinvokable]
        fn answer(self: Pin<&mut Greetd>, text: &QString);

        #[qinvokable]
        fn start(self: Pin<&mut Greetd>, index: i32);

        #[qinvokable]
        fn cancel(self: Pin<&mut Greetd>);
    }

    impl cxx_qt::Threading for Greetd {}
}
