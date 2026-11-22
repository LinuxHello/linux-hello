//! Builds the QML plugin `io.github.LinuxHello.AgentLink` with cxx-qt-build (ADR-0028).
use cxx_qt_build::{CxxQtBuilder, PluginType, QmlModule};

fn main() {
    CxxQtBuilder::new_qml_module(
        QmlModule::new("io.github.LinuxHello.AgentLink").plugin_type(PluginType::Dynamic),
    )
    .files(["src/bridge.rs"])
    .build();
}
