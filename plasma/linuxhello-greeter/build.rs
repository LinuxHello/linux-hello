//! Links the Qt modules the greeter uses, and cxx-qt-lib's start-up code, into the program.
use cxx_qt_build::CxxQtBuilder;

fn main() {
    CxxQtBuilder::new()
        .qt_module("Gui")
        .qt_module("Qml")
        .build();
}
