//! The Linux Hello Greeter: Linux Hello's own login screen, a greeter for greetd (ADR-0016,
//! amendment of 2026-11-21; ADR-0028, amendment of 2026-11-22).
//!
//! greetd, the login service, runs PAM and starts the chosen desktop; it runs this program under
//! cage, a compositor that shows one program full screen, and talks to it over a socket. This
//! program only opens the greeter's QML window, `Main.qml`; the window talks to greetd and to the
//! Linux Hello Agent through the Agent Link plugin. It starts no other program (ADR-0026).
//!
//! ```text
//! linuxhello-greeter [--qml FILE] [--import DIR]...
//! ```
//!
//! `--qml` names the window's file (default `/usr/share/linuxhello/greeter/Main.qml`), and each
//! `--import` adds a directory of QML modules (default `/usr/lib/linuxhello/qml`, where the
//! installer puts the Agent Link and the Auth Prompt). The arguments come from greetd's
//! configuration, which only root can change. Exits with 1 when the window does not load, so that
//! greetd does not keep an empty screen.
//!
//! C4 container: `plasma` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl)),
//! component `greeter`.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use cxx_qt_lib::{QGuiApplication, QQmlApplicationEngine, QString, QUrl};

/// The window's file when `--qml` is not given.
const DEFAULT_QML: &str = "/usr/share/linuxhello/greeter/Main.qml";

/// The directory of Linux Hello's QML modules when no `--import` is given.
const DEFAULT_IMPORT: &str = "/usr/lib/linuxhello/qml";

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
struct Options {
    /// The window's file.
    qml: String,
    /// The directories of QML modules.
    imports: Vec<String>,
}

/// Reads the arguments after the program's name; `Err` names the first one it does not know.
/// Qt's own arguments (such as `-platform`) are left to Qt.
fn options(args: &[String]) -> Result<Options, String> {
    let mut qml = None;
    let mut imports = Vec::new();
    let mut words = args.iter();
    while let Some(word) = words.next() {
        match word.as_str() {
            "--qml" => qml = Some(words.next().ok_or("--qml needs a file")?.clone()),
            "--import" => imports.push(words.next().ok_or("--import needs a directory")?.clone()),
            other if other.starts_with("--") => return Err(format!("unknown option {other}")),
            _ => {}
        }
    }
    if imports.is_empty() {
        imports.push(DEFAULT_IMPORT.to_string());
    }
    Ok(Options {
        qml: qml.unwrap_or_else(|| DEFAULT_QML.to_string()),
        imports,
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = match options(&args) {
        Ok(options) => options,
        Err(e) => {
            eprintln!("linuxhello-greeter: {e}");
            return ExitCode::from(2);
        }
    };
    let qml = match std::fs::canonicalize(&options.qml) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("linuxhello-greeter: {}: {e}", options.qml);
            return ExitCode::FAILURE;
        }
    };
    // Under cage the session type is not set, and Qt would then try X11; cage is a Wayland
    // compositor. Set before Qt starts, while the program has one thread.
    if std::env::var_os("WAYLAND_DISPLAY").is_some()
        && std::env::var_os("QT_QPA_PLATFORM").is_none()
    {
        std::env::set_var("QT_QPA_PLATFORM", "wayland");
    }
    let mut app = QGuiApplication::new();
    let mut engine = QQmlApplicationEngine::new();
    let (Some(app), Some(mut engine)) = (app.as_mut(), engine.as_mut()) else {
        eprintln!("linuxhello-greeter: Qt did not start");
        return ExitCode::FAILURE;
    };
    for dir in &options.imports {
        engine.as_mut().add_import_path(&QString::from(dir));
    }
    engine
        .as_mut()
        .on_object_creation_failed(|_, url| {
            eprintln!("linuxhello-greeter: {url} did not load");
            std::process::exit(1);
        })
        .release();
    let url = format!("file://{}", qml.display());
    engine.load(&QUrl::from(url.as_str()));
    match app.exec() {
        0 => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::{options, Options, DEFAULT_IMPORT, DEFAULT_QML};

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn no_arguments_mean_the_installed_files() {
        assert_eq!(
            options(&[]),
            Ok(Options {
                qml: DEFAULT_QML.into(),
                imports: vec![DEFAULT_IMPORT.into()]
            })
        );
    }

    #[test]
    fn the_window_and_imports_can_be_named() {
        assert_eq!(
            options(&words(
                "--qml /a/Main.qml --import /x --import /y -platform offscreen"
            )),
            Ok(Options {
                qml: "/a/Main.qml".into(),
                imports: vec!["/x".into(), "/y".into()]
            })
        );
    }

    #[test]
    fn unknown_or_incomplete_options_are_refused() {
        assert!(options(&words("--shell /bin/sh")).is_err());
        assert!(options(&words("--qml")).is_err());
    }
}
