//! The rule of ADR-0026 for this crate: the command-line tool starts no program.

use std::path::{Path, PathBuf};

/// Every `.rs` file under `dir`.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The code of a source file without its tests: a file named `tests.rs` has none, and the rest of
/// a file is cut at its first `#[cfg(test)]`, which in this crate opens the test module at its end.
fn code_of(path: &Path) -> String {
    if path.file_name().is_some_and(|n| n == "tests.rs") {
        return String::new();
    }
    let text = std::fs::read_to_string(path).unwrap();
    text.split("#[cfg(test)]")
        .next()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn the_cli_starts_no_program() {
    let mut files = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert!(files.len() > 5, "the sources were found: {files:?}");
    for file in files {
        let code = code_of(&file);
        for forbidden in [
            "process::Command",
            "Command::new",
            "libc::system",
            "execv",
            "posix_spawn",
        ] {
            assert!(
                !code.contains(forbidden),
                "{} uses {forbidden} outside its tests (ADR-0026)",
                file.display()
            );
        }
    }
}
