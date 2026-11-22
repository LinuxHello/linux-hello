//! Tests of the desktop and people lists, on file contents written here.

use std::path::PathBuf;

use super::{desktop, exec_words, people, uid_range, Person};

/// A directory with the programs the session files name.
fn bin() -> (tempdir::Dir, Vec<PathBuf>) {
    let dir = tempdir::Dir::new();
    for program in ["startplasma-wayland", "gnome-session", "weston"] {
        std::fs::write(dir.path().join(program), "").expect("write");
    }
    let path = vec![dir.path().to_path_buf()];
    (dir, path)
}

/// A temporary directory removed at the end of the test, without a dependency.
mod tempdir {
    use std::path::{Path, PathBuf};

    /// The directory.
    pub struct Dir(PathBuf);

    impl Dir {
        /// A new, empty directory under the system's temporary directory.
        pub fn new() -> Self {
            static COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let n = COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "linuxhello-sessions-test-{}-{n}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create");
            Self(path)
        }

        /// Its path.
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[test]
fn exec_lines_are_split_into_words() {
    assert_eq!(
        exec_words(r#"/usr/bin/env "A B" --flag %U plain"#),
        vec!["/usr/bin/env", "A B", "--flag", "plain"]
    );
    assert_eq!(exec_words(r#""say \"hi\"""#), vec![r#"say "hi""#]);
    assert!(exec_words("   ").is_empty());
}

#[test]
fn a_wayland_desktop_gets_its_command_and_environment() {
    let (_dir, path) = bin();
    let text =
        "[Desktop Entry]\nName=Plasma (Wayland)\nExec=startplasma-wayland\nDesktopNames=KDE\n";
    let d = desktop(text, "plasma", false, None, &path).expect("desktop");
    assert_eq!(d.name, "Plasma (Wayland)");
    assert_eq!(d.command, vec!["startplasma-wayland"]);
    assert_eq!(
        d.env,
        vec![
            "XDG_SESSION_TYPE=wayland",
            "XDG_SESSION_DESKTOP=plasma",
            "XDG_CURRENT_DESKTOP=KDE"
        ]
    );
}

#[test]
fn an_x_desktop_is_started_through_startx() {
    let (_dir, path) = bin();
    let text = "[Desktop Entry]\nName=GNOME on Xorg\nExec=gnome-session\nDesktopNames=GNOME;\n";
    let d = desktop(text, "gnome-xorg", true, Some("/usr/bin/startx"), &path).expect("desktop");
    assert_eq!(
        d.command,
        vec!["/usr/bin/startx", "/usr/bin/env", "gnome-session"]
    );
    assert_eq!(d.env[2], "XDG_CURRENT_DESKTOP=GNOME");
    assert!(desktop(text, "gnome-xorg", true, None, &path).is_none());
}

#[test]
fn hidden_and_missing_desktops_are_left_out() {
    let (_dir, path) = bin();
    for text in [
        "[Desktop Entry]\nName=A\nExec=weston\nHidden=true\n",
        "[Desktop Entry]\nName=A\nExec=weston\nNoDisplay=true\n",
        "[Desktop Entry]\nName=A\nExec=not-installed\n",
        "[Desktop Entry]\nName=A\nTryExec=not-installed\nExec=weston\n",
        "[Other Group]\nName=A\nExec=weston\n",
    ] {
        assert!(desktop(text, "a", false, None, &path).is_none(), "{text}");
    }
    assert!(desktop(
        "[Desktop Entry]\nName=Weston\nExec=weston\n",
        "weston",
        false,
        None,
        &path
    )
    .is_some());
}

#[test]
fn only_people_who_can_sign_in_are_listed() {
    let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                  _greetd:x:999:999::/var/lib/greetd:/usr/sbin/nologin\n\
                  alex:x:1000:1000:Alex Example,,,:/home/alex:/bin/bash\n\
                  sam:x:1001:1001::/home/sam:/bin/zsh\n\
                  ghost:x:1002:1002::/home/ghost:/bin/false\n\
                  nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
                  broken line\n";
    assert_eq!(
        people(passwd, (1000, 60000)),
        vec![
            Person {
                account: "alex".into(),
                name: "Alex Example".into()
            },
            Person {
                account: "sam".into(),
                name: "sam".into()
            },
        ]
    );
}

#[test]
fn the_id_range_comes_from_login_defs() {
    assert_eq!(
        uid_range("# UID_MIN 5\nUID_MIN\t\t 2000\nUID_MAX 3000\n"),
        (2000, 3000)
    );
    assert_eq!(uid_range(""), (1000, 60000));
}
