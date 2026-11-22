# The Agent Link

The Agent Link is the small part through which Linux Hello's screens on KDE Plasma, such as its login screen and its part in KDE's lock screen, reach the Linux Hello Agent. The Agent is the system service that runs the fingerprint, the face and the PIN. The screens are written in QML, the language Plasma's screens are made of, and QML cannot talk to the Agent on its own: the Agent answers on D-Bus, the message service desktop programs use to call each other, and a screen may not start a program to do it for it ([ADR-0026](https://github.com/LinuxHello/linux-hello-architecture/blob/main/adr/0026-clients-reach-the-agent-directly.md)). So the Agent Link is a *QML plugin*, a library QML can import, written in Rust ([ADR-0028](https://github.com/LinuxHello/linux-hello-architecture/blob/main/adr/0028-plasma-agent-backend.md)).

It also holds the link to greetd that Linux Hello's own login screen, the [Linux Hello Greeter](../linuxhello-greeter/), needs: greetd is the login service that runs PAM (Pluggable Authentication Modules, the Linux system that asks a module such as Linux Hello's whether a person may sign in) and starts the chosen desktop, and it talks to the greeter over a socket that QML cannot open either ([ADR-0028, amendment of 2026-11-22](https://github.com/LinuxHello/linux-hello-architecture/blob/main/adr/0028-plasma-agent-backend.md)).

**State:** built and tested in the desktop test VM. The greeter uses it; KDE's lock screen does not yet.

## What it gives QML

```qml
import io.github.LinuxHello.AgentLink
import io.github.LinuxHello.AuthPrompt

AgentLink { id: link; Component.onCompleted: watch() }
AuthPrompt { agentState: JSON.parse(link.stateJson) }
```

It gives QML two objects. `AgentLink` has three calls and two properties:

| | What it does |
| :-- | :-- |
| `ping()` | Asks whether the Agent answers, and sets `reachable` |
| `watch()` | Follows every sign-in attempt the Agent says has started for this screen: the screen's own user's, and for a login screen's account the logins root started |
| `follow(id)` | Follows one attempt, by its id |
| `stateJson` | The attempt's state as JSON, in exactly the form the [Auth Prompt](../auth-prompt/) reads: which methods run, how each ended, the result |
| `reachable` | Whether the Agent answered |

It listens on a thread of its own and reads only signals whose sender is the Agent itself, so another program cannot feed the screen a state.

`Greetd` runs one sign-in through greetd for the greeter, following greetd's protocol ([greetd-ipc(7)](https://man.archlinux.org/man/greetd-ipc.7.en)): greetd passes on each of PAM's questions and lines with its kind, and the greeter answers.

| | What it does |
| :-- | :-- |
| `load()` | Reads the installed desktops (the session files in `/usr/share/wayland-sessions` and `/usr/share/xsessions`, which GDM and SDDM read too) and the people who can sign in (`/etc/passwd`) into `desktopsJson` and `peopleJson` |
| `begin(account)` | Starts a sign-in for an account |
| `answer(text)` | Answers PAM's question, such as the PIN |
| `start(index)` | Asks greetd to start the desktop at `index` once the greeter closes |
| `cancel()` | Ends the sign-in, to start another |
| `phase` | Where the sign-in stands: `idle`, `waiting` (greetd has not replied yet, for example while Linux Hello waits for a finger), `asking`, `refused`, `signed-in`, `started`, `failed` or `no-greetd` |
| `question`, `secret` | PAM's question while `phase` is `asking`, and whether the answer is hidden while typed |
| `linesJson` | PAM's info and error lines of the attempt, such as "Wrong PIN.", as JSON |

It answers PAM's info and error lines itself and stops at each question, so the screen only shows lines and asks questions. The conversation runs on a thread of its own, because PAM may take seconds to reply. It starts no program: greetd starts the desktop.

## How it is built

It uses cxx-qt, a library that lets Rust define objects QML can use. cxx-qt generates glue between Rust and C++ that needs `unsafe` code, so one module, `src/bridge.rs`, holds only the bridge declaration and is allowed `unsafe` code (invariant 4 in [AGENTS.md](../../AGENTS.md), `scripts/ci/unsafe-allowlist.txt`). Everything else is safe Rust: `src/fold.rs` turns what the Agent says into the Auth Prompt's state, `src/link.rs` talks to the Agent, `src/greetd.rs` speaks greetd's protocol, `src/sessions.rs` reads the desktops and the people, and `src/greeter.rs` runs the conversation for `Greetd`. The protocol, the desktops and the people are unit-tested, the protocol against a fake greetd on a socket pair.

Because it needs Qt to build, it is in a Cargo workspace of its own with the greeter (`plasma/Cargo.toml`), outside the main one, and CI builds it in its own jobs (`plasma`, `plasma-deny`). On Ubuntu 26.04:

```sh
sudo apt install cargo rustc g++ qt6-base-dev qt6-base-dev-tools qt6-declarative-dev
cd plasma && QMAKE=/usr/lib/qt6/bin/qmake cargo test
```

The build writes the plugin as `plasma/target/debug/liblinuxhello_plasma.so` and its `qmldir` under `plasma/target/debug/build/linuxhello-plasma-*/out/qt-build-utils/qml_modules/io/github/LinuxHello/AgentLink/`. To import it, put both in `io/github/LinuxHello/AgentLink/` of a QML import directory, with the library renamed to `libio_github_LinuxHello_AgentLink.so`, the name the `qmldir` asks for. `scripts/prototype/install.sh --greeter` does this into `/usr/lib/linuxhello/qml`.
