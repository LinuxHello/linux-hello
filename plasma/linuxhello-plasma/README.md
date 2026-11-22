# The Agent Link

The Agent Link is the small part through which Linux Hello's screens on KDE Plasma, such as its login screen and its part in KDE's lock screen, reach the Linux Hello Agent. The Agent is the system service that runs the fingerprint, the face and the PIN. The screens are written in QML, the language Plasma's screens are made of, and QML cannot talk to the Agent on its own: the Agent answers on D-Bus, the message service desktop programs use to call each other, and a screen may not start a program to do it for it ([ADR-0026](https://github.com/LinuxHello/linux-hello-architecture/blob/main/adr/0026-clients-reach-the-agent-directly.md)). So the Agent Link is a *QML plugin*, a library QML can import, written in Rust ([ADR-0028](https://github.com/LinuxHello/linux-hello-architecture/blob/main/adr/0028-plasma-agent-backend.md)).

**State:** built and tested in the desktop test VM; no screen ships with it yet.

## What it gives QML

```qml
import io.github.LinuxHello.AgentLink
import io.github.LinuxHello.AuthPrompt

AgentLink { id: link; Component.onCompleted: watch() }
AuthPrompt { agentState: JSON.parse(link.stateJson) }
```

`AgentLink` has three calls and two properties:

| | What it does |
| :-- | :-- |
| `ping()` | Asks whether the Agent answers, and sets `reachable` |
| `watch()` | Follows every sign-in attempt the Agent says has started for this screen: the screen's own user's, and for a login screen's account the logins root started |
| `follow(id)` | Follows one attempt, by its id |
| `stateJson` | The attempt's state as JSON, in exactly the form the [Auth Prompt](../auth-prompt/) reads: which methods run, how each ended, the result |
| `reachable` | Whether the Agent answered |

It listens on a thread of its own and reads only signals whose sender is the Agent itself, so another program cannot feed the screen a state.

## How it is built

It uses cxx-qt, a library that lets Rust define objects QML can use. cxx-qt generates glue between Rust and C++ that needs `unsafe` code, so one module, `src/bridge.rs`, holds only the bridge declaration and is allowed `unsafe` code (invariant 4 in [AGENTS.md](../../AGENTS.md), `scripts/ci/unsafe-allowlist.txt`). Everything else is safe Rust: `src/fold.rs` turns what the Agent says into the Auth Prompt's state and is unit-tested, and `src/link.rs` talks to the Agent.

Because it needs Qt to build, it is a Cargo workspace of its own, outside the main one, and CI builds it in its own jobs (`plasma`, `plasma-deny`). On Ubuntu 26.04:

```sh
sudo apt install cargo rustc g++ qt6-base-dev qt6-base-dev-tools qt6-declarative-dev
cd plasma/linuxhello-plasma && QMAKE=/usr/lib/qt6/bin/qmake cargo test
```

The build writes the plugin as `target/debug/liblinuxhello_plasma.so` and its `qmldir` under `target/debug/build/linuxhello-plasma-*/out/qt-build-utils/qml_modules/io/github/LinuxHello/AgentLink/`. To import it, put both in `io/github/LinuxHello/AgentLink/` of a QML import directory, with the library renamed to `libio_github_LinuxHello_AgentLink.so`, the name the `qmldir` asks for.
