//! The Rust behind the `Greetd` QML object: the greeter's link to greetd (ADR-0028, amendment of
//! 2026-11-22).
//!
//! The QML window calls `load()` once for the lists of desktops and people, `begin(account)` to
//! start a sign-in, `answer(text)` when the person presses Enter, `start(index)` to start a desktop
//! after `phase` became `signed-in`, and `cancel()` to start over. A PAM module may take seconds to
//! reply (it waits for a finger or a face), so the conversation runs on a thread of its own and
//! hands each new state to Qt's thread; the window never freezes. The rules of the conversation are
//! in `greetd` and tested there. Nothing here starts a program: greetd starts the desktop after the
//! greeter exits (ADR-0026).
//!
//! `phase` is one of: `idle` (nothing asked yet), `waiting` (greetd has not replied yet), `asking`
//! (`question` waits for an answer), `refused` (PAM refused the person; `begin` starts again),
//! `signed-in`, `started` (greetd will start the desktop; the window closes), `failed` (greetd
//! refused something else) and `no-greetd` (greetd's socket does not answer). `linesJson` is the
//! list of info and error lines of the attempt, `[{"kind": "info", "text": "…"}]`, emptied when
//! the person answers.
//!
//! C4 component: `agentLink` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use core::pin::Pin;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{channel, Receiver, Sender};

use cxx_qt::{CxxQtType, Threading};
use cxx_qt_lib::QString;

use crate::bridge::qobject::Greetd;
use crate::greetd::{Conversation, Line, Step};
use crate::sessions::{self, Desktop};

/// The Rust side of `Greetd`.
#[derive(Default)]
pub struct GreetdRust {
    /// See the module's documentation.
    pub(crate) phase: QString,
    /// The question PAM asks now, while `phase` is `asking`.
    pub(crate) question: QString,
    /// Whether the answer is hidden while typed.
    pub(crate) secret: bool,
    /// The info and error lines of the attempt, as JSON.
    pub(crate) lines_json: QString,
    /// The installed desktops' names, as a JSON list.
    pub(crate) desktops_json: QString,
    /// The people who can sign in, `[{"account": "alex", "name": "Alex Example"}]`.
    pub(crate) people_json: QString,
    /// The installed desktops, in the order of `desktops_json`.
    desktops: Vec<Desktop>,
    /// Commands to the conversation's thread, once it runs.
    commands: Option<Sender<Command>>,
}

/// What the window asks the conversation's thread to do.
enum Command {
    /// `create_session`.
    Begin(String),
    /// `post_auth_message_response`.
    Answer(String),
    /// `start_session`.
    Start(Desktop),
    /// `cancel_session`.
    Cancel,
}

/// The state the thread hands to Qt's thread.
#[derive(Clone, Default)]
struct View {
    /// `phase`.
    phase: String,
    /// `question`.
    question: String,
    /// `secret`.
    secret: bool,
    /// The lines of `linesJson`.
    lines: Vec<Line>,
}

impl View {
    /// Shows `step`, the end of a conversation step.
    fn show(&mut self, step: Step) {
        self.question.clear();
        match step {
            Step::Question { text, secret } => {
                self.phase = "asking".into();
                self.question = text;
                self.secret = secret;
            }
            Step::SignedIn => self.phase = "signed-in".into(),
            Step::Refused(_) => self.phase = "refused".into(),
            Step::Failed(reason) => self.fail("failed", reason),
        }
    }

    /// Shows that something other than PAM went wrong.
    fn fail(&mut self, phase: &str, reason: String) {
        self.phase = phase.into();
        self.lines.push(Line {
            kind: "error".into(),
            text: reason,
        });
    }
}

/// The conversation's thread: connects to `$GREETD_SOCK` and runs each command, handing every new
/// state to `publish`. Returns when the window is gone.
fn converse(commands: Receiver<Command>, publish: impl Fn(View)) {
    let mut view = View::default();
    let socket = std::env::var_os("GREETD_SOCK");
    let mut talk = match socket.map(UnixStream::connect) {
        Some(Ok(stream)) => Conversation::new(stream),
        Some(Err(e)) => {
            view.fail("no-greetd", format!("greetd does not answer: {e}"));
            publish(view);
            return;
        }
        None => {
            view.fail("no-greetd", "GREETD_SOCK is not set.".into());
            publish(view);
            return;
        }
    };
    for command in commands {
        let mut lines = Vec::new();
        view.phase = "waiting".into();
        if matches!(command, Command::Answer(_)) {
            view.lines.clear();
        }
        publish(view.clone());
        let result = match command {
            Command::Begin(account) => talk.begin(&account, |l| lines.push(l)),
            Command::Answer(text) => talk.answer(&text, |l| lines.push(l)),
            Command::Cancel => {
                // greetd answers an error when no sign-in runs; either way none runs now.
                let _ = talk.cancel();
                view.phase = "idle".into();
                view.lines.clear();
                publish(view.clone());
                continue;
            }
            Command::Start(desktop) => match talk.start(desktop.command, desktop.env) {
                Ok(None) => {
                    view.phase = "started".into();
                    publish(view.clone());
                    continue;
                }
                Ok(Some(reason)) => Ok(Step::Failed(reason)),
                Err(e) => Err(e),
            },
        };
        view.lines.extend(lines);
        match result {
            Ok(step) => view.show(step),
            Err(e) => view.fail("no-greetd", format!("greetd does not answer: {e}")),
        }
        publish(view.clone());
    }
}

impl Greetd {
    /// Reads the installed desktops and the people who can sign in into `desktopsJson` and
    /// `peopleJson`, and sets `phase` to `idle`.
    pub fn load(mut self: Pin<&mut Self>) {
        let desktops = sessions::desktops();
        let names: Vec<&str> = desktops.iter().map(|d| d.name.as_str()).collect();
        let names = serde_json::to_string(&names).unwrap_or_default();
        let people = serde_json::to_string(&sessions::people_here()).unwrap_or_default();
        self.as_mut().rust_mut().get_mut().desktops = desktops;
        self.as_mut().set_desktops_json(QString::from(&names));
        self.as_mut().set_people_json(QString::from(&people));
        self.as_mut().set_lines_json(QString::from("[]"));
        self.set_phase(QString::from("idle"));
    }

    /// Starts a sign-in for `account`.
    pub fn begin(self: Pin<&mut Self>, account: &QString) {
        self.send(Command::Begin(account.to_string()));
    }

    /// Answers PAM's question with what the person typed.
    pub fn answer(self: Pin<&mut Self>, text: &QString) {
        self.send(Command::Answer(text.to_string()));
    }

    /// Asks greetd to start the desktop at `index` of `desktopsJson` once the window closes.
    pub fn start(self: Pin<&mut Self>, index: i32) {
        let chosen = usize::try_from(index)
            .ok()
            .and_then(|i| self.rust().desktops.get(i).cloned());
        if let Some(desktop) = chosen {
            self.send(Command::Start(desktop));
        }
    }

    /// Ends the sign-in that runs.
    pub fn cancel(self: Pin<&mut Self>) {
        self.send(Command::Cancel);
    }

    /// Hands `command` to the conversation's thread, starting the thread on the first call.
    fn send(mut self: Pin<&mut Self>, command: Command) {
        if self.rust().commands.is_none() {
            let (sender, receiver) = channel();
            let qt_thread = self.qt_thread();
            std::thread::spawn(move || {
                converse(receiver, |view| {
                    let _ = qt_thread.queue(move |mut object| {
                        let lines = serde_json::to_string(&view.lines).unwrap_or_default();
                        object.as_mut().set_question(QString::from(&view.question));
                        object.as_mut().set_secret(view.secret);
                        object.as_mut().set_lines_json(QString::from(&lines));
                        object.as_mut().set_phase(QString::from(&view.phase));
                    });
                });
            });
            self.as_mut().rust_mut().get_mut().commands = Some(sender);
        }
        if let Some(commands) = &self.rust().commands {
            let _ = commands.send(command);
        }
    }
}
