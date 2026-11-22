//! greetd's socket protocol and the conversation of one sign-in, without Qt (ADR-0028, amendment of
//! 2026-11-22).
//!
//! greetd is the login service that runs PAM and starts the chosen desktop; the greeter is the
//! screen it talks to over the Unix socket named in `$GREETD_SOCK`. Each message is a 32-bit length
//! in the machine's byte order followed by that many bytes of JSON, and greetd answers each request
//! with one reply (greetd-ipc(7)). A sign-in is: `create_session` with the account name; then, as
//! long as greetd replies `auth_message`, an answer with `post_auth_message_response`; until it
//! replies `success` (PAM let the person in) or `error`. Then `start_session` with the desktop's
//! command, or `cancel_session` to start over.
//!
//! PAM's questions come with a kind: `visible` or `secret` (a question the person answers) and
//! `info` or `error` (a line to show, answered with an empty response). `Conversation` answers
//! the lines itself and stops at each question, so the screen only shows lines and asks questions
//! (`lines_are_answered_and_kept`, `a_question_stops_the_conversation`).

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

/// The longest reply this side reads, so that a broken peer cannot make it allocate gigabytes.
const MAX_REPLY: u32 = 1 << 20;

/// A request to greetd (greetd-ipc(7)).
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Starts a sign-in for an account.
    CreateSession {
        /// The account name.
        username: String,
    },
    /// Answers the last `auth_message`; no response for an info or error line.
    PostAuthMessageResponse {
        /// What the person typed.
        #[serde(skip_serializing_if = "Option::is_none")]
        response: Option<String>,
    },
    /// Starts the desktop of a signed-in session once the greeter has exited.
    StartSession {
        /// The desktop's command and its arguments.
        cmd: Vec<String>,
        /// `NAME=value` lines for the desktop's environment.
        env: Vec<String>,
    },
    /// Ends the sign-in that runs.
    CancelSession,
}

/// A reply of greetd.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Reply {
    /// The request did what it asked.
    Success,
    /// It failed. `error_type` is `auth_error` when PAM refused the person, `error` otherwise.
    Error {
        /// `auth_error` or `error`.
        error_type: String,
        /// greetd's words.
        description: String,
    },
    /// PAM says something or asks something.
    AuthMessage {
        /// `visible`, `secret`, `info` or `error`.
        auth_message_type: String,
        /// The text.
        auth_message: String,
    },
}

/// Sends `request` and reads greetd's reply.
pub fn talk(stream: &mut (impl Read + Write), request: &Request) -> io::Result<Reply> {
    let body = serde_json::to_vec(request).map_err(io::Error::other)?;
    let length = u32::try_from(body.len()).map_err(io::Error::other)?;
    stream.write_all(&length.to_ne_bytes())?;
    stream.write_all(&body)?;
    stream.flush()?;
    let mut head = [0_u8; 4];
    stream.read_exact(&mut head)?;
    let length = u32::from_ne_bytes(head);
    if length > MAX_REPLY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "greetd's reply is too long",
        ));
    }
    let mut body = vec![0_u8; length as usize];
    stream.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// A line PAM sent to show, with its kind.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Line {
    /// `info` or `error`.
    pub kind: String,
    /// The text.
    pub text: String,
}

/// Where a conversation step ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// PAM asks a question; the person answers with `answer`.
    Question {
        /// The question's text, such as "PIN (or use the fingerprint sensor …):".
        text: String,
        /// Whether the answer is hidden while typed.
        secret: bool,
    },
    /// PAM let the person in; `start` starts the desktop.
    SignedIn,
    /// PAM refused the person (or the account is unknown); the sign-in was cancelled.
    Refused(String),
    /// greetd answered something else; the sign-in was cancelled.
    Failed(String),
}

/// The conversation of one sign-in, over any stream (greetd's socket in the greeter, a socket pair
/// in the tests). `on_line` gets each info and error line as it arrives.
pub struct Conversation<S> {
    /// The connection to greetd.
    stream: S,
}

impl<S: Read + Write> Conversation<S> {
    /// A conversation over `stream`.
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Starts a sign-in for `username` and runs it to the first question or the end.
    pub fn begin(&mut self, username: &str, on_line: impl FnMut(Line)) -> io::Result<Step> {
        let request = Request::CreateSession {
            username: username.to_string(),
        };
        self.run(request, on_line)
    }

    /// Answers the question and runs on to the next question or the end.
    pub fn answer(&mut self, text: &str, on_line: impl FnMut(Line)) -> io::Result<Step> {
        let request = Request::PostAuthMessageResponse {
            response: Some(text.to_string()),
        };
        self.run(request, on_line)
    }

    /// Ends the sign-in that runs, if any. greetd answers an error when none runs; that is fine.
    pub fn cancel(&mut self) -> io::Result<()> {
        talk(&mut self.stream, &Request::CancelSession).map(|_| ())
    }

    /// Asks greetd to start the desktop once the greeter exits; `Ok(None)` when it agreed, the
    /// reason otherwise.
    pub fn start(&mut self, cmd: Vec<String>, env: Vec<String>) -> io::Result<Option<String>> {
        match talk(&mut self.stream, &Request::StartSession { cmd, env })? {
            Reply::Success => Ok(None),
            Reply::Error { description, .. } => Ok(Some(description)),
            Reply::AuthMessage { .. } => Ok(Some("greetd asked a question".to_string())),
        }
    }

    /// Sends `request`, answers every line, and stops at a question or the end.
    fn run(&mut self, first: Request, mut on_line: impl FnMut(Line)) -> io::Result<Step> {
        let mut request = first;
        loop {
            match talk(&mut self.stream, &request)? {
                Reply::AuthMessage {
                    auth_message_type,
                    auth_message,
                } => match auth_message_type.as_str() {
                    "visible" | "secret" => {
                        return Ok(Step::Question {
                            secret: auth_message_type == "secret",
                            text: auth_message,
                        })
                    }
                    kind => {
                        on_line(Line {
                            kind: if kind == "info" { "info" } else { "error" }.to_string(),
                            text: auth_message,
                        });
                        request = Request::PostAuthMessageResponse { response: None };
                    }
                },
                Reply::Success => return Ok(Step::SignedIn),
                Reply::Error {
                    error_type,
                    description,
                } => {
                    // greetd keeps a refused session until it is cancelled (greetd-ipc(7)).
                    let _ = self.cancel();
                    return Ok(if error_type == "auth_error" {
                        Step::Refused(description)
                    } else {
                        Step::Failed(description)
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
