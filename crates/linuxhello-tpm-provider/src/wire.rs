//! What the Agent and the TPM provider say to each other over a local socket.
//!
//! In plain words: the Agent never touches the TPM, and the provider never sees a PIN. The Agent
//! stretches the PIN itself and sends the 32 stretched bytes; the provider turns a request into TPM
//! commands and answers with one status byte, plus the key blobs when it made or changed a key.
//! The blobs are the Agent's to store: only the TPM that made them can open them.
//!
//! A message is a frame: four bytes of length (big endian, at most [`MAX_FRAME`]) and the body. A
//! request body is one operation byte followed by its fields, each a two-byte length and the bytes.
//! There is one request per connection. Secrets (the authorisation values) live in [`Zeroizing`]
//! buffers on both sides, and no type here has a `Debug` that shows one.
//!
//! This module has no TPM code, so the Agent can use it (through [`crate::client`]) without linking
//! the TSS2 libraries.
//!
//! C4 component: `tpmProviderApi` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

use std::io::{self, Read, Write};

use zeroize::Zeroizing;

/// The bytes of an authorisation value: what the PIN stretching produces.
pub const AUTH_BYTES: usize = 32;

/// The largest frame, in bytes. A request or response over it is refused unread.
pub const MAX_FRAME: usize = 8 * 1024;

/// The status of an answer: the request was done.
pub const STATUS_OK: u8 = 0;
/// The status of an answer to a verification: the PIN is wrong.
pub const STATUS_WRONG: u8 = 1;
/// The status of an answer: the TPM is in dictionary-attack lockout.
pub const STATUS_LOCKED: u8 = 2;
/// The status of an answer: anything else went wrong (no TPM, a damaged blob, a refused command).
pub const STATUS_FAILED: u8 = 3;

/// A root key as it is kept on disk: the two blobs that only the TPM that made them can open. They
/// are wrapped by the TPM, so printing them shows no secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blobs {
    /// The public part, marshalled.
    pub public: Vec<u8>,
    /// The private part, wrapped by the TPM, marshalled.
    pub private: Vec<u8>,
}

/// An authorisation value, wiped when dropped.
pub type Auth = Zeroizing<[u8; AUTH_BYTES]>;

/// What the Agent asks.
pub enum Request {
    /// Make a root key whose authorisation is `auth`.
    Enrol {
        /// The authorisation of the new key.
        auth: Auth,
    },
    /// Whether `auth` is the authorisation of the root key in `blobs`.
    Verify {
        /// The key.
        blobs: Blobs,
        /// The value to check.
        auth: Auth,
    },
    /// Change the authorisation of the root key in `blobs` from `old` to `new`.
    ChangeAuth {
        /// The key.
        blobs: Blobs,
        /// The current authorisation.
        old: Auth,
        /// The new authorisation.
        new: Auth,
    },
}

/// What the provider answers.
pub struct Response {
    /// One of the `STATUS_` values.
    pub status: u8,
    /// The blobs of a key that was made or changed, when the status is [`STATUS_OK`].
    pub blobs: Option<Blobs>,
}

/// The operation byte of [`Request::Enrol`].
const OP_ENROL: u8 = 1;
/// The operation byte of [`Request::Verify`].
const OP_VERIFY: u8 = 2;
/// The operation byte of [`Request::ChangeAuth`].
const OP_CHANGE_AUTH: u8 = 3;

/// A cursor over a body: takes length-prefixed fields and says when there are none left.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    /// The next byte.
    fn byte(&mut self) -> Option<u8> {
        let (first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(*first)
    }

    /// The next field: a two-byte length and that many bytes.
    fn field(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(u16::from_be_bytes([*self.0.first()?, *self.0.get(1)?]));
        let field = self.0.get(2..2 + length)?;
        self.0 = &self.0[2 + length..];
        Some(field)
    }

    /// The next field as an authorisation value; it must be exactly [`AUTH_BYTES`] long.
    fn auth(&mut self) -> Option<Auth> {
        let bytes: [u8; AUTH_BYTES] = self.field()?.try_into().ok()?;
        Some(Zeroizing::new(bytes))
    }

    /// The next two fields as the blobs of a key.
    fn blobs(&mut self) -> Option<Blobs> {
        Some(Blobs {
            public: self.field()?.to_vec(),
            private: self.field()?.to_vec(),
        })
    }

    /// Whether every byte was taken.
    fn done(&self) -> bool {
        self.0.is_empty()
    }
}

/// Appends a length-prefixed field; `None` if it is over 65535 bytes.
fn put(body: &mut Vec<u8>, field: &[u8]) -> Option<()> {
    body.extend_from_slice(&u16::try_from(field.len()).ok()?.to_be_bytes());
    body.extend_from_slice(field);
    Some(())
}

/// The body of a request, in a buffer that is wiped when dropped. `None` if a field is too long.
pub fn encode_request(request: &Request) -> Option<Zeroizing<Vec<u8>>> {
    let mut body = Zeroizing::new(Vec::new());
    match request {
        Request::Enrol { auth } => {
            body.push(OP_ENROL);
            put(&mut body, &**auth)?;
        }
        Request::Verify { blobs, auth } => {
            body.push(OP_VERIFY);
            put(&mut body, &blobs.public)?;
            put(&mut body, &blobs.private)?;
            put(&mut body, &**auth)?;
        }
        Request::ChangeAuth { blobs, old, new } => {
            body.push(OP_CHANGE_AUTH);
            put(&mut body, &blobs.public)?;
            put(&mut body, &blobs.private)?;
            put(&mut body, &**old)?;
            put(&mut body, &**new)?;
        }
    }
    Some(body)
}

/// The request in `body`, or `None` for anything that is not exactly one well-formed request: an
/// unknown operation, a field of the wrong length, a missing field or bytes left over.
pub fn decode_request(body: &[u8]) -> Option<Request> {
    let mut reader = Reader(body);
    let request = match reader.byte()? {
        OP_ENROL => Request::Enrol {
            auth: reader.auth()?,
        },
        OP_VERIFY => Request::Verify {
            blobs: reader.blobs()?,
            auth: reader.auth()?,
        },
        OP_CHANGE_AUTH => Request::ChangeAuth {
            blobs: reader.blobs()?,
            old: reader.auth()?,
            new: reader.auth()?,
        },
        _ => return None,
    };
    reader.done().then_some(request)
}

/// The body of a response.
pub fn encode_response(response: &Response) -> Option<Vec<u8>> {
    let mut body = vec![response.status];
    if let Some(blobs) = &response.blobs {
        put(&mut body, &blobs.public)?;
        put(&mut body, &blobs.private)?;
    }
    Some(body)
}

/// The response in `body`: a status, and blobs when the status is [`STATUS_OK`] and there are
/// bytes after it. `None` for anything else.
pub fn decode_response(body: &[u8]) -> Option<Response> {
    let mut reader = Reader(body);
    let status = reader.byte()?;
    if status > STATUS_FAILED {
        return None;
    }
    let blobs = if reader.done() {
        None
    } else {
        Some(reader.blobs()?)
    };
    reader.done().then_some(Response { status, blobs })
}

/// Reads one frame. `None` for a length of zero or over [`MAX_FRAME`], and an error for a stream that
/// ends or fails first. The body is in a buffer that is wiped when dropped.
///
/// # Errors
///
/// The I/O error of the stream, including a frame cut short.
pub fn read_frame(stream: &mut impl Read) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
    if length == 0 || length > MAX_FRAME {
        return Ok(None);
    }
    let mut body = Zeroizing::new(vec![0_u8; length]);
    stream.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Writes one frame.
///
/// # Errors
///
/// The I/O error of the stream, or `InvalidInput` for a body that is empty or over [`MAX_FRAME`].
pub fn write_frame(stream: &mut impl Write, body: &[u8]) -> io::Result<()> {
    if body.is_empty() || body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a frame of this size",
        ));
    }
    let length = u32::try_from(body.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(body)
}

#[cfg(test)]
mod tests;
