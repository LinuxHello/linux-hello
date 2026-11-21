//! A small D-Bus message codec: the few shapes the module sends and reads (ADR-0023, amendment of
//! 2026-11-21, point 1).
//!
//! In plain words: D-Bus messages are bytes in a fixed layout, a header (who the message is for,
//! which method, which types follow) and a body (the arguments). The module only ever sends method
//! calls whose arguments are strings and one 64-bit number, and only reads replies, errors and the
//! Agent's signals, whose arguments are strings, a list of strings and one 32-bit number (and, for
//! its tests, its own calls). This
//! module writes and reads exactly those, in safe code, and refuses anything else as malformed
//! rather than guessing. It does not use `zbus`: a `zbus` connection starts a thread, and its
//! decoder of raw bytes is `unsafe`.
//!
//! The layout follows the D-Bus specification, "Message Protocol": every value is aligned to its
//! own size from the start of the message (strings and arrays to 4, 64-bit numbers and structures to
//! 8), and the header ends on a multiple of 8.

/// The largest message that is read, in bytes; a larger length in a header is refused. The Agent's
/// messages are a few hundred bytes.
pub const MAX_MESSAGE: usize = 64 * 1024;

/// The type of a message (D-Bus specification, "Message Types").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A method call.
    Call,
    /// The reply to a call.
    Return,
    /// An error reply to a call.
    Error,
    /// A signal.
    Signal,
}

impl Kind {
    /// The byte of the kind on the wire.
    const fn byte(self) -> u8 {
        match self {
            Self::Call => 1,
            Self::Return => 2,
            Self::Error => 3,
            Self::Signal => 4,
        }
    }

    /// The kind of a byte, `None` for one the specification does not define.
    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Call),
            2 => Some(Self::Return),
            3 => Some(Self::Error),
            4 => Some(Self::Signal),
            _ => None,
        }
    }
}

/// An argument of a method call the module sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arg<'a> {
    /// A string (`s`).
    Str(&'a str),
    /// A signed 64-bit number (`x`).
    I64(i64),
}

/// A value read from a body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// A string (`s`).
    Str(String),
    /// An unsigned 32-bit number (`u`).
    U32(u32),
    /// A list of strings (`as`).
    Strs(Vec<String>),
    /// A signed 64-bit number (`x`), as in the module's own calls.
    I64(i64),
    /// A list of three strings each (`a(sss)`): the conditions of `GetPromptStatus`, each as
    /// code, severity and sentence.
    Triples(Vec<(String, String, String)>),
}

/// A message read from the bus: the header fields the module uses and the decoded body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Call, reply, error or signal.
    pub kind: Kind,
    /// The sender's serial number of this message.
    pub serial: u32,
    /// For a reply or an error: the serial of the call it answers.
    pub reply_serial: Option<u32>,
    /// The interface of a call or signal.
    pub interface: Option<String>,
    /// The method or signal name.
    pub member: Option<String>,
    /// The name of an error.
    pub error_name: Option<String>,
    /// The unique bus name of the sender, set by the bus.
    pub sender: Option<String>,
    /// The arguments.
    pub body: Vec<Value>,
}

/// Why bytes could not be read as a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed;

/// The header field codes the module writes and reads (specification, "Header Fields").
mod field {
    /// The object path.
    pub const PATH: u8 = 1;
    /// The interface.
    pub const INTERFACE: u8 = 2;
    /// The member.
    pub const MEMBER: u8 = 3;
    /// The error name.
    pub const ERROR_NAME: u8 = 4;
    /// The serial of the call a reply answers.
    pub const REPLY_SERIAL: u8 = 5;
    /// The destination.
    pub const DESTINATION: u8 = 6;
    /// The sender.
    pub const SENDER: u8 = 7;
    /// The signature of the body.
    pub const SIGNATURE: u8 = 8;
}

/// Writes little-endian values, aligned from the start of the buffer.
struct Writer(Vec<u8>);

impl Writer {
    /// Pads with zero bytes to a multiple of `n`.
    fn align(&mut self, n: usize) {
        while self.0.len() % n != 0 {
            self.0.push(0);
        }
    }

    /// A 32-bit number, aligned to 4.
    fn u32(&mut self, v: u32) {
        self.align(4);
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    /// A string or an object path: length, bytes, a zero byte.
    fn string(&mut self, s: &str) -> Result<(), Malformed> {
        self.u32(u32::try_from(s.len()).map_err(|_| Malformed)?);
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
        Ok(())
    }

    /// A signature: a one-byte length, the type codes, a zero byte.
    fn signature(&mut self, s: &str) -> Result<(), Malformed> {
        self.0.push(u8::try_from(s.len()).map_err(|_| Malformed)?);
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
        Ok(())
    }

    /// One header field: a structure of the code and a variant of type `code_type`.
    fn field(&mut self, code: u8, code_type: &str, value: &str) -> Result<(), Malformed> {
        self.align(8);
        self.0.push(code);
        self.signature(code_type)?;
        if code_type == "g" {
            self.signature(value)
        } else {
            self.string(value)
        }
    }
}

/// The text of a method call to `destination`, `path`, `interface`, `member` with `args`, as
/// serial `serial`.
///
/// # Errors
///
/// [`Malformed`] when a value cannot be written (a string longer than 4 GiB).
pub fn method_call(
    serial: u32,
    destination: &str,
    path: &str,
    interface: &str,
    member: &str,
    args: &[Arg<'_>],
) -> Result<Vec<u8>, Malformed> {
    let mut body = Writer(Vec::new());
    let mut signature = String::new();
    for arg in args {
        match arg {
            Arg::Str(s) => {
                signature.push('s');
                body.string(s)?;
            }
            Arg::I64(v) => {
                signature.push('x');
                body.align(8);
                body.0.extend_from_slice(&v.to_le_bytes());
            }
        }
    }
    let mut out = Writer(Vec::with_capacity(128 + body.0.len()));
    out.0.extend_from_slice(&[b'l', Kind::Call.byte(), 0, 1]);
    out.u32(u32::try_from(body.0.len()).map_err(|_| Malformed)?);
    out.u32(serial);
    // The array of fields: its length is written after the fields, at this place.
    out.u32(0);
    let start = out.0.len();
    out.field(field::PATH, "o", path)?;
    out.field(field::INTERFACE, "s", interface)?;
    out.field(field::MEMBER, "s", member)?;
    out.field(field::DESTINATION, "s", destination)?;
    if !signature.is_empty() {
        out.field(field::SIGNATURE, "g", &signature)?;
    }
    let length = u32::try_from(out.0.len() - start).map_err(|_| Malformed)?;
    out.0[12..16].copy_from_slice(&length.to_le_bytes());
    out.align(8);
    out.0.extend_from_slice(&body.0);
    Ok(out.0)
}

/// The length of the whole message whose first 16 bytes are `head`, or [`Malformed`] when the
/// header is not one of ours to read (unknown byte order, a protocol version other than 1, a
/// length above [`MAX_MESSAGE`]).
///
/// # Errors
///
/// [`Malformed`] as above.
pub fn total_length(head: &[u8; 16]) -> Result<usize, Malformed> {
    let little = match head[0] {
        b'l' => true,
        b'B' => false,
        _ => return Err(Malformed),
    };
    if head[3] != 1 {
        return Err(Malformed);
    }
    let number = |at: usize| {
        let bytes = [head[at], head[at + 1], head[at + 2], head[at + 3]];
        usize::try_from(if little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
        .map_err(|_| Malformed)
    };
    let body = number(4)?;
    let fields = number(12)?;
    let header = (16_usize.checked_add(fields).ok_or(Malformed)?)
        .checked_next_multiple_of(8)
        .ok_or(Malformed)?;
    let total = header.checked_add(body).ok_or(Malformed)?;
    if total > MAX_MESSAGE {
        return Err(Malformed);
    }
    Ok(total)
}

/// Reads values from a message, aligned from the start of the message.
struct Reader<'a> {
    /// The whole message.
    bytes: &'a [u8],
    /// Where the next value starts.
    at: usize,
    /// The byte order of the message.
    little: bool,
}

impl Reader<'_> {
    /// Skips padding to a multiple of `n`; the padding must be zero.
    fn align(&mut self, n: usize) -> Result<(), Malformed> {
        while self.at % n != 0 {
            if *self.bytes.get(self.at).ok_or(Malformed)? != 0 {
                return Err(Malformed);
            }
            self.at += 1;
        }
        Ok(())
    }

    /// The next `n` bytes.
    fn take(&mut self, n: usize) -> Result<&[u8], Malformed> {
        let end = self.at.checked_add(n).ok_or(Malformed)?;
        let slice = self.bytes.get(self.at..end).ok_or(Malformed)?;
        self.at = end;
        Ok(slice)
    }

    /// One byte.
    fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }

    /// A 32-bit number, aligned to 4.
    fn u32(&mut self) -> Result<u32, Malformed> {
        self.align(4)?;
        let b = self.take(4)?;
        let bytes = [b[0], b[1], b[2], b[3]];
        Ok(if self.little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    }

    /// The text of `n` bytes followed by a zero byte; it must be UTF-8 without a zero byte.
    fn text(&mut self, n: usize) -> Result<String, Malformed> {
        let raw = self.take(n)?.to_vec();
        if self.u8()? != 0 || raw.contains(&0) {
            return Err(Malformed);
        }
        String::from_utf8(raw).map_err(|_| Malformed)
    }

    /// A string or an object path.
    fn string(&mut self) -> Result<String, Malformed> {
        let n = usize::try_from(self.u32()?).map_err(|_| Malformed)?;
        self.text(n)
    }

    /// A signature.
    fn signature(&mut self) -> Result<String, Malformed> {
        let n = usize::from(self.u8()?);
        self.text(n)
    }

    /// The value of a header field, whose variant must be a string, a path, a signature or a
    /// 32-bit number.
    fn variant(&mut self) -> Result<Value, Malformed> {
        match self.signature()?.as_str() {
            "s" | "o" => Ok(Value::Str(self.string()?)),
            "g" => Ok(Value::Str(self.signature()?)),
            "u" => Ok(Value::U32(self.u32()?)),
            _ => Err(Malformed),
        }
    }
}

/// Reads a whole message, as [`total_length`] measured it.
///
/// # Errors
///
/// [`Malformed`] for anything that is not a well-formed message whose body has only the types `s`,
/// `u`, `x` and `as`.
pub fn parse(bytes: &[u8]) -> Result<Message, Malformed> {
    let head: &[u8; 16] = bytes
        .get(..16)
        .and_then(|h| h.try_into().ok())
        .ok_or(Malformed)?;
    if total_length(head)? != bytes.len() {
        return Err(Malformed);
    }
    let kind = Kind::from_byte(bytes[1]).ok_or(Malformed)?;
    let mut r = Reader {
        bytes,
        at: 4,
        little: bytes[0] == b'l',
    };
    let body_length = usize::try_from(r.u32()?).map_err(|_| Malformed)?;
    let serial = r.u32()?;
    let fields_length = usize::try_from(r.u32()?).map_err(|_| Malformed)?;
    let fields_end = r.at.checked_add(fields_length).ok_or(Malformed)?;
    let mut message = Message {
        kind,
        serial,
        reply_serial: None,
        interface: None,
        member: None,
        error_name: None,
        sender: None,
        body: Vec::new(),
    };
    let mut signature = String::new();
    while r.at < fields_end {
        r.align(8)?;
        let code = r.u8()?;
        let value = r.variant()?;
        match (code, value) {
            (field::REPLY_SERIAL, Value::U32(v)) => message.reply_serial = Some(v),
            (field::INTERFACE, Value::Str(v)) => message.interface = Some(v),
            (field::MEMBER, Value::Str(v)) => message.member = Some(v),
            (field::ERROR_NAME, Value::Str(v)) => message.error_name = Some(v),
            (field::SENDER, Value::Str(v)) => message.sender = Some(v),
            (field::SIGNATURE, Value::Str(v)) => signature = v,
            (field::PATH | field::DESTINATION, Value::Str(_)) => {}
            // A field of a code the module does not use is skipped; a known code with the wrong
            // type is not.
            (field::REPLY_SERIAL | field::INTERFACE | field::MEMBER, _)
            | (field::ERROR_NAME | field::SENDER | field::SIGNATURE, _)
            | (field::PATH | field::DESTINATION, _) => return Err(Malformed),
            _ => {}
        }
    }
    if r.at != fields_end {
        return Err(Malformed);
    }
    r.align(8)?;
    let body_start = r.at;
    if bytes.len() - body_start != body_length {
        return Err(Malformed);
    }
    // The body is aligned from its own start, which is a multiple of 8 from the message's.
    let mut types = signature.as_str();
    while !types.is_empty() {
        if let Some(rest) = types.strip_prefix("a(sss)") {
            // The length counts the elements' bytes, from after the padding to the first one.
            let n = usize::try_from(r.u32()?).map_err(|_| Malformed)?;
            r.align(8)?;
            let end = r.at.checked_add(n).ok_or(Malformed)?;
            let mut items = Vec::new();
            while r.at < end {
                r.align(8)?;
                items.push((r.string()?, r.string()?, r.string()?));
            }
            if r.at != end {
                return Err(Malformed);
            }
            message.body.push(Value::Triples(items));
            types = rest;
        } else if let Some(rest) = types.strip_prefix("as") {
            let n = usize::try_from(r.u32()?).map_err(|_| Malformed)?;
            let end = r.at.checked_add(n).ok_or(Malformed)?;
            let mut items = Vec::new();
            while r.at < end {
                items.push(r.string()?);
            }
            if r.at != end {
                return Err(Malformed);
            }
            message.body.push(Value::Strs(items));
            types = rest;
        } else if let Some(rest) = types.strip_prefix('s') {
            message.body.push(Value::Str(r.string()?));
            types = rest;
        } else if let Some(rest) = types.strip_prefix('u') {
            message.body.push(Value::U32(r.u32()?));
            types = rest;
        } else if let Some(rest) = types.strip_prefix('x') {
            r.align(8)?;
            let b = r.take(8)?;
            let bytes: [u8; 8] = b.try_into().map_err(|_| Malformed)?;
            message.body.push(Value::I64(if r.little {
                i64::from_le_bytes(bytes)
            } else {
                i64::from_be_bytes(bytes)
            }));
            types = rest;
        } else {
            return Err(Malformed);
        }
    }
    if r.at != bytes.len() {
        return Err(Malformed);
    }
    Ok(message)
}

/// A message of any kind with the given header fields and body, for the fake bus of the tests.
#[cfg(test)]
pub(crate) fn encode_for_tests(message: &Message) -> Vec<u8> {
    let mut body = Writer(Vec::new());
    let mut signature = String::new();
    for value in &message.body {
        match value {
            Value::Str(s) => {
                signature.push('s');
                body.string(s).unwrap();
            }
            Value::U32(v) => {
                signature.push('u');
                body.u32(*v);
            }
            Value::I64(v) => {
                signature.push('x');
                body.align(8);
                body.0.extend_from_slice(&v.to_le_bytes());
            }
            Value::Strs(items) => {
                signature.push_str("as");
                body.u32(0);
                let at = body.0.len();
                for item in items {
                    body.string(item).unwrap();
                }
                let n = u32::try_from(body.0.len() - at).unwrap();
                body.0[at - 4..at].copy_from_slice(&n.to_le_bytes());
            }
            Value::Triples(items) => {
                signature.push_str("a(sss)");
                body.u32(0);
                let length_at = body.0.len() - 4;
                body.align(8);
                let at = body.0.len();
                for (a, b, c) in items {
                    body.align(8);
                    body.string(a).unwrap();
                    body.string(b).unwrap();
                    body.string(c).unwrap();
                }
                let n = u32::try_from(body.0.len() - at).unwrap();
                body.0[length_at..length_at + 4].copy_from_slice(&n.to_le_bytes());
            }
        }
    }
    let mut out = Writer(vec![b'l', message.kind.byte(), 0, 1]);
    out.u32(u32::try_from(body.0.len()).unwrap());
    out.u32(message.serial);
    out.u32(0);
    let start = out.0.len();
    if let Some(v) = message.reply_serial {
        out.align(8);
        out.0.push(field::REPLY_SERIAL);
        out.signature("u").unwrap();
        out.u32(v);
    }
    for (code, value) in [
        (field::INTERFACE, &message.interface),
        (field::MEMBER, &message.member),
        (field::ERROR_NAME, &message.error_name),
        (field::SENDER, &message.sender),
    ] {
        if let Some(v) = value {
            out.field(code, "s", v).unwrap();
        }
    }
    if !signature.is_empty() {
        out.field(field::SIGNATURE, "g", &signature).unwrap();
    }
    let n = u32::try_from(out.0.len() - start).unwrap();
    out.0[12..16].copy_from_slice(&n.to_le_bytes());
    out.align(8);
    out.0.extend_from_slice(&body.0);
    out.0
}

#[cfg(test)]
mod tests;
