//! The PAM entry points: the one module of this crate allowed `unsafe` code (invariant 4; listed in
//! `scripts/ci/unsafe-allowlist.txt`).
//!
//! In plain words: Linux-PAM (the library that `sudo`, login screens and lock screens use to ask
//! "is this the user?") loads this crate as `pam_linuxhello.so` and calls two C functions in it:
//! `pam_sm_authenticate` to check the user and `pam_sm_setcred` to set credentials, which this
//! module has none of. This file turns PAM's C values (the user name, the service, the terminal, the
//! conversation function that asks the person a question) into Rust values, calls the safe
//! [`crate::client`], and turns its answer into a PAM code. Everything else is safe code.
//!
//! What can go wrong here and how it is held: a panic never crosses into C (`catch_unwind`, and the
//! answer is then "unavailable"); every pointer from PAM is checked for null before use; the
//! person's answer to the PIN question is copied into wiped memory and the C copy is overwritten
//! with zeros before it is freed.
//!
//! C4 component: `pamEntry` ([workspace.dsl](https://github.com/LinuxHello/linux-hello-architecture/blob/main/workspace.dsl))

#![allow(unsafe_code)]

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;

use zeroize::Zeroizing;

use crate::client::{self, Code, Conversation, Request};

/// `PAM_SUCCESS`.
const PAM_SUCCESS: c_int = 0;
/// `PAM_AUTH_ERR`.
const PAM_AUTH_ERR: c_int = 7;
/// `PAM_AUTHINFO_UNAVAIL`.
const PAM_AUTHINFO_UNAVAIL: c_int = 9;
/// `PAM_USER_UNKNOWN`.
const PAM_USER_UNKNOWN: c_int = 10;
/// The item `PAM_SERVICE`.
const PAM_SERVICE: c_int = 1;
/// The item `PAM_TTY`.
const PAM_TTY: c_int = 3;
/// The item `PAM_CONV`.
const PAM_CONV: c_int = 5;
/// The item `PAM_XDISPLAY`.
const PAM_XDISPLAY: c_int = 11;
/// The message style of a question asked without echo.
const PAM_PROMPT_ECHO_OFF: c_int = 1;
/// The message style of an error.
const PAM_ERROR_MSG: c_int = 3;
/// The message style of information.
const PAM_TEXT_INFO: c_int = 4;
/// The flag that asks the module not to show messages.
const PAM_SILENT: c_int = 0x8000;

/// `struct pam_message`.
#[repr(C)]
struct PamMessage {
    /// One of the message styles.
    msg_style: c_int,
    /// The text.
    msg: *const c_char,
}

/// `struct pam_response`.
#[repr(C)]
struct PamResponse {
    /// The answer, allocated with `malloc` by the application.
    resp: *mut c_char,
    /// Unused, zero.
    resp_retcode: c_int,
}

/// The conversation function of `struct pam_conv`.
type ConvFn = unsafe extern "C" fn(
    c_int,
    *mut *const PamMessage,
    *mut *mut PamResponse,
    *mut c_void,
) -> c_int;

/// `struct pam_conv`.
#[repr(C)]
struct PamConv {
    /// The application's function.
    conv: Option<ConvFn>,
    /// The application's data, passed back to it.
    appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
extern "C" {
    /// `pam_get_user`: the user name, asking for it when the application has not set it.
    fn pam_get_user(pamh: *mut c_void, user: *mut *const c_char, prompt: *const c_char) -> c_int;
    /// `pam_get_item`: one of the handle's items.
    fn pam_get_item(pamh: *const c_void, item_type: c_int, item: *mut *const c_void) -> c_int;
}

/// The text of a string item of `pamh`, empty when it is not set or not UTF-8.
///
/// # Safety
///
/// `pamh` is the handle PAM passed to the entry point.
unsafe fn item_text(pamh: *mut c_void, item: c_int) -> String {
    let mut value: *const c_void = ptr::null();
    // SAFETY: `pamh` is PAM's handle; `value` is a valid place for the item pointer.
    let found = unsafe { pam_get_item(pamh, item, &mut value) };
    if found != PAM_SUCCESS || value.is_null() {
        return String::new();
    }
    // SAFETY: string items are NUL-terminated C strings owned by PAM for the handle's lifetime.
    unsafe { CStr::from_ptr(value.cast::<c_char>()) }
        .to_str()
        .unwrap_or_default()
        .to_string()
}

/// The user id of the user name `name`, from the system's user database.
fn uid_of(name: &CStr) -> Option<u32> {
    let mut buffer = vec![0_u8; 16 * 1024];
    // SAFETY: an all-zero `passwd` is a valid value to be overwritten.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = ptr::null_mut();
    // SAFETY: every pointer is valid for the call and the buffer length is its real length.
    let status = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr().cast::<c_char>(),
            buffer.len(),
            &mut found,
        )
    };
    (status == 0 && !found.is_null()).then_some(entry.pw_uid)
}

/// The application's conversation function, as PAM gave it.
struct PamConversation {
    /// The function; `None` when the application gave none (then nothing can be asked).
    conv: Option<ConvFn>,
    /// The application's data.
    appdata: *mut c_void,
    /// Whether messages are shown (`PAM_SILENT` not set).
    speak: bool,
}

impl PamConversation {
    /// Sends one message of `style` and returns the answer's C text, if any.
    fn send(&self, style: c_int, text: &str) -> Option<*mut c_char> {
        let conv = self.conv?;
        let text = CString::new(text).ok()?;
        let message = PamMessage {
            msg_style: style,
            msg: text.as_ptr(),
        };
        let mut list: *const PamMessage = &message;
        let mut response: *mut PamResponse = ptr::null_mut();
        // SAFETY: one message, given as Linux-PAM expects (a pointer to an array of pointers); the
        // application allocates `response` with malloc or leaves it null.
        let status = unsafe { conv(1, &mut list, &mut response, self.appdata) };
        if response.is_null() {
            return None;
        }
        // SAFETY: on any return the application owns nothing more; the array has one element.
        let answer = unsafe { (*response).resp };
        // SAFETY: the array was allocated with malloc by the application and is freed once.
        unsafe { libc::free(response.cast::<c_void>()) };
        if status != PAM_SUCCESS {
            wipe_and_free(answer);
            return None;
        }
        (!answer.is_null()).then_some(answer)
    }
}

/// Overwrites the C string `text` with zeros and frees it; nothing for a null pointer.
fn wipe_and_free(text: *mut c_char) {
    if text.is_null() {
        return;
    }
    // SAFETY: `text` is a NUL-terminated string allocated with malloc by the application.
    unsafe {
        let length = libc::strlen(text);
        for i in 0..length {
            ptr::write_volatile(text.add(i), 0);
        }
        libc::free(text.cast::<c_void>());
    }
}

impl Conversation for PamConversation {
    fn secret(&mut self, question: &str) -> Option<Zeroizing<String>> {
        let answer = self.send(PAM_PROMPT_ECHO_OFF, question)?;
        // SAFETY: a NUL-terminated string from the application, copied before it is wiped.
        let bytes = Zeroizing::new(unsafe { CStr::from_ptr(answer) }.to_bytes().to_vec());
        wipe_and_free(answer);
        std::str::from_utf8(&bytes)
            .ok()
            .map(|text| Zeroizing::new(text.to_string()))
    }

    fn info(&mut self, text: &str) {
        if self.speak {
            if let Some(answer) = self.send(PAM_TEXT_INFO, text) {
                wipe_and_free(answer);
            }
        }
    }

    fn error(&mut self, text: &str) {
        if self.speak {
            if let Some(answer) = self.send(PAM_ERROR_MSG, text) {
                wipe_and_free(answer);
            }
        }
    }
}

/// The value of the `context=` argument among the module's arguments, if any.
///
/// # Safety
///
/// `argv` holds `argc` NUL-terminated strings, as PAM passes them.
unsafe fn context_argument(argc: c_int, argv: *const *const c_char) -> Option<String> {
    if argv.is_null() {
        return None;
    }
    let count = usize::try_from(argc).ok()?;
    (0..count).find_map(|i| {
        // SAFETY: `argv` has `argc` elements.
        let arg = unsafe { *argv.add(i) };
        if arg.is_null() {
            return None;
        }
        // SAFETY: each element is a NUL-terminated string owned by PAM.
        let text = unsafe { CStr::from_ptr(arg) }.to_str().ok()?;
        text.strip_prefix("context=").map(str::to_string)
    })
}

/// The body of `pam_sm_authenticate`, outside the panic guard.
///
/// # Safety
///
/// The arguments are those PAM passed to the entry point.
unsafe fn authenticate(
    pamh: *mut c_void,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // SAFETY: as for the caller.
    let context = unsafe { context_argument(argc, argv) };
    let mut user: *const c_char = ptr::null();
    // SAFETY: `pamh` is PAM's handle; a null prompt lets PAM use its default.
    if unsafe { pam_get_user(pamh, &mut user, ptr::null()) } != PAM_SUCCESS || user.is_null() {
        return PAM_USER_UNKNOWN;
    }
    // SAFETY: the user name is a NUL-terminated string owned by PAM.
    let uid = uid_of(unsafe { CStr::from_ptr(user) });
    let mut conv: *const c_void = ptr::null();
    // SAFETY: `pamh` is PAM's handle; `conv` is a valid place for the item pointer.
    let found = unsafe { pam_get_item(pamh, PAM_CONV, &mut conv) };
    let (function, appdata) = if found == PAM_SUCCESS && !conv.is_null() {
        // SAFETY: the item `PAM_CONV` is a `struct pam_conv` owned by PAM.
        let conv = unsafe { &*conv.cast::<PamConv>() };
        (conv.conv, conv.appdata_ptr)
    } else {
        (None, ptr::null_mut())
    };
    let mut conversation = PamConversation {
        conv: function,
        appdata,
        speak: flags & PAM_SILENT == 0,
    };
    // SAFETY: `pamh` is PAM's handle.
    let service = unsafe { item_text(pamh, PAM_SERVICE) };
    // SAFETY: as above.
    let mut terminal = unsafe { item_text(pamh, PAM_TTY) };
    if terminal.is_empty() {
        // SAFETY: as above.
        terminal = unsafe { item_text(pamh, PAM_XDISPLAY) };
    }
    let request = Request {
        context: context.as_deref(),
        service: &service,
        terminal: &terminal,
        uid,
    };
    match client::authenticate(&request, &mut conversation) {
        Code::Success => PAM_SUCCESS,
        Code::Denied => PAM_AUTH_ERR,
        Code::Unavailable => PAM_AUTHINFO_UNAVAIL,
        Code::UserUnknown => PAM_USER_UNKNOWN,
    }
}

/// Checks the user: the PAM entry point `pam_sm_authenticate`. A panic is answered
/// `PAM_AUTHINFO_UNAVAIL`, never success.
///
/// # Safety
///
/// Called only by Linux-PAM, with its handle and the module's arguments.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut c_void,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // SAFETY: the arguments are passed on unchanged from PAM.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        authenticate(pamh, flags, argc, argv)
    }))
    .unwrap_or(PAM_AUTHINFO_UNAVAIL)
}

/// Sets credentials: the PAM entry point `pam_sm_setcred`. The module has none to set; it answers
/// success so that a stack in which it authenticated the user can go on.
///
/// # Safety
///
/// Called only by Linux-PAM.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}
