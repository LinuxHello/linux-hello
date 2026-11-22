// What the Linux Hello Greeter shows, worked out from greetd's state without Qt or greetd, so that
// tests/tst_greeter.qml can check every state of the login board D (ADR-0028, amendment of
// 2026-11-22). Part of the greeter (C4 component greeter).
//
// The state object `s` has the fields of the Greetd QML object, already parsed:
//   phase      idle | waiting | asking | refused | signed-in | started | failed | no-greetd
//   question   PAM's question while phase is asking, such as "PIN (or use the fingerprint sensor
//              or the camera, then press Enter):" from pam_linuxhello or "Password:" from pam_unix
//   secret     whether the answer is hidden
//   lines      the attempt's info and error lines, [{kind: "info" | "error", text}]
// and what the window knows besides greetd:
//   reachable  whether the Linux Hello Agent answered Ping; false shows the warning of square 7
//   desktop    the name of the chosen desktop, for "Starting Plasma (Wayland)…"
.pragma library

var UNAVAILABLE = "Linux Hello is not running. Sign in with your account password. "
    + "Your passkeys stay locked until it works again.";

function hasError(s) {
    return (s.lines || []).some(function (l) { return l.kind === "error"; });
}

function signedIn(s) {
    return s.phase === "signed-in" || s.phase === "started";
}

// The coloured cards above the field, top to bottom: {severity: info | warning | severe | success,
// text}. A PAM error line stays red and an info line blue; the greeter adds no sentence of its own
// to a PAM line.
function cards(s) {
    var out = [];
    if (s.reachable === false) {
        out.push({ severity: "warning", text: UNAVAILABLE });
    }
    (s.lines || []).forEach(function (l) {
        out.push({ severity: l.kind === "error" ? "severe" : "info", text: l.text });
    });
    if (s.phase === "refused" && !hasError(s)) {
        out.push({ severity: "severe", text: "Not signed in." });
    }
    if (signedIn(s)) {
        out.push({ severity: "success", text: "Starting " + (s.desktop || "the desktop") + "…" });
    }
    return out;
}

// The ring around the picture: busy (blue, dashed) while signing in, success (green), error (red)
// after an error line, off (grey) while Linux Hello is not running.
function ring(s) {
    if (signedIn(s)) return "success";
    if (hasError(s) || s.phase === "refused" || s.phase === "failed" || s.phase === "no-greetd") {
        return "error";
    }
    if (s.reachable === false) return "off";
    return "busy";
}

// Whether the field is shown: only while PAM asks.
function asking(s) {
    return s.phase === "asking";
}

// The grey word inside the field.
function placeholder(s) {
    var q = (s.question || "").toLowerCase();
    if (q.indexOf("pin") === 0) return "PIN";
    if (q.indexOf("password") >= 0) return "Password";
    return "";
}

// What to do when greetd's phase changes: "again" starts the next attempt at once (PAM refused an
// answer the person gave), "wait" waits for the person (PAM refused without a question, as on a
// lockout, so starting again at once would loop), "start" starts the chosen desktop, "quit"
// closes the window, "" nothing.
function next(phase, answered) {
    if (phase === "refused") return answered ? "again" : "wait";
    if (phase === "signed-in") return "start";
    if (phase === "started") return "quit";
    return "";
}

// The initial of a name, for the picture.
function initial(name) {
    return name ? name.charAt(0).toUpperCase() : "?";
}
