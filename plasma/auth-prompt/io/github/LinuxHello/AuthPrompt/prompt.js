// What the Auth Prompt shows, worked out from the Agent's state: one tile per method and the cards
// under them. Pure functions, so the wording and the rules can be tested without a window
// (tst_prompt.qml). Every Linux Hello screen gets the same words from here (UX5).
//
// The state is one plain object, the contract between the module and whatever feeds it (the fake
// Agent of the demo and the tests, later the backend on the Agent's D-Bus interface):
//
//   reachable   bool      the Agent answered its liveness check (Ping)
//   purpose     string    "unlock" (lock screen) or "login" (login screen): only the wording differs
//   available   [string]  methods that can be used in this attempt: "pin", "fingerprint", "face"
//   active      [string]  methods running now (the ActiveMethods signal)
//   state       string    "idle", "scanning" or "waiting-for-input" (the State signal)
//   outcomes    object    per method that ended: "matched", "not-recognised", "wrong-pin", "locked"
//                         or "unavailable". From the Agent's MethodEnded signal (ADR-0014, second
//                         amendment of 2026-11-22): matched is "matched"; failed is "wrong-pin" for
//                         the PIN and "not-recognised" for the others; locked-out is "locked";
//                         unavailable is "unavailable"
//   result      string    "", "success", "failure", "locked-out" or "cancelled" (the Result signal)
//   reason      string    the Result's reason ("not-recognised", "timeout", ...)
//   retryAfter  int       seconds until another PIN may be tried, during a lockout
//   conditions  [object]  {code, severity, sentence}, severity "info", "warning" or "severe"
//
// Tones of a tile: "running", "success", "failure", "idle", "disabled". Severities of a card:
// "info", "warning", "severe", "success".
.pragma library

var METHODS = ["pin", "fingerprint", "face"];

var TITLES = { pin: "PIN", fingerprint: "Fingerprint", face: "Face" };

function has(list, item) {
    return !!list && list.indexOf(item) !== -1;
}

function hasCondition(s, code) {
    var all = s.conditions || [];
    for (var i = 0; i < all.length; i++) {
        if (all[i].code === code || all[i].code.indexOf(code + ": ") === 0) {
            return true;
        }
    }
    return false;
}

// Whole minutes left of a lockout, rounded up, at least 1.
function minutes(seconds) {
    return Math.max(1, Math.ceil((seconds || 0) / 60));
}

function lockedOut(s) {
    return s.result === "locked-out" || (s.outcomes && s.outcomes.pin === "locked");
}

// The tile of one method.
function tile(s, method) {
    var t = { method: method, title: TITLES[method], detail: "", tone: "idle" };
    var outcome = s.outcomes ? s.outcomes[method] : undefined;
    var running = has(s.active, method);
    if (!s.reachable) {
        t.detail = "Unavailable";
        t.tone = "disabled";
    } else if (s.result === "success") {
        if (outcome === "matched") {
            t.detail = "Matched";
            t.tone = "success";
        } else {
            t.detail = method === "pin" ? "Not used" : "Stopped";
            t.tone = "disabled";
        }
    } else if (method === "pin" && hasCondition(s, "tpm-cleared")) {
        t.detail = "Cannot be used";
        t.tone = "failure";
    } else if (method === "pin" && lockedOut(s)) {
        t.detail = "Locked, " + minutes(s.retryAfter) + " min";
        t.tone = "failure";
    } else if (method === "pin" && outcome === "wrong-pin") {
        t.detail = "Wrong PIN";
        t.tone = "failure";
    } else if (outcome === "unavailable") {
        t.detail = "Unavailable";
        t.tone = "disabled";
    } else if (outcome === "not-recognised") {
        t.detail = "Not recognised";
        t.tone = "failure";
    } else if (running) {
        t.tone = "running";
        if (method === "pin") {
            var biometric = has(s.active, "fingerprint") || has(s.active, "face");
            t.detail = s.state === "scanning" && biometric ? "Waiting" : "Type and press Enter";
        } else if (method === "fingerprint") {
            t.detail = s.state === "scanning" ? "Reading finger…" : "Touch the sensor";
        } else {
            t.detail = "Camera on";
        }
    } else {
        t.detail = "Ready";
    }
    return t;
}

// The tiles, in the fixed order PIN, fingerprint, face, for the methods this attempt can use.
function tiles(s) {
    var out = [];
    for (var i = 0; i < METHODS.length; i++) {
        if (has(s.available, METHODS[i])) {
            out.push(tile(s, METHODS[i]));
        }
    }
    return out;
}

// The cards under the tiles: what went wrong or what the person should know, most serious first.
function cards(s) {
    var out = [];
    if (!s.reachable) {
        out.push({
            severity: "warning",
            text: "Linux Hello is not running. " +
                (s.purpose === "login" ? "Sign in" : "Unlock") +
                " with your account password. Your passkeys stay locked until it works again."
        });
        return out;
    }
    if (s.result === "success") {
        return out;
    }
    if (lockedOut(s)) {
        var m = minutes(s.retryAfter);
        out.push({
            severity: "severe",
            text: "Too many wrong PINs. Linux Hello is locked for " + m + " more minute" +
                (m === 1 ? "" : "s") + "."
        });
    } else if (s.outcomes && s.outcomes.pin === "wrong-pin") {
        var others = has(s.available, "fingerprint") || has(s.available, "face");
        out.push({
            severity: "severe",
            text: others ? "Wrong PIN. Try again, or use the sensor or the camera." : "Wrong PIN. Try again."
        });
    } else if (s.outcomes && (s.outcomes.fingerprint === "not-recognised" || s.outcomes.face === "not-recognised")) {
        out.push({
            severity: "severe",
            text: has(s.available, "pin") ? "Not recognised. Try again, or type your PIN." : "Not recognised. Try again."
        });
    }
    var all = s.conditions || [];
    var order = { severe: 0, warning: 1, info: 2 };
    var sorted = all.slice().sort(function (a, b) { return order[a.severity] - order[b.severity]; });
    for (var i = 0; i < sorted.length; i++) {
        out.push({ severity: sorted[i].severity, text: sorted[i].sentence });
    }
    return out;
}

// The placeholder of the field next to the tiles: what the person should type there.
function placeholder(s) {
    if (!s.reachable) {
        return "Password";
    }
    if (lockedOut(s)) {
        return "PIN locked";
    }
    return "PIN";
}
