// The states of the lock-screen board C and the login-screen board D of the UI proposals
// (linux-hello-architecture, notes/ui-proposals-2026-11.md), as a fake Agent would report them.
// The demo draws them; the tests check what the Auth Prompt says for each.
.pragma library

var ALL = ["pin", "fingerprint", "face"];

function base(extra) {
    var s = { reachable: true, purpose: "unlock", available: ALL, active: ALL, state: "idle",
              outcomes: {}, result: "", reason: "", retryAfter: 0, conditions: [] };
    for (var k in extra) { s[k] = extra[k]; }
    return s;
}

var STATES = [
    { name: "1 · The question", state: base({}) },
    { name: "2 · Checking a finger or a face", state: base({ state: "scanning" }) },
    { name: "3 · Success", state: base({ active: [], result: "success", outcomes: { fingerprint: "matched" } }) },
    { name: "4 · Wrong PIN", state: base({ active: ["fingerprint", "face"], outcomes: { pin: "wrong-pin" } }) },
    { name: "5 · Not recognised", state: base({ active: ["pin"], outcomes: { fingerprint: "not-recognised", face: "not-recognised" } }) },
    { name: "6 · Locked out", state: base({ active: ["fingerprint", "face"], result: "locked-out", retryAfter: 700 }) },
    { name: "7 · Linux Hello unavailable", state: base({ reachable: false, active: [] }) },
    { name: "8 · A condition before sign-in", state: base({ conditions: [{ code: "tpm-cleared", severity: "severe",
        sentence: "The TPM no longer holds the key that your PIN opens (it was cleared or replaced), so your PIN cannot be used until your enrolment is reset." }] }) }
];
