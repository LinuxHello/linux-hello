// The nine states of login board D of the UI proposals, as a fake greetd would show them: what the
// Greetd object's properties hold in each. Used by demo/Demo.qml and tests/tst_greeter.qml.
.pragma library

var QUESTION = "PIN (or use the fingerprint sensor or the camera, then press Enter):";

var STATES = [
    { name: "1 · The question", phase: "asking", question: QUESTION, lines: [] },
    { name: "2 · Checking a finger or a face", phase: "waiting",
      lines: [{ kind: "info", text: "Touch the fingerprint sensor or look at the camera." }] },
    { name: "3 · Success", phase: "signed-in", lines: [] },
    { name: "4 · Wrong PIN", phase: "asking", question: QUESTION,
      lines: [{ kind: "error", text: "Wrong PIN." }] },
    { name: "5 · Not recognised", phase: "asking", question: QUESTION,
      lines: [{ kind: "error", text: "Not recognised." }] },
    { name: "6 · Locked out", phase: "asking", question: QUESTION,
      lines: [{ kind: "error", text: "Too many wrong PINs. Linux Hello is locked for 12 more minutes." }] },
    { name: "7 · Linux Hello unavailable", phase: "asking", question: "Password:", reachable: false, lines: [] },
    { name: "8 · A condition before sign-in", phase: "asking", question: QUESTION,
      lines: [{ kind: "error", text: "The TPM no longer holds the key that your PIN opens (it was cleared or replaced), so your PIN cannot be used until your enrolment is reset." }] },
    { name: "9 · Another desktop", phase: "signed-in", desktop: 1,
      lines: [{ kind: "info", text: "Your PIN expires in 5 days. Change it with linuxhello-ctl pin change." }] }
];

var DESKTOPS = ["Plasma (Wayland)", "GNOME"];
var PEOPLE = [{ account: "alex", name: "Alex" }];
