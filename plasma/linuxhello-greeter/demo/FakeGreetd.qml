// A stand-in for the Greetd object of the Agent Link plugin, holding one state of demo/states.js.
// It records the calls the screen makes instead of talking to greetd.
import QtQuick
import "states.js" as States

QtObject {
    property var state: ({})
    property string phase: state.phase || "idle"
    property string question: state.question || ""
    property bool secret: true
    property string linesJson: JSON.stringify(state.lines || [])
    property string desktopsJson: JSON.stringify(States.DESKTOPS)
    property string peopleJson: JSON.stringify(States.PEOPLE)
    property var calls: []

    function load() { calls = calls.concat(["load"]); }
    function begin(account) { calls = calls.concat(["begin " + account]); }
    function answer(text) { calls = calls.concat(["answer " + text]); }
    function start(index) { calls = calls.concat(["start " + index]); }
    function cancel() { calls = calls.concat(["cancel"]); }
}
