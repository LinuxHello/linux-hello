// What the Auth Prompt shows for each state of the lock-screen board C and the login-screen board D
// of the UI proposals. Run with tests/run.sh (qmltestrunner, Qt 6).
import QtQuick
import QtTest
import io.github.LinuxHello.AuthPrompt
import "../demo/states.js" as States
import "../io/github/LinuxHello/AuthPrompt/prompt.js" as Prompt

TestCase {
    id: test
    name: "AuthPrompt"
    width: 600
    height: 400
    when: windowShown

    // A copy, so that a test that changes its state changes no other test's.
    function stateOf(index) { return JSON.parse(JSON.stringify(States.STATES[index].state)); }

    function details(state) {
        var out = {};
        var tiles = Prompt.tiles(state);
        for (var i = 0; i < tiles.length; i++) { out[tiles[i].method] = tiles[i].detail + "/" + tiles[i].tone; }
        return out;
    }

    function cardTexts(state) {
        return Prompt.cards(state).map(function (c) { return c.severity + ": " + c.text; });
    }

    function test_the_question_shows_all_three_methods_running() {
        compare(details(stateOf(0)), { pin: "Type and press Enter/running", fingerprint: "Touch the sensor/running", face: "Camera on/running" });
        compare(cardTexts(stateOf(0)), []);
        compare(Prompt.placeholder(stateOf(0)), "PIN");
    }

    function test_a_finger_being_read_is_shown_on_its_tile() {
        compare(details(stateOf(1)), { pin: "Waiting/running", fingerprint: "Reading finger…/running", face: "Camera on/running" });
    }

    function test_success_marks_the_method_that_matched_and_stops_the_rest() {
        compare(details(stateOf(2)), { pin: "Not used/disabled", fingerprint: "Matched/success", face: "Stopped/disabled" });
        compare(cardTexts(stateOf(2)), []);
    }

    function test_a_wrong_pin_fails_its_tile_and_says_what_else_works() {
        compare(details(stateOf(3)).pin, "Wrong PIN/failure");
        compare(cardTexts(stateOf(3)), ["severe: Wrong PIN. Try again, or use the sensor or the camera."]);
    }

    function test_a_biometric_that_did_not_match_fails_its_own_tile() {
        var d = details(stateOf(4));
        compare(d.fingerprint, "Not recognised/failure");
        compare(d.face, "Not recognised/failure");
        compare(d.pin, "Type and press Enter/running");
        compare(cardTexts(stateOf(4)), ["severe: Not recognised. Try again, or type your PIN."]);
    }

    function test_a_lockout_counts_whole_minutes_on_the_pin_tile_and_card() {
        compare(details(stateOf(5)).pin, "Locked, 12 min/failure");
        compare(cardTexts(stateOf(5)), ["severe: Too many wrong PINs. Linux Hello is locked for 12 more minutes."]);
        compare(Prompt.placeholder(stateOf(5)), "PIN locked");
        var one = stateOf(5); one.retryAfter = 30;
        compare(cardTexts(one), ["severe: Too many wrong PINs. Linux Hello is locked for 1 more minute."]);
    }

    function test_an_agent_that_does_not_answer_greys_every_tile_and_asks_for_the_password() {
        compare(details(stateOf(6)), { pin: "Unavailable/disabled", fingerprint: "Unavailable/disabled", face: "Unavailable/disabled" });
        compare(cardTexts(stateOf(6)), ["warning: Linux Hello is not running. Unlock with your account password. Your passkeys stay locked until it works again."]);
        compare(Prompt.placeholder(stateOf(6)), "Password");
        var login = stateOf(6); login.purpose = "login";
        verify(cardTexts(login)[0].indexOf("Sign in with your account password") !== -1);
    }

    function test_a_condition_before_sign_in_is_a_card_and_marks_the_pin() {
        compare(details(stateOf(7)).pin, "Cannot be used/failure");
        compare(details(stateOf(7)).fingerprint, "Touch the sensor/running");
        var cards = cardTexts(stateOf(7));
        compare(cards.length, 1);
        verify(cards[0].indexOf("severe: The TPM no longer holds the key") === 0);
    }

    function test_only_the_methods_this_attempt_can_use_get_a_tile() {
        var pinOnly = stateOf(0); pinOnly.available = ["pin"]; pinOnly.active = ["pin"];
        compare(Prompt.tiles(pinOnly).length, 1);
        pinOnly.outcomes = { pin: "wrong-pin" };
        compare(cardTexts(pinOnly), ["severe: Wrong PIN. Try again."]);
    }

    function test_a_method_that_could_not_run_is_greyed_alone() {
        var s = stateOf(0);
        s.active = ["pin", "face"];
        s.outcomes = { fingerprint: "unavailable" };
        var d = details(s);
        compare(d.fingerprint, "Unavailable/disabled");
        compare(d.face, "Camera on/running");
        compare(cardTexts(s), []);
    }

    function test_conditions_are_listed_most_serious_first() {
        var s = stateOf(0);
        s.conditions = [{ code: "pin-expires-soon: 5", severity: "info", sentence: "soon" },
                        { code: "policy-pin-only", severity: "severe", sentence: "pin only" },
                        { code: "tpm-dictionary-limit-low", severity: "warning", sentence: "low" }];
        compare(cardTexts(s), ["severe: pin only", "warning: low", "info: soon"]);
    }

    Component {
        id: promptComponent
        AuthPrompt {}
    }

    function test_the_component_draws_the_tiles_and_cards_of_a_state() {
        var item = createTemporaryObject(promptComponent, test, { agentState: stateOf(3) });
        verify(item);
        waitForRendering(item);
        var pin = findChild(item, "tile-pin");
        verify(pin, "a PIN tile");
        compare(pin.detail, "Wrong PIN");
        compare(pin.tone, "failure");
        verify(findChild(item, "tile-face"), "a face tile");
        compare(item.placeholder, "PIN");
        item.agentState = stateOf(6);
        waitForRendering(item);
        compare(findChild(item, "tile-pin").detail, "Unavailable");
        compare(item.placeholder, "Password");
    }
}
