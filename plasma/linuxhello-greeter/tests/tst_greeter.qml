// What the Linux Hello Greeter shows and does in each state of login board D, with a fake greetd
// (demo/FakeGreetd.qml). Run with tests/run.sh (qmltestrunner, Qt 6).
import QtQuick
import QtTest
import "../qml"
import "../demo"
import "../demo/states.js" as States
import "../qml/greeter.js" as G

TestCase {
    id: test
    name: "Greeter"
    width: 1024
    height: 640
    when: windowShown
    // Shown, so that `visible` of an item inside says whether the person would see it.
    visible: true

    Component { id: fakeGreetd; FakeGreetd {} }
    Component { id: greeterScreen; Greeter { quitWhenStarted: false } }

    // The view of state `index` of the board, as the screen builds it.
    function view(index) {
        var s = JSON.parse(JSON.stringify(States.STATES[index]));
        s.reachable = s.reachable !== false;
        s.desktop = States.DESKTOPS[s.desktop || 0];
        return s;
    }

    function cardTexts(index) {
        return G.cards(view(index)).map(function (c) { return c.severity + ": " + c.text; });
    }

    // A screen on a fake greetd in state `index`.
    function screenIn(index) {
        var fake = createTemporaryObject(fakeGreetd, test, { state: States.STATES[index] });
        var screen = createTemporaryObject(greeterScreen, test, { greetd: fake });
        return screen;
    }

    function test_the_question_is_shown_above_the_field() {
        compare(cardTexts(0), []);
        compare(G.ring(view(0)), "busy");
        verify(G.asking(view(0)));
        compare(G.placeholder(view(0)), "PIN");
        var screen = screenIn(0);
        compare(findChild(screen, "question").text, States.QUESTION);
        verify(findChild(screen, "question").visible);
        verify(findChild(screen, "field").visible);
    }

    function test_an_info_line_is_a_blue_card_and_hides_the_field() {
        compare(cardTexts(1), ["info: Touch the fingerprint sensor or look at the camera."]);
        compare(G.ring(view(1)), "busy");
        verify(!G.asking(view(1)));
        verify(!findChild(screenIn(1), "field").visible);
    }

    function test_success_says_which_desktop_starts() {
        compare(cardTexts(2), ["success: Starting Plasma (Wayland)…"]);
        compare(G.ring(view(2)), "success");
    }

    function test_an_error_line_stays_a_red_card_with_the_question() {
        compare(cardTexts(3), ["severe: Wrong PIN."]);
        compare(cardTexts(4), ["severe: Not recognised."]);
        compare(cardTexts(5), ["severe: Too many wrong PINs. Linux Hello is locked for 12 more minutes."]);
        for (var i = 3; i <= 5; i++) {
            compare(G.ring(view(i)), "error");
            verify(G.asking(view(i)));
        }
    }

    function test_linux_hello_not_running_warns_and_asks_the_password() {
        compare(cardTexts(6), ["warning: " + G.UNAVAILABLE]);
        compare(G.ring(view(6)), "off");
        compare(G.placeholder(view(6)), "Password");
    }

    function test_a_condition_before_sign_in_is_shown_with_the_question() {
        compare(G.cards(view(7))[0].severity, "severe");
        verify(G.asking(view(7)));
    }

    function test_a_line_after_sign_in_shows_with_the_other_desktop() {
        compare(cardTexts(8), [
            "info: Your PIN expires in 5 days. Change it with linuxhello-ctl pin change.",
            "success: Starting GNOME…"
        ]);
    }

    function test_the_greeter_adds_no_words_to_a_refusal_with_its_own_line() {
        compare(G.cards({ phase: "refused", lines: [{ kind: "error", text: "Wrong PIN." }] }).length, 1);
        compare(G.cards({ phase: "refused", lines: [] }), [{ severity: "severe", text: "Not signed in." }]);
    }

    function test_after_a_refused_answer_the_next_attempt_starts_at_once() {
        compare(G.next("refused", true), "again");
        var screen = screenIn(0);
        screen.begin();
        findChild(screen, "field").text = "1234";
        screen.submit();
        screen.greetd.state = { phase: "refused", lines: [{ kind: "error", text: "Wrong PIN." }] };
        compare(screen.greetd.calls, ["begin alex", "answer 1234", "begin alex"]);
    }

    function test_a_refusal_without_an_answer_waits_for_the_person() {
        compare(G.next("refused", false), "wait");
        var screen = screenIn(0);
        screen.begin();
        screen.greetd.state = { phase: "refused", lines: [{ kind: "error", text: "Locked." }] };
        compare(screen.greetd.calls, ["begin alex"]);
        verify(findChild(screen, "go").visible);
        compare(findChild(screen, "go").text, "Try again");
        screen.submit();
        compare(screen.greetd.calls, ["begin alex", "begin alex"]);
    }

    function test_signed_in_starts_the_chosen_desktop() {
        var screen = screenIn(0);
        screen.desktop = 1;
        screen.greetd.state = { phase: "signed-in", lines: [] };
        tryVerify(function () { return screen.greetd.calls.indexOf("start 1") >= 0; }, 3000);
    }

    function test_the_answer_is_sent_and_the_field_emptied() {
        var screen = screenIn(0);
        var field = findChild(screen, "field");
        field.text = "246810";
        screen.submit();
        compare(screen.greetd.calls, ["answer 246810"]);
        compare(field.text, "");
    }
}
