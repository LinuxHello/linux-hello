// The Linux Hello Greeter's screen: the person's picture and name, PAM's question above the field,
// PAM's info and error lines as coloured cards, the desktop menu and the clock (login board D of
// the UI proposals; ADR-0028, amendment of 2026-11-22). Part of the greeter (C4 component greeter).
//
// `greetd` is the Greetd object of the Agent Link plugin, or any object with the same properties
// and calls (the demo and the tests use a plain QtObject). The screen starts no program: greetd
// starts the desktop after the window closes (ADR-0026).
import QtQuick
import QtQuick.Controls.Basic
import io.github.LinuxHello.AuthPrompt
import "greeter.js" as G

Rectangle {
    id: screen
    objectName: "greeter"

    // The link to greetd: phase, question, secret, linesJson, desktopsJson, peopleJson; load(),
    // begin(account), answer(text), start(index), cancel().
    required property var greetd
    // Whether the Linux Hello Agent answered Ping.
    property bool reachable: true
    // The time shown at the top right; the demo fixes it.
    property string clock: Qt.formatTime(new Date(), "hh:mm")
    // Whether the window may close itself once greetd agreed to start the desktop.
    property bool quitWhenStarted: true

    // Which person and desktop are chosen, and whether the person answered in this attempt.
    property int person: 0
    property int desktop: 0
    property bool answered: false

    readonly property var people: JSON.parse(greetd.peopleJson || "[]")
    readonly property var desktops: JSON.parse(greetd.desktopsJson || "[]")
    readonly property var view: ({
        phase: greetd.phase,
        question: greetd.question,
        secret: greetd.secret,
        lines: JSON.parse(greetd.linesJson || "[]"),
        reachable: reachable,
        desktop: desktops[desktop] || ""
    })

    color: "#1d2433"
    width: 1024
    height: 640

    // Starts a sign-in for the chosen person.
    function begin() {
        answered = false;
        if (people.length > 0) greetd.begin(people[person].account);
    }

    // Chooses another person: the running sign-in ends and the new one starts.
    function choose(index) {
        if (index === person) return;
        person = index;
        greetd.cancel();
        begin();
    }

    function submit() {
        if (greetd.phase === "asking") {
            answered = true;
            greetd.answer(field.text);
            field.text = "";
        } else if (greetd.phase === "refused" || greetd.phase === "idle") {
            begin();
        }
    }

    Connections {
        target: screen.greetd
        function onPhaseChanged() {
            var step = G.next(screen.greetd.phase, screen.answered);
            if (step === "again") screen.begin();
            else if (step === "start") startSoon.restart();
            else if (step === "quit" && screen.quitWhenStarted) Qt.quit();
            if (screen.greetd.phase === "asking") field.forceActiveFocus();
        }
    }

    // A moment to read "Starting …" and a line PAM sent after the sign-in, then greetd starts the
    // desktop.
    Timer {
        id: startSoon
        interval: 1200
        onTriggered: screen.greetd.start(screen.desktop)
    }

    Text {
        objectName: "clock"
        text: screen.clock
        color: "#fcfcfc"
        font.pixelSize: 14
        anchors.top: parent.top
        anchors.right: parent.right
        anchors.margins: 18
    }
    Timer {
        interval: 10000
        running: true
        repeat: true
        onTriggered: screen.clock = Qt.formatTime(new Date(), "hh:mm")
    }

    Column {
        id: middle
        width: Math.min(parent.width - 40, 560)
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.verticalCenter: parent.verticalCenter
        anchors.verticalCenterOffset: -20
        spacing: 14

        // The other people, small, when there is more than one.
        Row {
            visible: screen.people.length > 1
            spacing: 10
            anchors.horizontalCenter: parent.horizontalCenter
            Repeater {
                model: screen.people
                delegate: Rectangle {
                    required property var modelData
                    required property int index
                    width: 30; height: 30; radius: 15
                    color: index === screen.person ? "#3daee9" : "#4d5459"
                    Text { anchors.centerIn: parent; text: G.initial(modelData.name); color: "#fcfcfc"; font.bold: true }
                    MouseArea { anchors.fill: parent; onClicked: screen.choose(index) }
                }
            }
        }

        // The picture with the ring.
        Item {
            width: 92; height: 92
            anchors.horizontalCenter: parent.horizontalCenter
            Canvas {
                id: ring
                objectName: "ring"
                property string tone: G.ring(screen.view)
                anchors.fill: parent
                onToneChanged: requestPaint()
                onPaint: {
                    var c = getContext("2d");
                    c.reset();
                    c.lineWidth = 3;
                    c.strokeStyle = tone === "success" ? "#27ae60" : tone === "error" ? "#ed1515"
                        : tone === "off" ? "#6e7680" : "#3daee9";
                    c.setLineDash(tone === "busy" ? [4, 4] : []);
                    c.beginPath();
                    c.arc(width / 2, height / 2, width / 2 - 3, 0, 2 * Math.PI);
                    c.stroke();
                }
            }
            Rectangle {
                width: 72; height: 72; radius: 36
                anchors.centerIn: parent
                color: "#3daee9"
                Text {
                    anchors.centerIn: parent
                    text: G.initial(screen.people.length ? screen.people[screen.person].name : "")
                    color: "#fcfcfc"; font.pixelSize: 30; font.bold: true
                }
            }
        }
        Text {
            objectName: "name"
            text: screen.people.length ? screen.people[screen.person].name : "No account to sign in to"
            color: "#fcfcfc"; font.pixelSize: 17; font.bold: true
            anchors.horizontalCenter: parent.horizontalCenter
        }

        Repeater {
            objectName: "cards"
            model: G.cards(screen.view)
            delegate: ConditionCard {
                required property var modelData
                severity: modelData.severity
                text: modelData.text
                // As wide as its text, up to the column's width.
                width: Math.min(measure.advanceWidth + 44, middle.width)
                anchors.horizontalCenter: parent.horizontalCenter
                TextMetrics { id: measure; font.pixelSize: 13; text: modelData.text }
            }
        }

        Text {
            objectName: "question"
            visible: G.asking(screen.view)
            text: screen.greetd.question
            color: "#fcfcfc"; font.pixelSize: 14
            width: parent.width
            wrapMode: Text.WordWrap
            horizontalAlignment: Text.AlignHCenter
        }
        Row {
            spacing: 6
            visible: G.asking(screen.view) || screen.greetd.phase === "refused"
            anchors.horizontalCenter: parent.horizontalCenter
            TextField {
                id: field
                objectName: "field"
                visible: G.asking(screen.view)
                width: 260
                echoMode: screen.greetd.secret ? TextInput.Password : TextInput.Normal
                placeholderText: G.placeholder(screen.view)
                placeholderTextColor: "#a1a9b1"
                color: "#fcfcfc"
                background: Rectangle { color: "#31363b"; border.color: "#4d5459"; radius: 3 }
                onAccepted: screen.submit()
            }
            Button {
                objectName: "go"
                text: screen.greetd.phase === "refused" ? "Try again" : "→"
                onClicked: screen.submit()
                height: field.implicitHeight
                width: screen.greetd.phase === "refused" ? implicitWidth : height
                palette.button: "#3daee9"
                palette.buttonText: "#fcfcfc"
            }
        }
    }

    ComboBox {
        objectName: "desktops"
        model: screen.desktops
        currentIndex: screen.desktop
        onActivated: function (index) { screen.desktop = index; }
        displayText: "Desktop: " + currentText
        width: 260
        anchors.left: parent.left
        anchors.bottom: parent.bottom
        anchors.margins: 14
        palette.button: "#31363b"
        palette.buttonText: "#fcfcfc"
        palette.window: "#31363b"
        palette.text: "#fcfcfc"
        palette.base: "#31363b"
        palette.highlight: "#3daee9"
    }
}
