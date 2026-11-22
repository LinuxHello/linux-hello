// The Linux Hello Greeter's window, as linuxhello-greeter loads it under cage: the screen of
// Greeter.qml, wired to greetd and to the Linux Hello Agent through the Agent Link plugin
// (ADR-0028, amendment of 2026-11-22). On opening it reads the desktops and the people, asks the
// Agent whether it runs (Ping) and starts the sign-in of the first person at once, so the
// fingerprint and the face can run before anything is typed. Part of the greeter (C4 component
// greeter).
import QtQuick
import QtQuick.Window
import io.github.LinuxHello.AgentLink

Window {
    id: window
    visible: true
    width: Screen.width > 0 ? Screen.width : 1024
    height: Screen.height > 0 ? Screen.height : 640
    title: "Linux Hello"
    // No title bar: cage shows this one window on the whole screen. Not FullScreen, which cage
    // 0.2.1 does not survive when it is asked for before the window is shown.
    flags: Qt.FramelessWindowHint
    color: "#1d2433"

    Greetd { id: greetd }
    AgentLink { id: agent }

    // Asks again now and then, so the warning goes once the Agent runs.
    Timer {
        interval: 5000
        running: !agent.reachable
        repeat: true
        onTriggered: agent.ping()
    }

    Greeter {
        anchors.fill: parent
        greetd: greetd
        reachable: agent.reachable
        Component.onCompleted: {
            greetd.load();
            agent.ping();
            begin();
        }
    }
}
