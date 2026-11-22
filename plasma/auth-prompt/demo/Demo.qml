// The Auth Prompt in every state of the lock-screen board C, driven by a fake Agent (states.js).
// demo/render.py saves it as a picture; it can also be opened with any QML viewer.
import QtQuick
import io.github.LinuxHello.AuthPrompt
import "states.js" as States

Rectangle {
    width: 3 * 470 + 4 * 16
    height: 3 * 300 + 4 * 16
    color: "#eff0f1"

    Grid {
        x: 16
        y: 16
        columns: 3
        spacing: 16
        Repeater {
            model: States.STATES
            delegate: Rectangle {
                required property var modelData
                width: 470
                height: 300
                radius: 6
                color: "#232f3e"
                Column {
                    anchors.centerIn: parent
                    spacing: 10
                    Text { text: "09:41"; color: "#fcfcfc"; font.pixelSize: 34; anchors.horizontalCenter: parent.horizontalCenter }
                    Text { text: "Alex"; color: "#fcfcfc"; font.bold: true; anchors.horizontalCenter: parent.horizontalCenter }
                    // The host's field, with the placeholder the Auth Prompt asks for.
                    Rectangle {
                        width: 240; height: 28; radius: 3
                        color: "#31363b"; border.color: "#4d5459"
                        anchors.horizontalCenter: parent.horizontalCenter
                        Text { text: prompt.placeholder; color: "#a1a9b1"; anchors.verticalCenter: parent.verticalCenter; x: 8 }
                    }
                    AuthPrompt { id: prompt; agentState: modelData.state; anchors.horizontalCenter: parent.horizontalCenter }
                }
                Text { text: modelData.name; color: "#a1a9b1"; font.pixelSize: 12; x: 10; y: 8 }
            }
        }
    }
}
