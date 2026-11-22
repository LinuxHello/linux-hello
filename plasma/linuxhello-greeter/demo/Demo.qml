// The Linux Hello Greeter in the nine states of login board D, each driven by a fake greetd
// (states.js). demo/render.py saves it as a picture (demo/states.png).
import QtQuick
import "../qml"
import "states.js" as States

Rectangle {
    width: 3 * 520 + 4 * 16
    height: 3 * 340 + 4 * 16
    color: "#eff0f1"

    Grid {
        x: 16
        y: 16
        columns: 3
        spacing: 16
        Repeater {
            model: States.STATES
            delegate: Item {
                required property var modelData
                width: 520
                height: 340
                FakeGreetd { id: fake; state: modelData }
                Greeter {
                    anchors.fill: parent
                    greetd: fake
                    reachable: modelData.reachable !== false
                    desktop: modelData.desktop || 0
                    clock: "09:41"
                    quitWhenStarted: false
                }
                Text { text: modelData.name; color: "#a1a9b1"; font.pixelSize: 12; x: 10; y: 8 }
            }
        }
    }
}
