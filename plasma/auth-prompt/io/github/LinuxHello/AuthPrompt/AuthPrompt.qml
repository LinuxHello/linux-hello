// Linux Hello's shared sign-in prompt: one tile per method of the attempt and the cards under them,
// worked out from the Agent's state by prompt.js. The login screen's greeter, the part in KDE's lock
// screen and the in-session prompt all import it, so they look alike (UX5) and show which method
// runs (UX1). It reads `agentState`, the contract documented at the top of prompt.js, and starts no
// program and calls no service itself (ADR-0026): the host feeds it.
//
// C4 component: authPrompt (workspace.dsl, container plasma)
import QtQuick
import "prompt.js" as Prompt

Column {
    id: prompt
    // The Agent's state for this attempt (see prompt.js). The host replaces the whole object when
    // something changes.
    property var agentState: ({ reachable: true, available: [], active: [], outcomes: {},
                           result: "", reason: "", retryAfter: 0, conditions: [], purpose: "unlock" })
    // Whether to show the tiles; the login screen of proposal D shows only the cards.
    property bool showTiles: true
    // The placeholder the host should put in its field: "PIN", "PIN locked" or "Password".
    readonly property string placeholder: Prompt.placeholder(agentState)

    spacing: 8

    Row {
        objectName: "tiles"
        visible: prompt.showTiles
        spacing: 8
        anchors.horizontalCenter: parent.horizontalCenter
        Repeater {
            model: Prompt.tiles(prompt.agentState)
            delegate: MethodTile {
                required property var modelData
                objectName: "tile-" + modelData.method
                method: modelData.method
                title: modelData.title
                detail: modelData.detail
                tone: modelData.tone
            }
        }
    }
    Repeater {
        model: Prompt.cards(prompt.agentState)
        delegate: ConditionCard {
            required property var modelData
            anchors.horizontalCenter: parent.horizontalCenter
            width: Math.max(implicitWidth, 352)
            severity: modelData.severity
            text: modelData.text
        }
    }
}
