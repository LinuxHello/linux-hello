// One line the person should read, in a coloured card with a mark: an error or a severe condition
// (red), a warning such as Linux Hello not running (orange), information (blue) or a success
// (green). Part of the Auth Prompt (C4 component authPrompt).
import QtQuick

Rectangle {
    id: card
    property string severity: "info"
    property string text: ""

    readonly property color accent: severity === "severe" ? "#ed1515"
        : severity === "warning" ? "#f67400"
        : severity === "success" ? "#27ae60"
        : "#3daee9"

    implicitWidth: 360
    implicitHeight: line.implicitHeight + 14
    radius: 4
    color: Qt.rgba(accent.r, accent.g, accent.b, 0.14)
    border.color: accent
    border.width: 1

    Rectangle {
        id: mark
        width: 16
        height: 16
        radius: 8
        color: "transparent"
        border.color: card.accent
        border.width: 1.5
        anchors.left: parent.left
        anchors.leftMargin: 8
        anchors.top: parent.top
        anchors.topMargin: 8
        Text {
            anchors.centerIn: parent
            text: card.severity === "info" || card.severity === "success" ? "i" : "!"
            color: card.accent
            font.pixelSize: 11
            font.bold: true
        }
    }
    Text {
        id: line
        objectName: "text"
        text: card.text
        color: "#fcfcfc"
        font.pixelSize: 13
        wrapMode: Text.WordWrap
        anchors.left: mark.right
        anchors.leftMargin: 8
        anchors.right: parent.right
        anchors.rightMargin: 8
        anchors.verticalCenter: parent.verticalCenter
    }
}
