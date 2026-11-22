// One method of a sign-in attempt (PIN, fingerprint or face) and its state, as a small tile with an
// icon, the method's name and one line of detail. The tone colours it: running (blue), success
// (green), failure (red), idle or disabled (grey). Part of the Auth Prompt (C4 component authPrompt).
import QtQuick

Rectangle {
    id: tile
    property string method: "pin"
    property string title: "PIN"
    property string detail: ""
    property string tone: "idle"

    readonly property color accent: tone === "running" ? "#3daee9"
        : tone === "success" ? "#27ae60"
        : tone === "failure" ? "#ed1515"
        : "#4d5459"

    implicitWidth: 112
    implicitHeight: 50
    radius: 4
    color: tone === "disabled" ? "transparent" : Qt.rgba(accent.r, accent.g, accent.b, 0.12)
    border.color: accent
    border.width: 1
    opacity: tone === "disabled" ? 0.55 : 1.0

    Image {
        id: icon
        source: "icon-" + tile.method + ".svg"
        sourceSize.width: 18
        sourceSize.height: 18
        anchors.left: parent.left
        anchors.leftMargin: 8
        anchors.verticalCenter: parent.verticalCenter
    }
    Column {
        anchors.left: icon.right
        anchors.leftMargin: 8
        anchors.right: parent.right
        anchors.rightMargin: 6
        anchors.verticalCenter: parent.verticalCenter
        Text {
            objectName: "title"
            text: tile.title
            color: "#fcfcfc"
            font.pixelSize: 12
            font.bold: true
        }
        Text {
            objectName: "detail"
            text: tile.detail
            color: tile.tone === "idle" || tile.tone === "disabled" ? "#a1a9b1" : tile.accent
            font.pixelSize: 11
            lineHeight: 0.9
            width: parent.width
            wrapMode: Text.WordWrap
            maximumLineCount: 2
            elide: Text.ElideRight
        }
    }
}
