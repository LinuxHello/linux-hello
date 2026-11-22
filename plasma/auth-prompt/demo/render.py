#!/usr/bin/env python3
"""Draws demo/Demo.qml without a screen (Qt's offscreen platform) and saves it as a PNG.

Usage: QT_QPA_PLATFORM=offscreen python3 demo/render.py OUT.png   (needs PySide6 and Qt Quick)
"""
import os
import sys

from PySide6.QtCore import QTimer, QUrl
from PySide6.QtGui import QGuiApplication
from PySide6.QtQuick import QQuickView

here = os.path.dirname(os.path.abspath(__file__))
app = QGuiApplication(sys.argv)
view = QQuickView()
view.engine().addImportPath(os.path.join(here, ".."))
view.setSource(QUrl.fromLocalFile(os.path.join(here, "Demo.qml")))
if view.status() != QQuickView.Status.Ready:
    for error in view.errors():
        print(error.toString(), file=sys.stderr)
    sys.exit(1)
view.show()


def save():
    image = view.grabWindow()
    ok = image.save(sys.argv[1])
    print("saved" if ok else "not saved", sys.argv[1])
    app.exit(0 if ok else 1)


QTimer.singleShot(1500, save)
sys.exit(app.exec())
