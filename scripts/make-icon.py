"""Generate the app's simple shield icon from its own vector geometry."""
from pathlib import Path
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QImage, QPainter, QColor, QPainterPath
from PySide6.QtCore import Qt

app = QApplication.instance() or QApplication([])
image = QImage(256, 256, QImage.Format_ARGB32)
image.fill(Qt.transparent)
painter = QPainter(image)
painter.setRenderHint(QPainter.Antialiasing)
shield = QPainterPath()
shield.moveTo(128, 16)
shield.lineTo(224, 52)
shield.lineTo(212, 150)
shield.quadTo(192, 210, 128, 242)
shield.quadTo(64, 210, 44, 150)
shield.lineTo(32, 52)
shield.closeSubpath()
painter.fillPath(shield, QColor('#0067c0'))
painter.setPen(Qt.NoPen)
painter.setBrush(QColor('white'))
for y in (78, 113, 148):
    painter.drawRoundedRect(75, y, 106, 19, 4, 4)
painter.end()
Path('build').mkdir(exist_ok=True)
if not image.save('build/win-harden.ico'):
    raise SystemExit('Qt could not write the ICO image')
