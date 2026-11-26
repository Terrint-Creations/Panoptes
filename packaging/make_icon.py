"""Render the Panoptes eye icon to packaging/panoptes.ico (multi-resolution)."""
import io
import sys
from pathlib import Path

from PIL import Image
from PySide6.QtCore import QBuffer, QIODevice
from PySide6.QtWidgets import QApplication

from panoptes.gui.app import eye_icon

app = QApplication(sys.argv[:1])
pm = eye_icon(256).pixmap(256, 256)
buf = QBuffer()
buf.open(QIODevice.WriteOnly)
pm.save(buf, "PNG")
img = Image.open(io.BytesIO(bytes(buf.data())))
out = Path(__file__).with_name("panoptes.ico")
img.save(out, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print(out)
