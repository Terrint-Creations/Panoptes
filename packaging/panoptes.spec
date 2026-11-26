# PyInstaller spec: builds dist/Panoptes/Panoptes.exe (GUI) + panoptes-cli.exe (terminal), sharing one runtime.
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

hidden = (collect_submodules("holehe") + collect_submodules("phonenumbers") + collect_submodules("dns")
          + collect_submodules("panoptes") + ["PIL.ExifTags", "pypdf"])
datas = collect_data_files("phonenumbers") + collect_data_files("holehe")
excludes = ["PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick", "PySide6.Qt3DCore",
            "PySide6.QtQuick", "PySide6.QtQml", "PySide6.QtMultimedia", "PySide6.QtCharts", "PySide6.QtDataVisualization",
            "PySide6.QtPdf", "PySide6.QtBluetooth", "PySide6.QtLocation", "PySide6.QtSensors", "PySide6.QtSql",
            "tkinter", "matplotlib", "numpy", "pandas", "scipy", "IPython", "networkx"]

common = dict(pathex=[".."], hiddenimports=hidden, datas=datas, excludes=excludes, noarchive=False)
gui_a = Analysis(["launch_gui.py"], **common)
cli_a = Analysis(["launch_cli.py"], **common)

gui_pyz = PYZ(gui_a.pure)
cli_pyz = PYZ(cli_a.pure)

gui_exe = EXE(gui_pyz, gui_a.scripts, [], exclude_binaries=True, name="Panoptes", icon="panoptes.ico",
              console=False, upx=False)
cli_exe = EXE(cli_pyz, cli_a.scripts, [], exclude_binaries=True, name="panoptes-cli", icon="panoptes.ico",
              console=True, upx=False)

coll = COLLECT(gui_exe, gui_a.binaries, gui_a.datas, cli_exe, cli_a.binaries, cli_a.datas,
               name="Panoptes", upx=False)
