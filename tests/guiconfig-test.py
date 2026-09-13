#!/usr/bin/env python3
"""Exercise each native editor: xvfb-run -a python3 tests/guiconfig-test.py."""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import guiconfig
import kconfig


def exercise(frontend):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / "Kconfig"
        source.write_text('''mainmenu "Test configuration"
menu "Options"
config PARENT
 bool "Parent"
 default y
config CHILD
 bool "Child"
 default y
 depends on PARENT
config NUMBER
 int "Number"
 default 42
config ADDRESS
 hex "Address"
 default 0x10
config TEXT
 string "Text"
 default "hello"
endmenu
''')
        args = argparse.Namespace(kconfig=str(source), config=str(root / ".config"),
                                  out_mk=str(root / "build/config.mk"),
                                  out_header=str(root / "build/autoconf.h"))
        editor = guiconfig.ConfigEditor(args)
        if frontend == "xconfig":
            app, window = guiconfig.qt_window(editor)
            window.show()
            app.processEvents()
            toggle = lambda name, value: window.widgets[name].setChecked(value)
            enter = lambda name, value: window.widgets[name].setText(value)
            enabled = lambda name: window.widgets[name].isEnabled()
            checked = lambda name: window.widgets[name].isChecked()
        else:
            app, window = guiconfig.gtk_window(editor)
            window.show_all()
            while app.events_pending():
                app.main_iteration()
            toggle = lambda name, value: window.widgets[name].set_active(value)
            enter = lambda name, value: window.widgets[name].set_text(value)
            enabled = lambda name: window.widgets[name].get_sensitive()
            checked = lambda name: window.widgets[name].get_active()
        assert not Path(args.config).exists(), "Opening must not create configuration"
        toggle("PARENT", False)
        assert editor.dirty and not enabled("CHILD") and not checked("CHILD")
        assert window.save()
        assert kconfig.parse_config(args.config)["CHILD"] == "n"
        toggle("PARENT", True)
        assert enabled("CHILD") and checked("CHILD"), "Restore child after parent is re-enabled"
        enter("NUMBER", "invalid")
        before = Path(args.config).read_bytes()
        try:
            editor.save()
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid integer accepted")
        assert Path(args.config).read_bytes() == before
        enter("NUMBER", "123")
        enter("ADDRESS", "0xff")
        enter("TEXT", 'quoted "text" \\ path')
        assert window.save() and not editor.dirty
        values = kconfig.parse_config(args.config)
        assert values["NUMBER"] == "123" and values["ADDRESS"] == "0xff"
        assert values["TEXT"] == 'quoted "text" \\ path'
        assert "CONFIG_NUMBER := 123" in Path(args.out_mk).read_text()
        assert "#define CONFIG_CHILD 1" in Path(args.out_header).read_text()
        assert "#define CONFIG_ADDRESS 0xff" in Path(args.out_header).read_text()
        snapshots = {path: Path(path).read_bytes() for path in
                     (args.config, args.out_mk, args.out_header)}
        enter("TEXT", "unsaved edit")
        if frontend == "xconfig":
            from PySide6 import QtGui, QtWidgets
            from unittest.mock import patch

            def close_with(response):
                event = QtGui.QCloseEvent()
                with patch.object(QtWidgets.QMessageBox, "question", return_value=response):
                    window.closeEvent(event)
                return event.isAccepted()

            assert not close_with(QtWidgets.QMessageBox.StandardButton.Cancel)
            assert editor.dirty
            assert close_with(QtWidgets.QMessageBox.StandardButton.Discard)
            window.hide()
        else:
            from gi.repository import GLib

            def close_with(response):
                def respond():
                    for dialog in app.Window.list_toplevels():
                        if isinstance(dialog, app.MessageDialog):
                            dialog.response(response)
                    return False

                GLib.idle_add(respond)
                window.close()
                while app.events_pending():
                    app.main_iteration()

            close_with(app.ResponseType.CANCEL)
            assert window.get_visible() and editor.dirty
            close_with(app.ResponseType.NO)
            assert not window.get_visible()
        assert all(Path(path).read_bytes() == data for path, data in snapshots.items())
        # No-op close must not rewrite files, even when no configuration exists.
        Path(args.config).unlink()
        editor = guiconfig.ConfigEditor(args)
        if frontend == "xconfig":
            app, window = guiconfig.qt_window(editor)
            window.show()
        else:
            app, window = guiconfig.gtk_window(editor)
            window.show_all()
        window.close()
        if frontend == "xconfig":
            app.processEvents()
        else:
            while app.events_pending():
                app.main_iteration()
        assert not Path(args.config).exists()
    print(f"{frontend}: passed", flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        exercise(sys.argv[1])
    else:
        for frontend in ("xconfig", "gconfig"):
            subprocess.run([sys.executable, __file__, frontend], check=True,
                           env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
