#!/usr/bin/env python3
"""Qt and GTK host editors for the shared VibeOS configuration model."""

import argparse
import sys

import kconfig


class ConfigEditor:
    def __init__(self, args):
        self.args = args
        self.model = kconfig.parse_kconfig(args.kconfig)
        self.raw = kconfig.resolve(self.model, kconfig.parse_config(args.config))
        self.saved = self.raw.copy()
        self.symbols = [sym for sym in self.model.symbols if sym.prompt]

    @property
    def values(self):
        return kconfig.resolve(self.model, self.raw)

    @property
    def dirty(self):
        return self.raw != self.saved

    def set_value(self, sym, value):
        # Keep input while dependencies are disabled, so toggling a parent back
        # on restores edits. Resolve only for display, validation and saving.
        self.raw[sym.name] = value

    def save(self):
        values = self.values
        for sym in self.symbols:
            if sym.typ in (kconfig.INT, kconfig.HEX) and kconfig.eval_depends(sym.depends, values):
                try:
                    int(self.raw[sym.name], 0)
                except ValueError as exc:
                    raise ValueError(f"{sym.prompt}: enter a valid {sym.typ} value.") from exc
        kconfig.write_config(self.args.config, self.model, values)
        kconfig.write_outputs(self.model, values, self.args.out_mk, self.args.out_header)
        self.saved = self.raw.copy()


def help_text(sym):
    return (f"CONFIG_{sym.name}\nType: {sym.typ}\nDefault: {sym.default or '(none)'}"
            f"\nDepends on: {sym.depends or '(none)'}")


def qt_window(editor):
    try:
        from PySide6 import QtWidgets as Q
    except ImportError as exc:
        raise SystemExit("xconfig requires PySide6 for the host Python; install PySide6 "
                         "or select an interpreter with HOST_PYTHON=...") from exc

    class Window(Q.QWidget):
        def __init__(self):
            super().__init__()
            self.setWindowTitle(editor.model.mainmenu + " — xconfig")
            self.resize(850, 700)
            layout = Q.QVBoxLayout(self)
            scroll = Q.QScrollArea()
            scroll.setWidgetResizable(True)
            content = Q.QWidget()
            form = Q.QVBoxLayout(content)
            self.widgets = {}
            groups = {}
            for sym in editor.symbols:
                menu = sym.menu or "General"
                if menu not in groups:
                    box = Q.QGroupBox(menu)
                    groups[menu] = Q.QFormLayout(box)
                    form.addWidget(box)
                if sym.typ == kconfig.BOOL:
                    widget = Q.QCheckBox(sym.prompt)
                    widget.setChecked(editor.raw[sym.name] == "y")
                    widget.toggled.connect(lambda checked, s=sym: self.changed(s, "y" if checked else "n"))
                    groups[menu].addRow(widget)
                else:
                    widget = Q.QLineEdit(editor.raw[sym.name])
                    widget.textChanged.connect(lambda value, s=sym: self.changed(s, value))
                    groups[menu].addRow(sym.prompt, widget)
                widget.setToolTip(help_text(sym))
                self.widgets[sym.name] = widget
            form.addStretch()
            scroll.setWidget(content)
            layout.addWidget(scroll)
            self.status = Q.QLabel(editor.args.config)
            layout.addWidget(self.status)
            buttons = Q.QDialogButtonBox(Q.QDialogButtonBox.StandardButton.Save |
                                         Q.QDialogButtonBox.StandardButton.Close)
            buttons.button(Q.QDialogButtonBox.StandardButton.Save).clicked.connect(self.save)
            buttons.rejected.connect(self.close)
            layout.addWidget(buttons)
            self.refresh()

        def refresh(self):
            values = editor.values
            for sym in editor.symbols:
                widget = self.widgets[sym.name]
                enabled = kconfig.eval_depends(sym.depends, values)
                widget.setEnabled(enabled)
                if sym.typ == kconfig.BOOL:
                    widget.blockSignals(True)
                    widget.setChecked(values[sym.name] == "y")
                    widget.blockSignals(False)
            self.status.setText(editor.args.config + (" — Modified" if editor.dirty else ""))

        def changed(self, sym, value):
            editor.set_value(sym, value)
            self.refresh()

        def save(self):
            try:
                editor.save()
            except (OSError, ValueError) as exc:
                Q.QMessageBox.warning(self, "Cannot save configuration", str(exc))
                return False
            self.refresh()
            return True

        def closeEvent(self, event):
            if editor.dirty:
                buttons = Q.QMessageBox.StandardButton
                answer = Q.QMessageBox.question(self, "Unsaved changes", "Save configuration before closing?",
                                               buttons.Save | buttons.Discard | buttons.Cancel, buttons.Cancel)
                if answer == buttons.Cancel or (answer == buttons.Save and not self.save()):
                    event.ignore()
                    return
            event.accept()

    app = Q.QApplication.instance() or Q.QApplication([sys.argv[0]])
    return app, Window()


def gtk_window(editor):
    try:
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk
    except (ImportError, ValueError) as exc:
        raise SystemExit("gconfig requires PyGObject and GTK 3 for the host Python; "
                         "install python3-gi and gir1.2-gtk-3.0 (Debian/Ubuntu), "
                         "or select an interpreter with HOST_PYTHON=...") from exc
    if not Gtk.init_check()[0]:
        raise SystemExit("gconfig requires a graphical display (DISPLAY or WAYLAND_DISPLAY).")

    class Window(Gtk.Window):
        def __init__(self):
            super().__init__(title=editor.model.mainmenu + " — gconfig")
            self.set_default_size(850, 700)
            self.set_border_width(12)
            self.refreshing = False
            layout = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            self.add(layout)
            scroll = Gtk.ScrolledWindow()
            scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
            layout.pack_start(scroll, True, True, 0)
            content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            scroll.add(content)
            self.widgets = {}
            groups = {}
            for sym in editor.symbols:
                menu = sym.menu or "General"
                if menu not in groups:
                    frame = Gtk.Frame(label=menu)
                    group = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
                    group.set_border_width(10)
                    frame.add(group)
                    groups[menu] = group
                    content.pack_start(frame, False, False, 0)
                if sym.typ == kconfig.BOOL:
                    widget = Gtk.CheckButton(label=sym.prompt)
                    widget.set_active(editor.raw[sym.name] == "y")
                    widget.connect("toggled", lambda w, s=sym: self.changed(s, "y" if w.get_active() else "n"))
                    row = widget
                else:
                    row = Gtk.Box(spacing=12)
                    row.pack_start(Gtk.Label(label=sym.prompt, xalign=0), True, True, 0)
                    widget = Gtk.Entry()
                    widget.set_text(editor.raw[sym.name])
                    widget.connect("changed", lambda w, s=sym: self.changed(s, w.get_text()))
                    row.pack_end(widget, False, False, 0)
                widget.set_tooltip_text(help_text(sym))
                self.widgets[sym.name] = widget
                groups[menu].pack_start(row, False, False, 0)
            self.status = Gtk.Label(xalign=0)
            layout.pack_start(self.status, False, False, 0)
            buttons = Gtk.ButtonBox(orientation=Gtk.Orientation.HORIZONTAL)
            buttons.set_layout(Gtk.ButtonBoxStyle.END)
            for label, callback in (("Save", self.save), ("Close", self.close)):
                button = Gtk.Button(label=label)
                button.connect("clicked", lambda w, cb=callback: cb())
                buttons.add(button)
            layout.pack_start(buttons, False, False, 0)
            self.connect("delete-event", self.confirm_close)
            self.connect("destroy", lambda w: Gtk.main_quit() if Gtk.main_level() else None)
            self.refresh()

        def refresh(self):
            self.refreshing = True
            values = editor.values
            for sym in editor.symbols:
                widget = self.widgets[sym.name]
                widget.set_sensitive(kconfig.eval_depends(sym.depends, values))
                if sym.typ == kconfig.BOOL:
                    widget.set_active(values[sym.name] == "y")
            self.refreshing = False
            self.status.set_text(editor.args.config + (" — Modified" if editor.dirty else ""))

        def changed(self, sym, value):
            if not self.refreshing:
                editor.set_value(sym, value)
                self.refresh()

        def save(self):
            try:
                editor.save()
            except (OSError, ValueError) as exc:
                dialog = Gtk.MessageDialog(transient_for=self, modal=True,
                                           message_type=Gtk.MessageType.ERROR,
                                           buttons=Gtk.ButtonsType.CLOSE, text="Cannot save configuration")
                dialog.format_secondary_text(str(exc))
                dialog.run()
                dialog.destroy()
                return False
            self.refresh()
            return True

        def confirm_close(self, *unused):
            if not editor.dirty:
                return False
            dialog = Gtk.MessageDialog(transient_for=self, modal=True,
                                       message_type=Gtk.MessageType.QUESTION,
                                       text="Save configuration before closing?")
            dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Discard", Gtk.ResponseType.NO,
                               "Save", Gtk.ResponseType.YES)
            dialog.set_default_response(Gtk.ResponseType.CANCEL)
            answer = dialog.run()
            dialog.destroy()
            return answer != Gtk.ResponseType.NO and (answer != Gtk.ResponseType.YES or not self.save())

    return Gtk, Window()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("frontend", choices=("xconfig", "gconfig"))
    kconfig.add_common(parser)
    parser.add_argument("--out-mk", default="build/config.mk")
    parser.add_argument("--out-header", default="build/include/generated/autoconf.h")
    args = parser.parse_args(argv)
    editor = ConfigEditor(args)
    if args.frontend == "xconfig":
        app, window = qt_window(editor)
        window.show()
        return app.exec()
    gtk, window = gtk_window(editor)
    window.show_all()
    gtk.main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
