#!/usr/bin/env python3
"""Small Kconfig-like configurator for VibeOS.

This intentionally implements the subset VibeOS needs: menus, bool/string/int/hex
symbols, defaults, simple "depends on" expressions, .config I/O, generated make
variables, and a generated C autoconf header.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import sys
import textwrap
from dataclasses import dataclass, field
from typing import Iterable


BOOL = "bool"
STRING = "string"
INT = "int"
HEX = "hex"


@dataclass
class Symbol:
    name: str
    typ: str = BOOL
    prompt: str | None = None
    default: str | None = None
    depends: str | None = None
    menu: str = ""
    order: int = 0


@dataclass
class Model:
    mainmenu: str = "Configuration"
    symbols: list[Symbol] = field(default_factory=list)

    def by_name(self) -> dict[str, Symbol]:
        return {sym.name: sym for sym in self.symbols}


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return bytes(value[1:-1], "utf-8").decode("unicode_escape")
    return value


def parse_kconfig(path: str) -> Model:
    model = Model()
    menu_stack: list[str] = []
    current: Symbol | None = None
    order = 0

    with open(path, "r", encoding="utf-8") as f:
        for line_no, raw in enumerate(f, 1):
            line = raw.rstrip("\n")
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if stripped.startswith("mainmenu "):
                model.mainmenu = unquote(stripped[len("mainmenu ") :])
                continue

            if stripped.startswith("menu "):
                menu_stack.append(unquote(stripped[len("menu ") :]))
                continue

            if stripped == "endmenu":
                if not menu_stack:
                    raise SystemExit(f"{path}:{line_no}: endmenu without menu")
                menu_stack.pop()
                continue

            if stripped.startswith("config "):
                name = stripped[len("config ") :].strip()
                if not re.fullmatch(r"[A-Z0-9_]+", name):
                    raise SystemExit(f"{path}:{line_no}: invalid symbol name: {name}")
                order += 1
                current = Symbol(name=name, menu=" / ".join(menu_stack), order=order)
                model.symbols.append(current)
                continue

            if current is None:
                raise SystemExit(f"{path}:{line_no}: property outside config: {stripped}")

            words = stripped.split(None, 1)
            key = words[0]
            rest = words[1] if len(words) > 1 else ""

            if key in {BOOL, STRING, INT, HEX}:
                current.typ = key
                if rest:
                    current.prompt = unquote(rest)
                continue

            if key == "prompt":
                current.prompt = unquote(rest)
                continue

            if key == "default":
                current.default = unquote(rest)
                continue

            if key == "depends" and rest.startswith("on "):
                current.depends = rest[len("on ") :].strip()
                continue

            raise SystemExit(f"{path}:{line_no}: unsupported Kconfig line: {stripped}")

    return model


def parse_config(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    if not os.path.exists(path):
        return values

    set_re = re.compile(r"^CONFIG_([A-Z0-9_]+)=(.*)$")
    unset_re = re.compile(r"^# CONFIG_([A-Z0-9_]+) is not set$")
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            m = set_re.match(line)
            if m:
                value = m.group(2)
                if len(value) >= 2 and value[0] == value[-1] == '"':
                    value = shlex.split(value)[0]
                values[m.group(1)] = value
                continue
            m = unset_re.match(line)
            if m:
                values[m.group(1)] = "n"
    return values


def bool_value(value: str | None) -> bool:
    return value == "y"


def eval_depends(expr: str | None, values: dict[str, str]) -> bool:
    if not expr:
        return True

    tokens = re.findall(r"[A-Z0-9_]+|&&|\|\||!|\(|\)|y|n", expr)
    pos = 0

    def parse_primary() -> bool:
        nonlocal pos
        if pos >= len(tokens):
            return False
        tok = tokens[pos]
        pos += 1
        if tok == "!":
            return not parse_primary()
        if tok == "(":
            value = parse_or()
            if pos < len(tokens) and tokens[pos] == ")":
                pos += 1
            return value
        if tok == "y":
            return True
        if tok == "n":
            return False
        return bool_value(values.get(tok, "n"))

    def parse_and() -> bool:
        nonlocal pos
        value = parse_primary()
        while pos < len(tokens) and tokens[pos] == "&&":
            pos += 1
            value = parse_primary() and value
        return value

    def parse_or() -> bool:
        nonlocal pos
        value = parse_and()
        while pos < len(tokens) and tokens[pos] == "||":
            pos += 1
            value = parse_and() or value
        return value

    return parse_or()


def normalize_value(sym: Symbol, value: str | None, values: dict[str, str]) -> str:
    if not eval_depends(sym.depends, values):
        return "n" if sym.typ == BOOL else ""

    if value is None or value == "":
        value = sym.default
    if value is None:
        value = "n" if sym.typ == BOOL else ""

    if sym.typ == BOOL:
        return "y" if value in {"y", "Y", "1", "true", "True"} else "n"
    if sym.typ == INT:
        try:
            return str(int(value, 0))
        except ValueError:
            return str(int(sym.default or "0", 0))
    if sym.typ == HEX:
        try:
            return hex(int(value, 0))
        except ValueError:
            return hex(int(sym.default or "0", 0))
    return value


def resolve(model: Model, raw_values: dict[str, str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for sym in model.symbols:
        values[sym.name] = normalize_value(sym, raw_values.get(sym.name), values)
    return values


def config_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_config(path: str, model: Model, values: dict[str, str], minimal: bool = False) -> None:
    lines = [f"# {model.mainmenu}", "# Generated by tools/kconfig.py", ""]
    current_menu = None
    for sym in model.symbols:
        if sym.menu != current_menu:
            current_menu = sym.menu
            if current_menu:
                lines.extend([f"#", f"# {current_menu}", f"#"])

        default_value = normalize_value(sym, None, values)
        value = values[sym.name]
        if minimal and value == default_value:
            continue
        if sym.typ == BOOL:
            if value == "y":
                lines.append(f"CONFIG_{sym.name}=y")
            else:
                lines.append(f"# CONFIG_{sym.name} is not set")
        elif sym.typ == STRING:
            lines.append(f"CONFIG_{sym.name}={config_quote(value)}")
        else:
            lines.append(f"CONFIG_{sym.name}={value}")
    lines.append("")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def make_quote(value: str) -> str:
    return value.replace("$", "$$")


def write_outputs(model: Model, values: dict[str, str], out_mk: str, out_header: str) -> None:
    os.makedirs(os.path.dirname(out_mk), exist_ok=True)
    os.makedirs(os.path.dirname(out_header), exist_ok=True)

    with open(out_mk, "w", encoding="utf-8") as f:
        f.write("# Generated by tools/kconfig.py; do not edit.\n")
        for sym in model.symbols:
            f.write(f"CONFIG_{sym.name} := {make_quote(values[sym.name])}\n")

    with open(out_header, "w", encoding="utf-8") as f:
        guard = "VIBEOS_GENERATED_AUTOCONF_H"
        f.write("/* Generated by tools/kconfig.py; do not edit. */\n")
        f.write(f"#ifndef {guard}\n#define {guard}\n\n")
        for sym in model.symbols:
            value = values[sym.name]
            if sym.typ == BOOL:
                if value == "y":
                    f.write(f"#define CONFIG_{sym.name} 1\n")
                else:
                    f.write(f"/* #undef CONFIG_{sym.name} */\n")
            elif sym.typ == STRING:
                f.write(f"#define CONFIG_{sym.name} {config_quote(value)}\n")
            else:
                f.write(f"#define CONFIG_{sym.name} {value}\n")
        f.write(f"\n#endif /* {guard} */\n")


def prompt_bool(sym: Symbol, value: str) -> str:
    default = "Y/n" if value == "y" else "y/N"
    answer = input(f"{sym.prompt or sym.name} ({default}) ").strip().lower()
    if answer in {"y", "yes"}:
        return "y"
    if answer in {"n", "no"}:
        return "n"
    return value


def prompt_value(sym: Symbol, value: str) -> str:
    answer = input(f"{sym.prompt or sym.name} [{value}] ").strip()
    return answer if answer else value


def run_config(model: Model, config_path: str, old: bool = False) -> None:
    values = resolve(model, parse_config(config_path))
    for sym in model.symbols:
        if old and sym.name in parse_config(config_path):
            continue
        if sym.typ == BOOL:
            values[sym.name] = prompt_bool(sym, values[sym.name])
        else:
            values[sym.name] = prompt_value(sym, values[sym.name])
    values = resolve(model, values)
    write_config(config_path, model, values)


def run_menuconfig(model: Model, config_path: str) -> None:
    try:
        import curses
    except ImportError as exc:
        raise SystemExit("menuconfig requires Python curses support") from exc

    values = resolve(model, parse_config(config_path))
    symbols = [sym for sym in model.symbols if sym.prompt]

    def visible_items() -> list[tuple[str, str | Symbol]]:
        items: list[tuple[str, str | Symbol]] = []
        current_menu = None
        for sym in symbols:
            if not eval_depends(sym.depends, values):
                continue
            if sym.menu != current_menu:
                current_menu = sym.menu
                items.append(("menu", current_menu or "General"))
            items.append(("symbol", sym))
        return items

    def symbol_rows(items: list[tuple[str, str | Symbol]]) -> list[int]:
        return [i for i, (kind, _) in enumerate(items) if kind == "symbol"]

    def clamp_selection(items: list[tuple[str, str | Symbol]], selected: int) -> int:
        rows = symbol_rows(items)
        if not rows:
            return 0
        if selected in rows:
            return selected
        return min(rows, key=lambda row: abs(row - selected))

    def row_label(sym: Symbol) -> str:
        value = values[sym.name]
        prompt = sym.prompt or sym.name
        if sym.typ == BOOL:
            marker = "[*]" if value == "y" else "[ ]"
            return f"{marker} {prompt}"
        return f"({value}) {prompt}"

    def draw_centered(win, y: int, text: str, attr: int = 0) -> None:
        height, width = win.getmaxyx()
        if y < 0 or y >= height:
            return
        x = max(0, (width - len(text)) // 2)
        win.addnstr(y, x, text, max(0, width - x - 1), attr)

    def draw_message(stdscr, text: str) -> None:
        height, width = stdscr.getmaxyx()
        stdscr.move(height - 2, 2)
        stdscr.clrtoeol()
        stdscr.addnstr(height - 2, 2, text, max(0, width - 4), curses.A_BOLD)
        stdscr.refresh()

    def popup(stdscr, title: str, body: list[str]) -> None:
        height, width = stdscr.getmaxyx()
        popup_width = min(max(54, *(len(line) + 4 for line in body), len(title) + 8), width - 4)
        popup_height = min(len(body) + 4, height - 4)
        y = max(0, (height - popup_height) // 2)
        x = max(0, (width - popup_width) // 2)
        win = curses.newwin(popup_height, popup_width, y, x)
        win.keypad(True)
        win.box()
        draw_centered(win, 0, f" {title} ", curses.A_BOLD)
        for idx, line in enumerate(body[: popup_height - 4], 2):
            win.addnstr(idx, 2, line, popup_width - 4)
        draw_centered(win, popup_height - 2, "< Press any key >", curses.A_REVERSE)
        win.refresh()
        win.getch()

    def confirm(stdscr, question: str) -> bool:
        height, width = stdscr.getmaxyx()
        popup_width = min(max(48, len(question) + 8), width - 4)
        popup_height = 7
        y = max(0, (height - popup_height) // 2)
        x = max(0, (width - popup_width) // 2)
        win = curses.newwin(popup_height, popup_width, y, x)
        win.keypad(True)
        while True:
            win.erase()
            win.box()
            draw_centered(win, 1, "Confirm", curses.A_BOLD)
            draw_centered(win, 3, question)
            draw_centered(win, 5, "<Y> Yes    <N> No", curses.A_REVERSE)
            win.refresh()
            key = win.getch()
            if key in (ord("y"), ord("Y")):
                return True
            if key in (ord("n"), ord("N"), 27):
                return False

    def edit_value(stdscr, sym: Symbol) -> None:
        height, width = stdscr.getmaxyx()
        popup_width = min(max(60, len(sym.prompt or sym.name) + 8), width - 4)
        popup_height = 8
        y = max(0, (height - popup_height) // 2)
        x = max(0, (width - popup_width) // 2)
        win = curses.newwin(popup_height, popup_width, y, x)
        curses.echo()
        curses.curs_set(1)
        try:
            win.erase()
            win.box()
            draw_centered(win, 1, sym.prompt or sym.name, curses.A_BOLD)
            win.addnstr(3, 2, f"CONFIG_{sym.name}", popup_width - 4)
            win.addnstr(5, 2, "> ", popup_width - 4)
            win.addnstr(5, 4, values[sym.name], popup_width - 6)
            win.move(5, 4 + min(len(values[sym.name]), popup_width - 7))
            win.refresh()
            raw = win.getstr(5, 4, max(1, popup_width - 7))
        finally:
            curses.noecho()
            curses.curs_set(0)
        answer = raw.decode("utf-8", errors="replace").strip()
        if answer:
            values[sym.name] = normalize_value(sym, answer, values)

    def help_for(sym: Symbol) -> list[str]:
        lines = [
            f"Symbol: CONFIG_{sym.name}",
            f"Type: {sym.typ}",
            f"Prompt: {sym.prompt or sym.name}",
        ]
        if sym.default is not None:
            lines.append(f"Default: {sym.default}")
        if sym.depends:
            lines.append(f"Depends on: {sym.depends}")
        if sym.menu:
            lines.append(f"Location: {sym.menu}")
        lines.append("")
        lines.extend(
            textwrap.wrap(
                "Use Space to toggle boolean options. Use Enter to edit string, "
                "integer, and hex options. Press S to save the current configuration.",
                width=66,
            )
        )
        return lines

    def app(stdscr) -> bool:
        nonlocal values
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        selected_attr = curses.A_REVERSE
        menu_attr = curses.A_BOLD
        if curses.has_colors():
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)
            curses.init_pair(2, curses.COLOR_CYAN, -1)
            selected_attr = curses.color_pair(1)
            menu_attr = curses.color_pair(2) | curses.A_BOLD
        selected = 0
        top = 0
        dirty = False
        message = ""

        while True:
            stdscr.erase()
            height, width = stdscr.getmaxyx()
            if height < 12 or width < 54:
                stdscr.addnstr(0, 0, "Terminal too small for menuconfig", width - 1)
                stdscr.refresh()
                key = stdscr.getch()
                if key in (ord("q"), ord("Q"), 27):
                    return dirty
                continue

            items = visible_items()
            selected = clamp_selection(items, selected)
            rows = symbol_rows(items)
            visible_height = height - 8
            if selected < top:
                top = selected
            if selected >= top + visible_height:
                top = selected - visible_height + 1
            top = max(0, min(top, max(0, len(items) - visible_height)))

            stdscr.box()
            draw_centered(stdscr, 0, f" {model.mainmenu} ", curses.A_BOLD)
            draw_centered(stdscr, 2, "Arrow keys navigate, Space selects, Enter edits, S saves, Q exits")

            for screen_row, item_idx in enumerate(range(top, min(len(items), top + visible_height)), 4):
                kind, payload = items[item_idx]
                if kind == "menu":
                    text = f"--- {payload} ---"
                    stdscr.addnstr(screen_row, 4, text, width - 8, menu_attr)
                    continue
                sym = payload
                assert isinstance(sym, Symbol)
                attr = selected_attr if item_idx == selected else curses.A_NORMAL
                stdscr.addnstr(screen_row, 4, row_label(sym), width - 8, attr)

            if top > 0:
                draw_centered(stdscr, 3, "(-)")
            if top + visible_height < len(items):
                draw_centered(stdscr, height - 4, "(+)")
            if dirty:
                stdscr.addnstr(height - 3, 2, "Modified", width - 4, curses.A_BOLD)
            if message:
                stdscr.addnstr(height - 2, 2, message, width - 4)
            draw_centered(stdscr, height - 1, "<Select> <Exit> <Help> <Save>", curses.A_REVERSE)
            stdscr.refresh()

            key = stdscr.getch()
            message = ""

            if key in (curses.KEY_UP, ord("k"), ord("K")) and rows:
                prior = [row for row in rows if row < selected]
                selected = prior[-1] if prior else rows[-1]
            elif key in (curses.KEY_DOWN, ord("j"), ord("J")) and rows:
                after = [row for row in rows if row > selected]
                selected = after[0] if after else rows[0]
            elif key in (curses.KEY_PPAGE,):
                for _ in range(max(1, visible_height - 1)):
                    prior = [row for row in rows if row < selected]
                    selected = prior[-1] if prior else selected
            elif key in (curses.KEY_NPAGE,):
                for _ in range(max(1, visible_height - 1)):
                    after = [row for row in rows if row > selected]
                    selected = after[0] if after else selected
            elif key in (ord(" "), ord("\n"), curses.KEY_ENTER, 10, 13) and items:
                kind, payload = items[selected]
                if kind != "symbol":
                    continue
                sym = payload
                assert isinstance(sym, Symbol)
                if sym.typ == BOOL:
                    values[sym.name] = "n" if values[sym.name] == "y" else "y"
                else:
                    edit_value(stdscr, sym)
                values = resolve(model, values)
                selected = clamp_selection(visible_items(), selected)
                dirty = True
            elif key in (ord("h"), ord("H"), ord("?")) and items:
                kind, payload = items[selected]
                if kind == "symbol":
                    assert isinstance(payload, Symbol)
                    popup(stdscr, "Help", help_for(payload))
            elif key in (ord("s"), ord("S")):
                write_config(config_path, model, resolve(model, values))
                dirty = False
                message = f"Wrote {config_path}"
            elif key in (ord("q"), ord("Q"), 27):
                if dirty:
                    if confirm(stdscr, "Save configuration before exit?"):
                        write_config(config_path, model, resolve(model, values))
                        return False
                    if confirm(stdscr, "Exit without saving changes?"):
                        return True
                else:
                    return False

    unsaved = curses.wrapper(app)
    if unsaved:
        print("Configuration changes were not saved.")


def load_model(args: argparse.Namespace) -> Model:
    return parse_kconfig(args.kconfig)


def cmd_defconfig(args: argparse.Namespace) -> None:
    model = load_model(args)
    write_config(args.config, model, resolve(model, {}))


def cmd_olddefconfig(args: argparse.Namespace) -> None:
    model = load_model(args)
    write_config(args.config, model, resolve(model, parse_config(args.config)))


def cmd_sync(args: argparse.Namespace) -> None:
    model = load_model(args)
    values = resolve(model, parse_config(args.config))
    write_config(args.config, model, values)
    write_outputs(model, values, args.out_mk, args.out_header)


def cmd_savedefconfig(args: argparse.Namespace) -> None:
    model = load_model(args)
    values = resolve(model, parse_config(args.config))
    write_config(args.output, model, values, minimal=True)


def cmd_config(args: argparse.Namespace) -> None:
    run_config(load_model(args), args.config, old=False)


def cmd_oldconfig(args: argparse.Namespace) -> None:
    run_config(load_model(args), args.config, old=True)


def cmd_menuconfig(args: argparse.Namespace) -> None:
    menuconfig = os.environ.get("MENUCONFIG", "build/tools/menuconfig")
    if not os.path.exists(menuconfig):
        raise SystemExit("menuconfig is implemented by the ncurses host tool; run `make menuconfig` first")
    os.execvp(menuconfig, [menuconfig, "--kconfig", args.kconfig, "--config", args.config])


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--kconfig", default="Kconfig")
    parser.add_argument("--config", default=".config")


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description="VibeOS Kconfig-like configurator")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, func in {
        "defconfig": cmd_defconfig,
        "olddefconfig": cmd_olddefconfig,
        "config": cmd_config,
        "oldconfig": cmd_oldconfig,
        "menuconfig": cmd_menuconfig,
    }.items():
        p = sub.add_parser(name)
        add_common(p)
        p.set_defaults(func=func)

    p = sub.add_parser("sync")
    add_common(p)
    p.add_argument("--out-mk", required=True)
    p.add_argument("--out-header", required=True)
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("savedefconfig")
    add_common(p)
    p.add_argument("--output", default="defconfig")
    p.set_defaults(func=cmd_savedefconfig)

    args = parser.parse_args(list(argv))
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
