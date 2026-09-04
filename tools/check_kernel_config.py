#!/usr/bin/env python3
"""Test kernel feature configurations without changing the user's .config."""

import os
from pathlib import Path
import subprocess
import tempfile

import kconfig


def main():
    root = Path(__file__).resolve().parent.parent
    os.chdir(root)
    model = kconfig.parse_kconfig("Kconfig")
    disabled = {
        sym.name: "n" for sym in model.symbols
        if sym.name.startswith("KERNEL_") and sym.typ == kconfig.BOOL
    }
    variants = {
        "default": {},
        "disabled": disabled,
        "mixed": {
            "KERNEL_INET": "n", "KERNEL_EXT2": "n",
            "KERNEL_PS2_MOUSE": "n", "KERNEL_PTYS": "n",
        },
        "no-keyboard": {"KERNEL_PS2_KEYBOARD": "n"},
        "no-evdev": {"KERNEL_INPUT_EVENTS": "n"},
    }
    env = os.environ.copy()
    env.setdefault("ZIG_GLOBAL_CACHE_DIR", str(root / "build/zig-global-cache"))
    env.setdefault("ZIG_LOCAL_CACHE_DIR", str(root / "build/zig-local-cache"))
    with tempfile.TemporaryDirectory(prefix="vibeos-config-") as tmp:
        for name, raw in variants.items():
            directory = Path(tmp) / name
            values = kconfig.resolve(model, raw)
            if name == "mixed":
                for symbol in ("VIRTIO_NET", "TCP_SOCKETS", "UDP_SOCKETS", "RAW_ICMP_SOCKETS",
                               "ICMP_ECHO", "EXT2_WRITE", "USR_AUTOMOUNT", "HOME_AUTOMOUNT"):
                    assert values[f"KERNEL_{symbol}"] == "n", symbol
                assert values["KERNEL_INPUT_EVENTS"] == "y"
            if name == "no-keyboard":
                assert values["KERNEL_INPUT_EVENTS"] == "y"
            if name == "disabled":
                assert values["KERNEL_INPUT_EVENTS"] == "n"
            kconfig.write_config(str(directory / ".config"), model, values)
            assert kconfig.resolve(model, kconfig.parse_config(str(directory / ".config"))) == values
            header = directory / "autoconf.h"
            kconfig.write_outputs(model, values, str(directory / "config.mk"), str(header))
            print(f"{name}:", flush=True)
            for test in ("kernel-config", "kernel-input-config", "kernel-fs-config"):
                binary = directory / test
                subprocess.run([
                    "zig", "cc", "-target", "x86_64-linux-musl", "-static", "-no-pie",
                    "-std=gnu11", "-O2", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-Ikernel/include", "-include", str(header),
                    "-Wl,--gc-sections", f"tests/{test}-host-test.c", "-o", str(binary),
                ], check=True, env=env)
                subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
