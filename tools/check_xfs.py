#!/usr/bin/env python3
"""Exercise the kernel XFS reader against mkfs.xfs images, without mounting them."""
import pathlib
import shutil
import subprocess
import tempfile
import sys


def main():
    binary = pathlib.Path(sys.argv[1]).resolve()
    if not shutil.which("mkfs.xfs"):
        raise SystemExit("check-xfs requires mkfs.xfs (xfsprogs)")
    with tempfile.TemporaryDirectory(prefix="vibeos-xfs-") as tmp:
        root = pathlib.Path(tmp)
        hello = root / "hello"
        hello.write_bytes(b"hello from XFS\n")
        large = root / "large"
        large.write_bytes(bytes(range(256)) * 257)
        for name, flags, extra in (
            ("v5-shortform", [], 0),
            ("v5-block", [], 25),
            ("v5-leaf", [], 600),
            ("v5-large-dirblock", ["-n", "size=16384"], 600),
            ("v4-shortform", ["-m", "crc=0", "-i", "sparse=0", "-n", "ftype=0"], 0),
            ("v4-leaf", ["-m", "crc=0", "-i", "sparse=0"], 600),
        ):
            image = root / f"{name}.img"
            with image.open("wb") as f:
                f.truncate(384 * 1024 * 1024)
            proto = root / "proto"
            proto.write_text("\n".join([
                "boot", "0 0", "d--755 0 0",
                f"hello ---644 1000 1000 {hello}",
                "link l--777 0 0 hello",
                "sub d--755 0 0", f"nested ---644 0 0 {hello}", "$",
                f"large ---644 0 0 {large}",
                "remote l--777 0 0 " + "a" * 700,
                "empty d--755 0 0", "$",
                *[f"file{i:04} ---644 0 0 {hello}" for i in range(extra)], "$", "",
            ]))
            print(name, flush=True)
            subprocess.run(["mkfs.xfs", "-f", "-q", *flags, "-p", str(proto), str(image)], check=True)
            subprocess.run([str(binary), str(image)], check=True)
            image.unlink()


if __name__ == "__main__":
    main()
