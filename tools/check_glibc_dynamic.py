#!/usr/bin/env python3

import os
import selectors
import shutil
import subprocess
import sys
import tempfile
import time


def fail(message: str, output: bytearray) -> None:
    sys.stderr.write(output.decode("utf-8", errors="replace"))
    raise RuntimeError(message)


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: check_glibc_dynamic.py <gpt-image> <usr-image> <home-image>", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="vibeos-glibc-", dir="/tmp") as temp_dir:
        images = []
        for source in sys.argv[1:]:
            destination = os.path.join(temp_dir, os.path.basename(source))
            shutil.copyfile(source, destination)
            images.append(destination)

        command = [
            "qemu-system-x86_64",
            "-name", "vibeos-glibc-check",
            "-machine", "q35,accel=tcg",
            "-cpu", "max",
            "-m", "1G",
            "-display", "none",
            "-device", "virtio-vga",
            "-drive", f"format=raw,file={images[0]},if=ide,index=0",
            "-device", "virtio-scsi-pci-transitional,id=scsi0",
            "-drive", f"format=raw,file={images[1]},if=none,id=usr",
            "-device", "scsi-hd,drive=usr,bus=scsi0.0,scsi-id=0,lun=0",
            "-drive", f"format=raw,file={images[2]},if=none,id=home",
            "-device", "scsi-hd,drive=home,bus=scsi0.0,scsi-id=1,lun=0",
            "-chardev", "stdio,id=serial0,signal=off",
            "-serial", "chardev:serial0",
        ]
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert process.stdin is not None and process.stdout is not None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        output = bytearray()
        deadline = time.monotonic() + 45
        command_sent = False
        success = False

        try:
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                for key, _ in selector.select(timeout=0.25):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        continue
                    output.extend(chunk)
                    if not command_sent and b"root@vibeos" in output:
                        process.stdin.write(b"cd / && /usr/bin/kernel-tests glibc_dynamic_linking\n")
                        process.stdin.flush()
                        command_sent = True
                    if b"[PASS] glibc_dynamic_linking" in output and b"0 failures" in output:
                        success = True
                        process.stdin.write(b"poweroff\n")
                        process.stdin.flush()
                        break
                if success:
                    process.wait(timeout=10)
                    break
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)

        if not success:
            fail("glibc dynamic system test did not pass", output)
        print("glibc dynamic system test passed")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
