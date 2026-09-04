#!/usr/bin/env python3
"""Boot the real kernel twice against a disposable writable XFS image."""
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from make_xfs_image import build


def initramfs(source, binary):
    data = source.read_bytes()
    entries = {}
    pos = 0
    while pos + 110 <= len(data):
        if data[pos:pos+6] not in (b'070701', b'070702'):
            raise ValueError('expected an uncompressed newc initramfs')
        fields = [int(data[pos+6+i*8:pos+14+i*8], 16) for i in range(13)]
        size, namesize = fields[6], fields[11]
        name = data[pos+110:pos+110+namesize-1].decode()
        pos = (pos+110+namesize+3) & ~3
        payload = data[pos:pos+size]
        pos = (pos+size+3) & ~3
        if name == 'TRAILER!!!':
            break
        entries[name.removeprefix('./')] = (fields[1], fields[2], fields[3], payload)
    entries['bin/xfs-kernel-test'] = (stat.S_IFREG | 0o755, 0, 0, binary.read_bytes())
    entries['init'] = (stat.S_IFREG | 0o755, 0, 0, b'exec /bin/xfs-kernel-test\n')
    entries['TRAILER!!!'] = (0, 0, 0, b'')
    output = bytearray()
    for ino, (name, (mode, uid, gid, payload)) in enumerate(entries.items(), 1):
        fields = [ino, mode, uid, gid, 1, 0, len(payload), 0, 0, 0, 0, len(name.encode())+1, 0]
        output += b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + name.encode() + b'\0'
        output += b'\0' * (-len(output) % 4)
        output += payload
        output += b'\0' * (-len(output) % 4)
    return output


def main():
    kernel, source, usr, binary = map(lambda p: Path(p).resolve(), sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix='vibeos-xfs-kernel-') as temporary:
        root = Path(temporary)
        (root / 'root').mkdir()
        disk, cpio, iso = root / 'test.xfs', root / 'init.cpio', root / 'test.iso'
        build(root / 'root', disk, writable=True)
        cpio.write_bytes(initramfs(source, binary))
        subprocess.run(['tools/make_iso.sh', str(iso), str(kernel), str(cpio), str(usr)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        command = ['qemu-system-x86_64', '-machine', 'q35,accel=tcg', '-cpu', 'max', '-m', '1G',
                   '-display', 'none', '-device', 'virtio-vga', '-cdrom', str(iso),
                   '-device', 'virtio-scsi-pci-transitional,id=scsi0',
                   '-drive', f'file={disk},format=raw,if=none,id=test',
                   '-device', 'scsi-hd,drive=test,bus=scsi0.0,scsi-id=0,lun=0',
                   '-serial', 'stdio', '-no-reboot']
        for marker in ('XFS_KERNEL_WRITE_PASS', 'XFS_KERNEL_REMOUNT_PASS'):
            result = subprocess.run(command, capture_output=True, text=True, timeout=90)
            if result.returncode or marker not in result.stdout or 'XFS_KERNEL_WRITE_FAIL' in result.stdout:
                raise RuntimeError(f'QEMU XFS check failed:\n{result.stdout}{result.stderr}')
            repair = subprocess.run(['xfs_repair', '-n', str(disk)], capture_output=True, text=True)
            if repair.returncode:
                raise RuntimeError(repair.stdout + repair.stderr)
            print(f'{binary.name}: {marker}; xfs_repair -n passed', flush=True)


if __name__ == '__main__':
    main()
