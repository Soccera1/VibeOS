#!/usr/bin/env python3
"""Populate a clean XFS image from a directory, without mounts or root access."""

import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


def token(value: str) -> str:
    # mkfs prototypes have no quoting mechanism; a leading ':' begins a comment and '$'
    # ends a directory. Fail explicitly rather than silently misbuilding a tree.
    if not value or value.startswith((':', '$')) or any(c.isspace() for c in value):
        raise ValueError(f"cannot represent XFS prototype token: {value!r}")
    return value


def build(root: Path, output: Path) -> None:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"not a directory: {root}")
    output = output.absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    # Numeric source aliases also support host source paths containing spaces.
    with tempfile.TemporaryDirectory(prefix="vibeos-xfs-", dir="/tmp") as tmp:
        work = Path(tmp)
        lines = ["boot", "0 0"]
        data_bytes = 0
        entries = 0

        def visit(path: Path, name: str = "") -> None:
            nonlocal data_bytes, entries
            st = path.lstat()
            entries += 1
            mode = st.st_mode
            if stat.S_ISDIR(mode):
                kind = 'd'
            elif stat.S_ISREG(mode):
                kind = '-'
            elif stat.S_ISLNK(mode):
                kind = 'l'
            else:
                raise ValueError(f"unsupported file type in /usr tree: {path}")
            if mode & stat.S_ISVTX:
                raise ValueError(f"sticky mode is not representable by mkfs.xfs prototypes: {path}")
            perms = kind + ('u' if mode & stat.S_ISUID else '-') + ('g' if mode & stat.S_ISGID else '-')
            fields = ([token(name)] if name else []) + [f"{perms}{mode & 0o777:03o}", str(st.st_uid), str(st.st_gid)]
            if kind == '-':
                alias = work / str(entries)
                alias.symlink_to(path)
                fields.append(str(alias))
                data_bytes += ((st.st_size + 4095) // 4096) * 4096
            elif kind == 'l':
                fields.append(token(os.readlink(path)))
                data_bytes += 4096
            else:
                data_bytes += 4096
            lines.append(' '.join(fields))
            if kind == 'd':
                for child in sorted(path.iterdir()):
                    visit(child, child.name)
                lines.append('$')

        visit(root)
        proto = work / 'prototype'
        proto.write_text('\n'.join(lines) + '\n')
        # XFS requires >=300 MiB; allow a 64 MiB internal log, inode/block
        # metadata, and headroom without an unbounded format/retry loop.
        mib = 1024 * 1024
        size = max(384 * mib, data_bytes + data_bytes // 10 + entries * 2048 + 128 * mib)
        size = ((size + mib - 1) // mib) * mib
        # Publish only a successfully populated image, on the destination FS.
        fd, temporary = tempfile.mkstemp(prefix=output.name + '.', dir=output.parent)
        try:
            with os.fdopen(fd, 'wb') as image:
                image.truncate(size)
            subprocess.run(['mkfs.xfs', '-f', '-q', '-b', 'size=4096',
                            '-i', 'size=512', '-l', 'size=64m',
                            '-m', 'crc=1,reflink=0', '-L', 'VIBEUSR',
                            '-p', str(proto), temporary], check=True)
            os.chmod(temporary, 0o644)
            os.replace(temporary, output)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: make_xfs_image.py <root-directory> <output.xfs>')
    try:
        build(Path(sys.argv[1]), Path(sys.argv[2]))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f'XFS image build failed: {error}')
