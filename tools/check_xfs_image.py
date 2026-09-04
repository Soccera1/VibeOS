#!/usr/bin/env python3
"""Check rootless XFS population and preservation of an existing output on error."""
from pathlib import Path
import subprocess
import tempfile

from make_xfs_image import build


with tempfile.TemporaryDirectory(prefix='vibeos-xfs-builder-') as tmp:
    directory = Path(tmp)
    root = directory / 'source tree with spaces'
    root.mkdir()
    (root / 'lib').mkdir()
    payload = root / 'gnu::aligned.3attr'
    payload.write_bytes(b'prototype payload\n')
    payload.chmod(0o640)
    (root / 'lib' / 'link').symlink_to('../gnu::aligned.3attr')
    image = directory / 'usr.xfs'
    build(root, image)
    assert image.stat().st_size >= 384 * 1024 * 1024
    result = subprocess.run(['xfs_db', '-r', '-c', 'sb 0', '-c', 'p magicnum',
                             '-c', 'path /gnu::aligned.3attr', '-c', 'p core.mode core.size',
                             '-c', 'path /lib/link', '-c', 'p core.mode', str(image)],
                            check=True, capture_output=True, text=True).stdout
    assert 'magicnum = 0x58465342' in result, result
    assert 'core.mode = 0100640' in result and 'core.size = 18' in result, result
    assert 'core.mode = 0120777' in result, result
    before = image.stat()
    (root / 'invalid name').touch()
    try:
        build(root, image)
    except ValueError as error:
        assert 'prototype token' in str(error), error
    else:
        raise AssertionError('unrepresentable filename accepted')
    after = image.stat()
    assert (before.st_ino, before.st_size, before.st_mtime_ns) == (after.st_ino, after.st_size, after.st_mtime_ns)
    assert list(directory.glob('usr.xfs.*')) == []
print('XFS image builder checks passed')
