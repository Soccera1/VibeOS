#!/usr/bin/env python3
"""Exercise writable XFS images and native recovery without mounting host disks."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def main():
    exe = str(Path(sys.argv[1]).resolve())
    allocator = str(Path(sys.argv[2]).resolve())
    with tempfile.TemporaryDirectory(prefix='vibeos-xfs-write-') as temporary:
        root = Path(temporary)
        base, work = root / 'base.xfs', root / 'work.xfs'

        def run(mode, image=work, env=None, expected=0):
            result = subprocess.run([exe, str(image), mode], env=env, capture_output=True, text=True)
            if result.returncode != expected:
                raise RuntimeError(f'{mode}: exit {result.returncode}, expected {expected}\n{result.stdout}{result.stderr}')
            return result.stdout

        def copy(source=base, destination=work):
            subprocess.run(['cp', '--reflink=auto', '--sparse=always', str(source), str(destination)], check=True)

        def repair(image=work):
            result = subprocess.run(['xfs_repair', '-n', str(image)], capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(f'xfs_repair -n: {result.stdout}{result.stderr}')

        with base.open('wb') as image:
            image.truncate(384 * 1024 * 1024)
        subprocess.run(['mkfs.xfs', '-f', '-q', '-s', 'size=512',
                        '-m', 'crc=1,finobt=0,reflink=0,rmapbt=0,bigtime=0,inobtcount=0',
                        '-i', 'size=512,sparse=0,nrext64=0,exchange=0',
                        '-n', 'ftype=1,parent=0', str(base)], check=True)
        copy()
        for mode in ('basic', 'verify', 'stress', 'remove-stress', 'verify'):
            run(mode)
            repair()
            print(f'XFS {mode} and consistency checks passed', flush=True)
        for mode in ('grow', 'full'):
            copy()
            subprocess.run([allocator, str(work), mode], check=True)
            repair()
            subprocess.run([allocator, str(work), 'shrink'], check=True)
            repair()
        print('XFS allocation tree growth, shrink, and ENOSPC checks passed', flush=True)
        run('seed', base)
        copy()
        events = int(re.search(r'events=(\d+)', run('rename'))[1])
        repair()
        dirty = root / 'dirty.xfs'
        for cut in range(events):
            copy()
            run('rename', env=dict(os.environ, XFS_FAIL_AFTER=str(cut)), expected=99)
            if cut == events - 8:
                copy(work, dirty)
            run('recover')
            repair()
        print(f'XFS rename: {events} sector/flush interruption points passed', flush=True)
        for cut in range(events - 1):
            copy()
            run('rename', env=dict(os.environ, XFS_FAIL_AFTER=str(cut), XFS_FAIL_IO='1'), expected=98)
            run('recover')
            repair()
        print('XFS write/flush error propagation and recovery checks passed', flush=True)
        copy(dirty)
        recovery_events = int(re.search(r'events=(\d+)', run('recover'))[1])
        for cut in range(recovery_events):
            copy(dirty)
            run('recover', env=dict(os.environ, XFS_FAIL_AFTER=str(cut)), expected=99)
            run('recover')
            repair()
        print(f'XFS recovery: {recovery_events} interruption points passed', flush=True)
        copy()
        env = dict(os.environ, XFS_VOLATILE_CACHE='1')
        reordered_events = int(re.search(r'events=(\d+)', run('rename', env=env))[1])
        for cut in range(reordered_events):
            copy()
            run('rename', env=dict(env, XFS_FAIL_AFTER=str(cut)), expected=99)
            run('recover')
            repair()
        print(f'XFS volatile cache: {reordered_events} reordered persistence cuts passed', flush=True)
        subprocess.run([allocator, str(base), 'pad-log'], check=True)
        repair(base)
        for cut in range(reordered_events):
            copy()
            run('rename', env=dict(env, XFS_FAIL_AFTER=str(cut)), expected=99)
            run('recover')
            repair()
        print('XFS log wraparound with reordered persistence cuts passed', flush=True)


if __name__ == '__main__':
    main()
