#!/usr/bin/env python3
"""Exercise the actual VT100 frontend through a PTY, with isolated outputs."""
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
import fcntl

BINARY = str(Path(sys.argv[1]).resolve())


class Session:
    def __init__(self, root, source):
        self.root = root
        (root / 'Kconfig').write_text(source)
        self.master, self.slave = pty.openpty()
        self.original = termios.tcgetattr(self.slave)
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
        self.process = subprocess.Popen(
            [BINARY, '--kconfig', str(root / 'Kconfig'), '--config', str(root / '.config'),
             '--out-mk', str(root / 'config.mk'), '--out-header', str(root / 'autoconf.h')],
            stdin=self.slave, stdout=self.slave, stderr=self.slave,
            env={**os.environ, 'TERM': 'vt100'})
        self.expect('q: quit')

    def expect(self, text):
        output = b''
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if select.select([self.master], [], [], .1)[0]:
                output += os.read(self.master, 65536)
                if text.encode() in output:
                    return
        raise AssertionError(f'Missing {text!r}: {output!r}')

    def send(self, keys, text):
        os.write(self.master, keys)
        self.expect(text)

    def finish(self, keys=b'q', status=0):
        if keys:
            os.write(self.master, keys)
        assert self.process.wait(timeout=5) == status
        assert termios.tcgetattr(self.slave) == self.original, 'Terminal not restored'
        os.close(self.master)
        os.close(self.slave)


SOURCE = '''mainmenu "Test configuration"
menu "Basic"
config ENABLE
 bool "Enable feature"
 default y
config CHILD
 bool "Dependent option"
 default y
 depends on ENABLE
config NUMBER
 int "Number"
 default 10
config TEXT
 string "Text"
 default "hello"
endmenu
'''

with tempfile.TemporaryDirectory(prefix='tconfig-test-') as directory:
    root = Path(directory)
    session = Session(root, SOURCE)
    session.send(b' ', '[modified]')
    session.send(b'\x1b[B ', 'Unavailable: ENABLE')
    session.send(b'\x1bOA ', 'Dependent option')
    session.send(b'jj\r', 'Ctrl-U clears')
    session.send(b'\x15bad\r', 'valid signed 64-bit number')
    session.send(b'\x1525\r', '[25]')
    session.send(b'j\r', 'Ctrl-U clears')
    session.send(b'\x15world!\x7f\r', '[world] Basic / Text')
    session.send(b'?', 'CONFIG_TEXT')
    session.send(b' ', 'q: quit')
    session.send(b's', 'Configuration saved.')
    saved = {name: (root / name).read_bytes() for name in ('.config', 'config.mk', 'autoconf.h')}
    assert b'CONFIG_ENABLE=y' in saved['.config']
    assert b'CONFIG_CHILD=y' in saved['.config']
    assert b'CONFIG_NUMBER=25' in saved['.config']
    assert b'CONFIG_TEXT="world"' in saved['.config']
    assert b'#define CONFIG_NUMBER 25' in saved['autoconf.h']
    session.send(b'k\r', 'Ctrl-U clears')
    session.send(b'\x1599\x1b', 'q: quit')
    session.finish()
    assert all((root / name).read_bytes() == data for name, data in saved.items())

    session = Session(root, SOURCE)
    session.send(b' q', 'Save before exit?')
    session.send(b'\x1b', 'q: quit')
    session.send(b'q', 'Save before exit?')
    session.finish(b'n')
    assert all((root / name).read_bytes() == data for name, data in saved.items())

    session = Session(root, SOURCE)
    session.send(b' q', 'Save before exit?')
    session.finish(b'y')
    assert b'# CONFIG_ENABLE is not set' in (root / '.config').read_bytes()

    session = Session(root, SOURCE)
    fcntl.ioctl(session.slave, termios.TIOCSWINSZ, struct.pack('HHHH', 6, 18, 0, 0))
    session.process.send_signal(signal.SIGWINCH)
    session.expect('Terminal too smal')
    session.process.send_signal(signal.SIGTERM)
    session.finish(b'', 128 + signal.SIGTERM)

    session = Session(root, 'mainmenu "Empty"\n')
    session.send(b'j ', 'No configurable options')
    session.finish()

    # Scrolling and wraparound with more options than fit on a VT100 screen.
    many = 'mainmenu "Long menu"\n' + ''.join(
        f'config ITEM_{i}\n bool "Item {i}"\n default n\n' for i in range(40))
    session = Session(root, many)
    session.send(b'k', 'Option 40/40')
    session.send(b'j', 'Option 1/40')
    session.process.send_signal(signal.SIGINT)
    session.finish(b'', 128 + signal.SIGINT)

    # Failed save keeps the editor open and dirty, allowing discard.
    (root / '.config').unlink()
    session = Session(root, SOURCE)
    (root / '.config').mkdir()
    session.send(b' s', 'Cannot write configuration outputs')
    session.send(b'q', 'Save before exit?')
    session.finish(b'n')

result = subprocess.run([BINARY, '--help'], capture_output=True)
assert result.returncode == 0 and b'--out-header' in result.stdout
result = subprocess.run([BINARY], input=b'', capture_output=True)
assert result.returncode != 0 and b'requires a VT100-compatible terminal' in result.stderr
print('tconfig PTY tests passed')
