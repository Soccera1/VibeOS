#!/usr/bin/env python3
"""Test dumb-terminal commands and generated outputs without touching .config."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

BINARY = str(Path(sys.argv[1]).resolve())
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
SOURCE += ''.join(f'config EXTRA{i}\n bool "Extra {i}"\n default n\n' for i in range(12))

with tempfile.TemporaryDirectory(prefix='dconfig-test-') as directory:
    root = Path(directory)
    (root / 'Kconfig').write_text(SOURCE)
    outputs = [root / name for name in ('.config', 'config.mk', 'autoconf.h')]

    def run(commands, header=None):
        result = subprocess.run(
            [BINARY, '--kconfig', str(root / 'Kconfig'), '--config', str(outputs[0]),
             '--out-mk', str(outputs[1]), '--out-header', str(header or outputs[2])],
            input=commands, text=True, capture_output=True, timeout=5,
            env={**os.environ, 'TERM': 'dumb'})
        assert result.returncode == 0, result.stderr
        assert all(c == '\n' or 32 <= ord(c) < 127 for c in result.stdout), result.stdout
        return result.stdout

    text = run('h 2\n1\nn\n2\n1\ny\n3\nbad\n3\n25\n4\n world \nn\np\ns\nq\n')
    for expected in ('CONFIG_CHILD', 'Depends on: ENABLE', 'Unavailable: ENABLE',
                     'valid signed 64-bit number', 'page 2/2', 'Configuration saved.'):
        assert expected in text, (expected, text)
    config = outputs[0].read_text()
    for expected in ('CONFIG_ENABLE=y', 'CONFIG_CHILD=y', 'CONFIG_NUMBER=25', 'CONFIG_TEXT=" world "'):
        assert expected in config, config
    assert '#define CONFIG_NUMBER 25' in outputs[2].read_text()
    saved = [p.read_bytes() for p in outputs]
    run('3\n99\nq\n\nq\nn\n')
    assert saved == [p.read_bytes() for p in outputs]
    run('3\n99\n')  # EOF must not save or hang.
    assert saved == [p.read_bytes() for p in outputs]
    run('4\n""\nq\ny\n')
    assert 'CONFIG_TEXT=""' in outputs[0].read_text()
    run('s\nq\n')  # Empty strings must also survive loading and saving again.
    assert 'CONFIG_TEXT=""' in outputs[0].read_text()
    text = run('0\n999\nh nonsense\n1\nmaybe\nq\n')
    assert 'Enter an option number' in text and 'Enter y or n.' in text
    text = run('s\nq\n', header=root)  # A directory cannot be an output file.
    assert 'Cannot write configuration outputs' in text
    text = run('4\nhello\x1b[2J\nl\nq\nn\n')
    assert 'hello?[2J' in text
    (root / 'Kconfig').write_text('mainmenu "Empty"\n')
    assert 'page 1/1' in run('n\np\nq\n')

print('dconfig tests passed')
