#!/usr/bin/env python3
"""Black-box regression tests for the compiled C configurator."""
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'build/tools/kconfig').resolve())
fixture = '''mainmenu "Configuration test"
menu "Options"
config A
 bool "A"
 default y
config B
 bool "B"
 default n
config C
 bool "C"
 default y
 depends on !(A&&B) && (B||y)
config D
 bool "D"
 default y
 depends on B && A || C
config NUMBER
 int "Number"
 default 42
config HEX
 hex "Hex"
 default 0x10
config TEXT
 string "Text"
 default "hello"
endmenu
'''
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    (root/'Kconfig').write_text(fixture)
    def run(command, *args, input=None, ok=True):
        result = subprocess.run([binary, command, *args], cwd=root, input=input,
                                text=True, capture_output=True)
        assert (result.returncode == 0) == ok, result.stderr
        return result
    run('defconfig')
    default = (root/'.config').read_text()
    assert 'CONFIG_C=y' in default and 'CONFIG_D=y' in default
    run('savedefconfig')
    assert not any(line.startswith('CONFIG_') for line in (root/'defconfig').read_text().splitlines())
    (root/'.config').write_text('CONFIG_A=True\nCONFIG_B=y\nCONFIG_NUMBER=0b1111011\n'
                              'CONFIG_HEX=255\nCONFIG_TEXT="quoted \\"text\\" \\\\ path $HOME"\n')
    run('sync','--out-mk','nested/config.mk','--out-header','nested/autoconf.h')
    saved = (root/'.config').read_text()
    assert '# CONFIG_C is not set' in saved
    assert 'CONFIG_NUMBER=123' in saved and 'CONFIG_HEX=0xff' in saved
    assert 'quoted \\"text\\" \\\\ path $HOME' in saved
    assert '$$HOME' in (root/'nested/config.mk').read_text()
    run('olddefconfig')
    assert (root/'.config').read_text() == saved
    run('oldconfig', input='')  # Nothing new to prompt for.
    assert (root/'.config').read_text() == saved
    run('config', input='', ok=False)
    assert (root/'.config').read_text() == saved
    run('defconfig')
    run('config', input='n\ny\n\n\ninvalid\n-32\nchanged\n')
    saved = (root/'.config').read_text()
    assert '# CONFIG_A is not set' in saved and 'CONFIG_B=y' in saved
    assert 'CONFIG_NUMBER=42' in saved and 'CONFIG_HEX=-0x20' in saved
    assert 'CONFIG_TEXT="changed"' in saved
    run('savedefconfig')
    (root/'.config').write_bytes((root/'defconfig').read_bytes())
    run('olddefconfig')
    assert (root/'.config').read_text() == saved
    run('sync','--out-mk','config.mk','--out-header','autoconf.h')
    for raw, expected in [('1_234', '1234'), ('-0b100', '-4'), ('0o17', '15'),
                          ('-9223372036854775808', '-9223372036854775808'),
                          ('9223372036854775808', '42'), ('0b-1', '42'), ('012', '42')]:
        (root/'.config').write_text(f'CONFIG_NUMBER={raw}\n')
        run('olddefconfig')
        assert f'CONFIG_NUMBER={expected}\n' in (root/'.config').read_text()
    run('sync',ok=False)
    run('unknown',ok=False)
    run('--help')
    run('defconfig','--config','missing/subdir/config')
    assert (root/'missing/subdir/config').exists()
    for invalid in ('config bad-name\n', 'endmenu\n', 'bool "Outside"\n',
                    'config VALID\n unsupported value\n', 'config VALID\n boolean "Typo"\n'):
        (root/'Kconfig').write_text(invalid)
        run('defconfig',ok=False)
print('C configurator CLI tests passed')
