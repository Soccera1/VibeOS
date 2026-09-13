#!/usr/bin/env python3
"""Exercise tool selection and generated wrappers without installed cross tools."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools/musl_toolchain.sh'


class ToolchainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.bin = self.directory / 'bin'
        self.bin.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith('MUSL_')}
        self.env.update(PATH=str(self.bin), LOG=str(self.directory / 'log'))
        for name in ('bash', 'dirname', 'mkdir', 'cat', 'chmod', 'cksum'):
            (self.bin / name).symlink_to(shutil.which(name))

    def fake(self, name):
        path = self.bin / name
        path.write_text('#!' + shutil.which('python3') + '\n'
                        'import json, os, sys\n'
                        'with open(os.environ["LOG"], "w") as f:\n'
                        '    json.dump([os.path.basename(sys.argv[0]), *sys.argv[1:]], f)\n')
        path.chmod(0o755)
        return path

    def run_tool(self, *args, success=True):
        result = subprocess.run([str(TOOL), *args], env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode == 0, success, result.stderr)
        return result

    def logged(self):
        return json.loads(Path(self.env['LOG']).read_text())

    def wrapper(self, kind='cc', profile='standard'):
        path = self.directory / 'compiler wrapper'
        result = subprocess.run(['bash', '-c',
                                 'source "$1"; musl_write_wrapper "$2" "$3" "$4"',
                                 'test', str(TOOL), str(path), kind, profile],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return path

    def test_default_zig(self):
        self.fake('zig')
        self.fake('musl-gcc')
        self.run_tool('cc', 'hello.c')
        self.assertEqual(self.logged(), ['zig', 'cc', '-target', 'x86_64-linux-musl', 'hello.c'])
        self.run_tool('c++', 'hello.cc')
        self.assertEqual(self.logged()[1], 'c++')
        self.run_tool('ar', 'rc', 'test.a')
        self.assertEqual(self.logged(), ['zig', 'ar', 'rc', 'test.a'])

    def test_fallbacks_without_zig(self):
        for compiler in ('gcc-musl', 'musl-gcc', 'x86_64-linux-musl-gcc'):
            self.fake(compiler)
            self.run_tool('cc', 'hello.c')
            self.assertEqual(self.logged(), [compiler, 'hello.c'])

    def test_explicit_command_overrides_zig_and_preserves_arguments(self):
        self.fake('zig')
        self.fake('custom-clang')
        self.env['MUSL_CC'] = 'custom-clang --target=x86_64-linux-musl --sysroot=/sdk'
        args = ['a b.c', '-Wl,--gc-sections,-Map,out.map', '-static-libgcc', '-fuse-ld=bfd', '$(touch nope)']
        path = self.wrapper()
        subprocess.run([str(path), *args], env=self.env, check=True)
        self.assertEqual(self.logged(), ['custom-clang', '--target=x86_64-linux-musl', '--sysroot=/sdk', *args])

    def test_executable_path_with_spaces(self):
        compiler = self.fake('custom compiler')
        self.env['MUSL_CC'] = str(compiler)
        self.run_tool('cc', 'a b.c')
        self.assertEqual(self.logged(), ['custom compiler', 'a b.c'])

    def test_custom_archivers_and_cxx(self):
        for name in ('musl-gcc', 'sdk-ar', 'sdk-ranlib', 'sdk-c++'):
            self.fake(name)
        self.env.update(MUSL_AR='sdk-ar', MUSL_RANLIB='sdk-ranlib', MUSL_CXX='sdk-c++')
        for kind, name in [('ar', 'sdk-ar'), ('ranlib', 'sdk-ranlib'), ('c++', 'sdk-c++')]:
            self.run_tool(kind, 'file')
            self.assertEqual(self.logged(), [name, 'file'])
        subprocess.run([str(self.wrapper('c++')), '-static', 'test.cc'], env=self.env, check=True)
        self.assertEqual(self.logged(), ['sdk-c++', '-static', 'test.cc'])

    def test_missing_cxx_never_uses_host_gxx(self):
        self.fake('musl-gcc')
        self.fake('g++')
        result = self.run_tool('c++', success=False)
        self.assertIn('MUSL_CXX', result.stderr)

    def test_cross_cxx_inference(self):
        self.fake('x86_64-linux-musl-gcc')
        self.fake('x86_64-linux-musl-g++')
        self.run_tool('c++', '-static')
        self.assertEqual(self.logged(), ['x86_64-linux-musl-g++', '-static'])

    def test_missing_compiler(self):
        result = self.run_tool('cc', success=False)
        self.assertIn('MUSL_CC', result.stderr)
        self.fake('zig')
        self.env['MUSL_CC'] = 'missing-compiler'
        self.run_tool('cc', success=False)

    def test_zig_filter_retains_supported_linker_flags(self):
        self.fake('zig')
        path = self.wrapper()
        subprocess.run([str(path), '-fuse-ld=bfd', '-Wl,--gc-sections,-Map,out.map,-z,now', 'test.c'],
                       env=self.env, check=True)
        self.assertEqual(self.logged(), ['zig', 'cc', '-target', 'x86_64-linux-musl',
                                        '-Wl,--gc-sections,-z,now', 'test.c'])

    def test_cached_build_invalidates_only_on_tool_change(self):
        self.fake('musl-gcc')
        self.fake('alternate-musl-gcc')
        self.fake('make')
        (self.bin / 'rm').symlink_to(shutil.which('rm'))
        source = self.directory / 'source'
        source.mkdir()
        (source / 'Makefile').touch()
        cache = source / 'build-musl'
        command = ['bash', '-c',
                   'source "$1"; musl_prepare_cached_build "$2" "$3"; '
                   'musl_fingerprint > "$2/.musl-toolchain"',
                   'test', str(TOOL), str(cache), str(source)]
        subprocess.run(command, env=self.env, check=True)
        sentinel = cache / 'old-library.a'
        sentinel.touch()
        subprocess.run(command, env=self.env, check=True)
        self.assertTrue(sentinel.exists())
        self.env['MUSL_CC'] = 'alternate-musl-gcc'
        subprocess.run(command, env=self.env, check=True)
        self.assertFalse(sentinel.exists())
        self.assertEqual(self.logged(), ['make', '-C', str(source), 'distclean'])

    def test_zig_terminal_and_plain_profiles(self):
        self.fake('zig')
        args = ['-Wl,--gc-sections', '-Wl,-z,now', 'test.c']
        for profile, expected in [('terminal', args[1:]), ('plain', args)]:
            subprocess.run([str(self.wrapper(profile=profile)), *args], env=self.env, check=True)
            self.assertEqual(self.logged()[4:], expected)


if __name__ == '__main__':
    unittest.main()
