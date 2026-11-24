"""Exercise capture lifecycle offline in PowerShell 5.1 and 7 when present."""
from pathlib import Path
import base64
import ctypes
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CampusCaptureTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Windows command-line parsing')
    def test_elevation_arguments_preserve_trailing_backslashes(self):
        script = str(ROOT / 'campus_capture.ps1').replace("'", "''")
        # Exercise the actual argument builder without launching anything.
        command = f". '{script}' -OutputDirectory 'D:\\'; " + (
            "foreach ($path in @('D:\\', 'D:\\capture folder\\', 'D:\\folder')) { "
            "$line = New-CampusElevationArguments -ScriptPath 'D:\\tool space\\capture.ps1' "
            "-Seconds 120 -Directory $path -NoBrowser -NoPause; "
            "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($line)) }"
        )
        encoded = base64.b64encode(command.encode('utf-16-le')).decode('ascii')
        shell32 = ctypes.WinDLL('shell32', use_last_error=True)
        shell32.CommandLineToArgvW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
        shell32.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        for name in ('powershell.exe', 'pwsh.exe'):
            shell = shutil.which(name)
            if not shell:
                continue
            with self.subTest(shell=shell):
                result = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                                        capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', errors='replace'))
                lines = result.stdout.decode('ascii').splitlines()
                self.assertEqual(len(lines), 3)
                for line, expected in zip(lines, ('D:\\', 'D:\\capture folder\\', 'D:\\folder')):
                    text = base64.b64decode(line).decode('utf-8')
                    count = ctypes.c_int()
                    pointer = shell32.CommandLineToArgvW('powershell.exe ' + text, ctypes.byref(count))
                    self.assertTrue(pointer)
                    try:
                        args = [pointer[n] for n in range(count.value)]
                    finally:
                        kernel32.LocalFree(pointer)
                    self.assertEqual(args[args.index('-OutputDirectory') + 1], expected)
                    self.assertEqual(args[-2:], ['-NoBrowser', '-NoPause'])
                    self.assertEqual(args[args.index('-File') + 1], 'D:\\tool space\\capture.ps1')

    def test_offline_lifecycle_in_available_powershells(self):
        shells = []
        for name in ('powershell.exe', 'pwsh.exe'):
            shell = shutil.which(name)
            if shell and shell not in shells:
                shells.append(shell)
        if not shells:
            self.skipTest('PowerShell unavailable')
        for shell in shells:
            with self.subTest(shell=shell), tempfile.TemporaryDirectory(prefix='campus-offline-') as temp:
                result = subprocess.run(
                    [shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                     '-File', str(ROOT / 'tests' / 'campus_capture_harness.ps1'),
                     '-WorkDirectory', temp],
                    capture_output=True, timeout=45,
                )
                output = (result.stdout + result.stderr).decode('utf-8', errors='replace')
                self.assertEqual(result.returncode, 0, output)
                self.assertIn('CAMPUS_OFFLINE_TESTS_OK', output)


if __name__ == '__main__':
    unittest.main()
