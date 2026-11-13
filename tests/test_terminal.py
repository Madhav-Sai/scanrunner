"""Terminal mode and real POSIX PTY regressions for live scanner output."""
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock

from test_roadmap import backend


class TerminalModeTests(unittest.TestCase):
    def test_scan_key_mode_preserves_output_flags_and_keeps_control_bytes_readable(self):
        terminal = mock.Mock()
        terminal.BRKINT, terminal.ICRNL, terminal.INPCK, terminal.ISTRIP, terminal.IXON = 1, 2, 4, 8, 16
        terminal.CSIZE, terminal.PARENB, terminal.CS8 = 32, 64, 128
        terminal.ECHO, terminal.ICANON, terminal.IEXTEN, terminal.ISIG = 256, 512, 1024, 2048
        terminal.VMIN, terminal.VTIME = 0, 1
        terminal.TCSADRAIN = 1
        mode = [31, 0x1234, 96, 3840, 0, 0, [0, 1]]
        terminal.tcgetattr.return_value = mode
        with mock.patch.object(backend, "termios", terminal):
            backend.enable_scan_keys(7)
        active = terminal.tcsetattr.call_args.args[2]
        self.assertEqual(active[1], 0x1234)
        self.assertEqual(active[0], 0)
        self.assertEqual(active[3], 0)
        self.assertEqual(active[6], [1, 0])

    @unittest.skipUnless(os.name == "posix", "Real PTY output processing applies to POSIX terminals")
    def test_live_capture_starts_each_line_at_column_zero_and_retains_original_bytes(self):
        import pty
        import select
        import termios
        master, slave = pty.openpty()
        stdin = os.fdopen(os.dup(slave), "r")
        stdout = os.fdopen(os.dup(slave), "w", buffering=1)
        displayed = bytearray()
        stop = threading.Event()
        def read_terminal():
            while not stop.is_set():
                ready, _, _ = select.select([master], [], [], 0.05)
                if ready:
                    try:
                        displayed.extend(os.read(master, 65536))
                    except OSError:
                        break
        reader = threading.Thread(target=read_terminal, daemon=True)
        reader.start()
        try:
            mode = termios.tcgetattr(slave)
            mode[1] |= termios.OPOST | termios.ONLCR
            termios.tcsetattr(slave, termios.TCSANOW, mode)
            saved = termios.tcgetattr(slave)
            with tempfile.TemporaryDirectory() as temporary, mock.patch("sys.stdin", stdin), mock.patch("sys.stdout", stdout), \
                    mock.patch.object(backend, "_original_term_settings", None):
                backend._save_terminal()
                code, state = backend.capture_process([sys.executable, "-c",
                    "import time; time.sleep(.2); print('PORT STATE', flush=True); print('22/tcp open', flush=True)"], temporary, timeout=10, live=True)
                self.assertEqual((code, state), (0, "Exited"))
                self.assertEqual((Path(temporary) / "stdout.bin").read_bytes(), b"PORT STATE\n22/tcp open\n")
                restored = termios.tcgetattr(slave)
                # macOS may set PENDIN when canonical input resumes. Compare
                # user-controlled settings while excluding that kernel marker.
                restored[3] &= ~getattr(termios, "PENDIN", 0)
                saved[3] &= ~getattr(termios, "PENDIN", 0)
                self.assertEqual(restored, saved)
            stop.wait(0.1)
            self.assertIn(b"PORT STATE\r\n22/tcp open\r\n", displayed)
        finally:
            stop.set()
            reader.join(timeout=2)
            stdin.close()
            stdout.close()
            os.close(slave)
            os.close(master)
