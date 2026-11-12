"""Child-process fixture isolation. Loaded only via the workflow test PYTHONPATH.

Never use real scanners, DNS, shells, or graphical terminals in these tests.
"""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys

_popen = subprocess.Popen
_tools = {name: str(Path(os.environ["FAKE_TOOL_DIR"]) / (name + ".py"))
          for name in ("nmap", "ping", "nxc")}


def _which(name, *args, **kwargs):
    return _tools.get(name)


def _spawn(args, *positional, **kwargs):
    if isinstance(args, (str, bytes)) or kwargs.get("shell"):
        raise OSError("Shells are disabled in offline workflow tests")
    command = list(args)
    name = Path(str(command[0])).name
    if name in _tools:
        command = [sys.executable, _tools[name], *command[1:]]
    elif str(command[0]) in _tools.values():
        command = [sys.executable, *command]
    elif os.path.normcase(os.path.abspath(command[0])) != os.path.normcase(sys.executable):
        raise OSError("Non-fixture executable blocked in offline workflow tests")
    return _popen(command, *positional, **kwargs)


def _no_dns(*args, **kwargs):
    raise socket.gaierror("DNS disabled in offline workflow tests")


shutil.which = _which
subprocess.Popen = _spawn
socket.getaddrinfo = _no_dns
