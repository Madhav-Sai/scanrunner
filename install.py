#!/usr/bin/env python3
"""Cross-platform installer for scanrunner."""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import stat
import subprocess
import sys
import sysconfig
from pathlib import Path

APP = "scanrunner"
SCRIPT = "scanrunner.py"
MARKER_START = "# >>> scanrunner completion >>>"
MARKER_END = "# <<< scanrunner completion <<<"

PROFILES = [
    "quick", "full", "full-fast", "web", "web-enum", "ssl-ciphers",
    "smb-audit", "rdp-audit", "udp", "vuln",
]
NXC_PROTOCOLS = ["smb", "rdp", "ldap", "winrm", "ssh", "ftp", "mssql", "wmi", "vnc", "nfs"]
NXC_QUERIES = ["os", "hostname", "smbv1", "smb-signing", "null-auth", "rdp-nla", "all"]
OPTIONS = [
    "-h", "--help", "-f", "--file", "-i", "--ip", "--split", "--profile",
    "--template", "--preset", "--exclude", "--exclude-file", "-nxc", "--nxc",
    "--nxc-query", "--yes", "--resume", "--skip-ping", "--no-color",a
    "--scope-file", "--retries", "--parallel", "-o", "--output",
    "--metadata-csv", "--html-report", "--list-templates", "--help-all",
    "--nmap", "--reports",
]


def info(message: str) -> None:
    print(f"\033[96m[*]\033[0m {message}" if sys.stdout.isatty() else f"[*] {message}")


def success(message: str) -> None:
    print(f"\033[92m[+]\033[0m {message}" if sys.stdout.isatty() else f"[+] {message}")


def warn(message: str) -> None:
    print(f"\033[93m[!]\033[0m {message}" if sys.stdout.isatty() else f"[!] {message}")


def fail(message: str) -> "NoReturn":
    print(f"\033[91m[x]\033[0m {message}" if sys.stdout.isatty() else f"[x] {message}", file=sys.stderr)
    raise SystemExit(1)


def project_script() -> Path:
    path = Path(__file__).resolve().parent / SCRIPT
    if not path.is_file():
        fail(f"{SCRIPT} was not found beside install.py")
    return path


def detect_os() -> str:
    name = platform.system().lower()
    if name == "darwin":
        return "macos"
    if name == "windows":
        return "windows"
    if name == "linux":
        return "linux"
    return name


def detect_shell(system: str, requested: str) -> str:
    if requested != "auto":
        return requested
    if system == "windows":
        return "powershell"
    shell = Path(os.environ.get("SHELL", "")).name.lower()
    if shell in {"zsh", "bash", "fish"}:
        return shell
    return "zsh" if system == "macos" else "bash"


def run(command: list[str]) -> None:
    try:
        subprocess.run(command, check=True)
    except FileNotFoundError:
        fail(f"Required command not found: {command[0]}")
    except subprocess.CalledProcessError as error:
        fail(f"Command failed with exit code {error.returncode}: {' '.join(command)}")


def make_executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def install_unix_launcher(source: Path, user_install: bool) -> Path:
    make_executable(source)
    destination = Path.home() / ".local/bin/scanrunner" if user_install else Path("/usr/local/bin/scanrunner")
    destination.parent.mkdir(parents=True, exist_ok=True) if user_install else None

    absolute_source = source.resolve()
    if destination.exists() or destination.is_symlink():
        try:
            if destination.is_symlink() and destination.resolve() == absolute_source:
                success(f"Launcher already installed: {destination}")
                return destination
        except OSError:
            pass

    if os.access(destination.parent, os.W_OK):
        destination.unlink(missing_ok=True)
        destination.symlink_to(absolute_source)
    else:
        info(f"Administrator permission is required to write {destination}")
        run(["sudo", "ln", "-sfn", str(absolute_source), str(destination)])

    success(f"Installed launcher: {destination} -> {absolute_source}")
    return destination


def windows_scripts_dir() -> Path:
    value = sysconfig.get_path("scripts", scheme="nt_user")
    return Path(value) if value else Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Programs" / "Python" / "Scripts"


def add_windows_user_path(directory: Path) -> None:
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE)
        try:
            current, value_type = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            current, value_type = "", winreg.REG_EXPAND_SZ
        entries = [entry for entry in current.split(";") if entry]
        normalized = {os.path.normcase(os.path.normpath(os.path.expandvars(entry))) for entry in entries}
        if os.path.normcase(os.path.normpath(str(directory))) not in normalized:
            entries.append(str(directory))
            winreg.SetValueEx(key, "Path", 0, value_type, ";".join(entries))
            success(f"Added to user PATH: {directory}")
            warn("Open a new terminal before running scanrunner.")
        winreg.CloseKey(key)
    except Exception as error:
        warn(f"Could not update Windows PATH automatically: {error}")
        warn(f"Add this directory to PATH manually: {directory}")


def install_windows_launcher(source: Path) -> Path:
    destination_dir = windows_scripts_dir()
    destination_dir.mkdir(parents=True, exist_ok=True)
    installed_script = destination_dir / SCRIPT
    launcher = destination_dir / "scanrunner.cmd"
    shutil.copy2(source, installed_script)
    launcher.write_text(f'@echo off\r\n"{sys.executable}" "{installed_script}" %*\r\n', encoding="utf-8")
    add_windows_user_path(destination_dir)
    success(f"Installed launcher: {launcher}")
    return launcher


def zsh_completion() -> str:
    options = " ".join(OPTIONS)
    profiles = " ".join(PROFILES)
    protocols = " ".join(NXC_PROTOCOLS)
    queries = " ".join(NXC_QUERIES)
    return f'''#compdef scanrunner

_scanrunner() {{
  local state
  _arguments -C \\
    '(-f --file)'{{-f,--file}}'[target file]:target file:_files' \\
    '(-i --ip)'{{-i,--ip}}'[single IP, hostname, URL, or CIDR]:target:' \\
    '--split[split target file]:parts:' \\
    '--profile[use Nmap profile]:profile:({profiles})' \\
    '--template[use Nmap template]:template:({profiles})' \\
    '--preset[use Nmap preset]:preset:({profiles})' \\
    '(-nxc --nxc)'{{-nxc,--nxc}}'[run NetExec protocol]:protocol:({protocols})' \\
    '--nxc-query[NXC result fields]:query:({queries})' \\
    '(-o --output)'{{-o,--output}}'[output directory]:directory:_directories' \\
    '--exclude[exclude target or CIDR]:target:' \\
    '--exclude-file[Nmap exclusion file]:file:_files' \\
    '--scope-file[authorized scope file]:file:_files' \\
    '--metadata-csv[asset metadata CSV]:file:_files' \\
    '--parallel[parallel workers]:workers:' \\
    '--retries[retry count]:count:' \\
    '--yes[non-interactive mode]' '--resume[skip completed scans]' \\
    '--skip-ping[skip wrapper ping]' '--no-color[disable colors]' \\
    '--html-report[create HTML report]' '--list-templates[list templates]' \\
    '--help-all[show complete help]' '--nmap[Nmap help]' '--reports[reporting help]' \\
    '(-h --help)'{{-h,--help}}'[show help]' \\
    '*:Nmap argument or target:'
}}

_scanrunner "$@"
'''


def bash_completion() -> str:
    return f'''_scanrunner_completion() {{
    local cur prev
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    case "$prev" in
        --profile|--template|--preset) COMPREPLY=( $(compgen -W "{' '.join(PROFILES)}" -- "$cur") ); return ;;
        -nxc|--nxc) COMPREPLY=( $(compgen -W "{' '.join(NXC_PROTOCOLS)}" -- "$cur") ); return ;;
        --nxc-query) COMPREPLY=( $(compgen -W "{' '.join(NXC_QUERIES)}" -- "$cur") ); return ;;
        -f|--file|--exclude-file|--scope-file|--metadata-csv) COMPREPLY=( $(compgen -f -- "$cur") ); return ;;
        -o|--output) COMPREPLY=( $(compgen -d -- "$cur") ); return ;;
    esac
    COMPREPLY=( $(compgen -W "{' '.join(OPTIONS)}" -- "$cur") )
}}
complete -F _scanrunner_completion scanrunner
'''


def fish_completion() -> str:
    lines = ["complete -c scanrunner -f"]
    for option in OPTIONS:
        if option.startswith("--"):
            lines.append(f"complete -c scanrunner -l {option[2:]}")
        elif option.startswith("-") and len(option) == 2:
            lines.append(f"complete -c scanrunner -s {option[1:]}")
    lines.extend([
        f"complete -c scanrunner -n '__fish_seen_subcommand_from --profile --template --preset' -a '{' '.join(PROFILES)}'",
        f"complete -c scanrunner -n '__fish_seen_subcommand_from -nxc --nxc' -a '{' '.join(NXC_PROTOCOLS)}'",
    ])
    return "\n".join(lines) + "\n"


def replace_managed_block(path: Path, content: str) -> None:
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    block = f"{MARKER_START}\n{content.rstrip()}\n{MARKER_END}"
    if MARKER_START in existing and MARKER_END in existing:
        before = existing.split(MARKER_START, 1)[0].rstrip()
        after = existing.split(MARKER_END, 1)[1].lstrip()
        updated = f"{before}\n\n{block}\n"
        if after:
            updated += f"\n{after}"
    else:
        separator = "\n\n" if existing.strip() else ""
        updated = existing.rstrip() + separator + block + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(updated, encoding="utf-8")


def install_completion(shell: str, system: str) -> None:
    home = Path.home()
    if shell == "zsh":
        completion_dir = home / ".zsh/completions"
        completion_dir.mkdir(parents=True, exist_ok=True)
        completion_file = completion_dir / "_scanrunner"
        completion_file.write_text(zsh_completion(), encoding="utf-8")
        replace_managed_block(home / ".zshrc", "fpath=(~/.zsh/completions $fpath)\nautoload -Uz compinit && compinit")
        success(f"Installed Zsh completion: {completion_file}")
    elif shell == "bash":
        completion_dir = home / ".local/share/bash-completion/completions"
        completion_dir.mkdir(parents=True, exist_ok=True)
        completion_file = completion_dir / "scanrunner"
        completion_file.write_text(bash_completion(), encoding="utf-8")
        success(f"Installed Bash completion: {completion_file}")
        if system == "macos":
            replace_managed_block(home / ".bash_profile", f"source {completion_file}")
    elif shell == "fish":
        completion_file = home / ".config/fish/completions/scanrunner.fish"
        completion_file.parent.mkdir(parents=True, exist_ok=True)
        completion_file.write_text(fish_completion(), encoding="utf-8")
        success(f"Installed Fish completion: {completion_file}")
    elif shell == "powershell":
        completion_file = home / "Documents/PowerShell/scanrunner-completion.ps1"
        completion_file.parent.mkdir(parents=True, exist_ok=True)
        words = ",".join(repr(item) for item in OPTIONS + PROFILES + NXC_PROTOCOLS + NXC_QUERIES)
        completion_file.write_text(
            "Register-ArgumentCompleter -Native -CommandName scanrunner -ScriptBlock {\n"
            "  param($wordToComplete, $commandAst, $cursorPosition)\n"
            f"  @({words}) | Where-Object {{ $_ -like \"$wordToComplete*\" }} | "
            "ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }\n"
            "}\n", encoding="utf-8")
        profile = home / "Documents/PowerShell/Microsoft.PowerShell_profile.ps1"
        replace_managed_block(profile, f'. "{completion_file}"')
        success(f"Installed PowerShell completion: {completion_file}")
    else:
        warn(f"Automatic completion is not available for shell: {shell}")


def dependency_report(system: str) -> None:
    if shutil.which("nmap"):
        success("Nmap detected")
    else:
        warn("Nmap was not found in PATH. Install it before running Nmap scans.")
        if system == "linux":
            print("    Debian/Kali/Ubuntu: sudo apt install nmap")
        elif system == "macos":
            print("    Homebrew: brew install nmap")
        elif system == "windows":
            print("    Install Nmap from the official Windows installer and enable PATH support.")

    if shutil.which("nxc") or shutil.which("netexec"):
        success("NetExec detected")
    else:
        warn("NetExec was not found. It is optional and only required for -nxc mode.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install scanrunner and shell completion")
    location = parser.add_mutually_exclusive_group()
    location.add_argument("--user", action="store_true", help="install launcher under the current user")
    location.add_argument("--system", action="store_true", help="install launcher system-wide (Unix default)")
    parser.add_argument("--shell", choices=("auto", "zsh", "bash", "fish", "powershell", "none"), default="auto")
    parser.add_argument("--no-completion", action="store_true", help="do not install shell completion")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    source = project_script()
    system = detect_os()
    shell = detect_shell(system, args.shell)

    info(f"Operating system: {platform.system()} {platform.release()} ({platform.machine()})")
    info(f"Python: {platform.python_version()}")
    info(f"Shell: {shell}")

    if system in {"linux", "macos"}:
        user_install = args.user
        launcher = install_unix_launcher(source, user_install)
        if user_install and str(launcher.parent) not in os.environ.get("PATH", "").split(os.pathsep):
            warn(f"{launcher.parent} is not currently in PATH. Add it to your shell configuration.")
    elif system == "windows":
        if args.system:
            warn("Windows uses a per-user launcher; --system is ignored.")
        install_windows_launcher(source)
    else:
        fail(f"Unsupported operating system: {platform.system()}")

    if not args.no_completion and shell != "none":
        install_completion(shell, system)

    dependency_report(system)
    print()
    success("scanrunner installation completed")
    if shell in {"zsh", "bash", "fish"}:
        print(f"    Reload your shell: exec {shell}")
    elif shell == "powershell":
        print("    Open a new PowerShell window.")
    print("    Verify installation: scanrunner -h")


if __name__ == "__main__":
    main()
