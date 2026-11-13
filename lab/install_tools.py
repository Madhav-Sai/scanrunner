"""Build-time installation of exact official release binaries for the owned lab."""
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import urllib.request
import zipfile

ROOT = Path("/opt/bin")
ROOT.mkdir(parents=True, exist_ok=True)
identities = {}
for name, version in (("httpx", "1.12.0"), ("nuclei", "3.11.1")):
    filename = f"{name}_{version}_linux_amd64.zip"
    base = f"https://github.com/projectdiscovery/{name}/releases/download/v{version}/"
    with urllib.request.urlopen(base + filename, timeout=120) as response:
        raw = response.read(128 * 1024 * 1024)
    with urllib.request.urlopen(base + f"{name}_{version}_checksums.txt", timeout=60) as response:
        checksums = response.read().decode()
    expected = next(line.split()[0] for line in checksums.splitlines() if line.split()[-1].lstrip("*") == filename)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("Official release checksum mismatch")
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        member = archive.getinfo(name)
        if member.file_size > 256 * 1024 * 1024:
            raise ValueError("Binary exceeds size limit")
        binary = ROOT / name
        binary.write_bytes(archive.read(member))
        binary.chmod(0o755)
    identities[name] = {"version": version, "release_archive_sha256": expected,
                        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
commit = "711a07ada11bc6d4681264e7a5c003b5c03bb588"
with urllib.request.urlopen(f"https://github.com/testssl/testssl.sh/archive/{commit}.zip", timeout=120) as response:
    raw = response.read(128 * 1024 * 1024)
destination = Path("/opt/testssl")
destination.mkdir()
with zipfile.ZipFile(BytesIO(raw)) as archive:
    for member in archive.infolist():
        parts = Path(member.filename).parts[1:]
        target = destination.joinpath(*parts).resolve()
        if not target.is_relative_to(destination) or member.file_size > 128 * 1024 * 1024:
            raise ValueError("Unsafe source archive member")
        if member.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif parts:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(member))
            target.chmod(0o755 if member.external_attr >> 16 & 0o111 else 0o644)
os.symlink(destination / "testssl.sh", ROOT / "testssl.sh")
identities["testssl"] = {"version": "3.2.5", "commit": commit, "archive_sha256": hashlib.sha256(raw).hexdigest()}
Path("/opt/tool-identities.json").write_text(json.dumps(identities, indent=2))
