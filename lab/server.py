"""Start a deliberately configured, isolated Samba lab target."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def main():
    protocol = os.environ["MIN_PROTOCOL"]
    signing = os.environ["SIGNING"]
    if protocol not in {"NT1", "SMB2_02"} or signing not in {"auto", "mandatory"}:
        raise ValueError("Unrecognized lab policy")
    config = Path("/etc/samba/smb.conf")
    config.write_text(f"""[global]
server role = standalone server
workgroup = SRLAB
netbios name = SRLAB
security = user
map to guest = Never
server min protocol = {protocol}
server max protocol = SMB3
server signing = {signing}
smb ports = 445
disable netbios = yes
load printers = no
printing = bsd
printcap name = /dev/null
log level = 1
""", encoding="utf-8")
    proof_directory = Path("/proof")
    proof_directory.mkdir(parents=True, exist_ok=True)
    if any(proof_directory.iterdir()):
        raise FileExistsError("Choose a fresh lab evidence directory to preserve earlier proof")
    shutil.copyfile(config, proof_directory / "smb.conf")
    settings = {}
    for parameter in ("server min protocol", "server max protocol", "server signing"):
        result = subprocess.run(["testparm", "-s", "--parameter-name=" + parameter, str(config)],
                                capture_output=True, text=True, check=True)
        settings[parameter] = result.stdout.strip()
    executable = Path(shutil.which("smbd"))
    argv = [str(executable), "--foreground", "--no-process-group", "--debug-stdout", "--configfile=" + str(config)]
    proof = {"profile": os.environ["LAB_PROFILE"], "effective_settings": settings,
             "configured_smbv1": protocol == "NT1", "configured_signing_required": signing == "mandatory",
             "smbd_version": subprocess.check_output([str(executable), "--version"], text=True).strip(),
             "binary_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
             "config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(), "argv": argv,
             "captured_at": datetime.now(timezone.utc).isoformat()}
    (proof_directory / "server.json").write_text(json.dumps(proof, indent=2), encoding="utf-8")
    if settings["server min protocol"] != protocol:
        raise RuntimeError("Samba did not accept the requested minimum protocol")
    required_values = {"mandatory", "required", "true", "yes"}
    optional_values = {"auto", "if_required", "default", "disabled", "false", "no"}
    accepted = required_values if signing == "mandatory" else optional_values
    if settings["server signing"].lower() not in accepted:
        raise RuntimeError("Samba did not accept the requested signing policy")
    os.execv(str(executable), argv)


if __name__ == "__main__":
    main()
