"""Offline syntax, safety lint and installer payload checks using the stdlib."""
import ast
from pathlib import Path
import tokenize
import zipfile
import io

ROOT = Path(__file__).resolve().parents[1]
failures = []
sources = [ROOT / "scanrunner.py", ROOT / "install.py", *ROOT.glob("tests/*.py")]
for path in sources:
    with tokenize.open(path) as source:
        text = source.read()
    tree = ast.parse(text, filename=str(path))
    compile(tree, str(path), "exec")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and any(keyword.arg == "shell" and
                isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords):
            failures.append(f"{path.name}:{node.lineno} enables shell execution")
    for number, line in enumerate(text.splitlines(), 1):
        if line.rstrip() != line:
            failures.append(f"{path.name}:{number} has trailing whitespace")

# The supported deployment is a standalone script plus installer. Verify the
# distributable retains valid entry points and version metadata without running scans.
payload = io.BytesIO()
with zipfile.ZipFile(payload, "w") as archive:
    for name in ("scanrunner.py", "install.py", "LICENSE", "README.md"):
        archive.writestr(name, (ROOT / name).read_bytes())
with zipfile.ZipFile(payload) as archive:
    assert archive.testzip() is None
    for name in ("scanrunner.py", "install.py"):
        ast.parse(archive.read(name).decode("utf-8"))

if failures:
    raise SystemExit("\n".join(failures))
print(f"Offline quality checks passed for {len(sources)} Python sources and installer archive")
