"""Build a customer-facing release ZIP from an explicit application allowlist."""
import argparse
import ast
import hashlib
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def build(destination):
    tree = ast.parse((ROOT / "scanrunner.py").read_text(encoding="utf-8"))
    version = next(node.value.value for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets))
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    name = f"scanrunner-{version}"
    paths = [ROOT / filename for filename in
             ("scanrunner.py", "install.py", "LICENSE", "README.md", "RELEASE_NOTES.md", "requirements-optional.txt")]
    paths += sorted((ROOT / "scanrunner_lib").glob("*.py"))
    paths += [ROOT / "docs/assessment-workflows.md", ROOT / "docs/README.md"]
    paths += sorted(path for path in (ROOT / "assets/readme").rglob("*") if path.is_file())
    archive_path = destination / f"{name}.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            archive.write(path, f"{name}/{path.relative_to(ROOT).as_posix()}")
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    (destination / "SHA256SUMS.txt").write_text(f"{digest}  {archive_path.name}\n", encoding="utf-8")
    return archive_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, default=ROOT / "dist")
    print(build(parser.parse_args().destination))
