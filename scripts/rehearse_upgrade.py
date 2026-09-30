"""Install supplied, trusted wheels in disposable environments and preserve real state.

No downloads, live app state, or repository-defined commands are used. This executes
the supplied Vulcanary packages: only pass trusted release/build artifacts.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import venv

PUBLISHED = {
    "vulcanary-0.64.0-py3-none-any.whl": "4f8b763371594728fdf7e927994f0d8d94cf59bc4969472cad41b0e47435dddf",
    "vulcanary-0.60.0-py3-none-any.whl": "a08604c79e1fafbb9729bc8f30f76d046cad1797d64b887e2cb03ae1da79148e",
    "vulcanary-0.63.0-py3-none-any.whl": "3c51ed93aaff7774cdac54b1572ddd9e3de49ea4d97c9c782bfba8f055ab931e",
}


def run(python, args, root):
    environment = dict(os.environ, HOME=str(root), USERPROFILE=str(root), PYTHONPATH="")
    result = subprocess.run([str(python), *args], cwd=root, env=environment,
                            capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError(f"Isolated upgrade step failed: {result.stderr}")


def rehearse(old, candidate, intermediate=None):
    for wheel in [old, *([intermediate] if intermediate else [])]:
        expected = PUBLISHED.get(wheel.name)
        if expected is None or hashlib.sha256(wheel.read_bytes()).hexdigest() != expected:
            raise ValueError(f"Unrecognized or changed published wheel: {wheel.name}")
    helper = Path(__file__).with_name("upgrade_state_fixture.py").resolve()
    receipt = Path(__file__).resolve().parents[1] / "tests/contracts/golden/receipt.json"
    with tempfile.TemporaryDirectory(prefix="vulcanary-upgrade-") as directory:
        root = Path(directory)
        venv.EnvBuilder(with_pip=True).create(root / "env")
        python = root / "env" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        versions = [old, *([intermediate] if intermediate else []), candidate,
                    *([intermediate] if intermediate else []), old]
        for index, wheel in enumerate(versions):
            app_path = root / ".vulcanary/app.json"
            before = app_path.read_bytes() if app_path.exists() else None
            run(python, ["-I", "-m", "pip", "install", "--no-index", "--no-deps", "--force-reinstall", str(wheel)], root)
            if before is not None:
                assert app_path.read_bytes() == before, "Package installation altered config bytes"
            run(python, ["-I", str(helper), "seed" if index == 0 else "check", str(root), str(receipt), wheel.name.split("-")[1]], root)
        return {"sequence": [wheel.name for wheel in versions], "result": "passed",
                "preserved": ["config/token", "repository suppressions", "fingerprints", "first_seen",
                              "history", "receipt proof", "rotation acknowledgements"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--intermediate", type=Path)
    args = parser.parse_args()
    print(json.dumps(rehearse(args.old.resolve(), args.candidate.resolve(), args.intermediate.resolve() if args.intermediate else None), indent=2))
