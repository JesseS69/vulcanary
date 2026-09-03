from __future__ import annotations

import hashlib
import shutil
from pathlib import Path


SCRIPT_NAMES = ("install-windows.ps1", "uninstall-windows.ps1")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stage_release(dist: Path, scripts: Path, output: Path) -> list[Path]:
    """Stage release assets and write a basename-only SHA-256 manifest."""
    distributions = sorted(path for path in dist.iterdir() if path.is_file())
    sources = [*distributions, *(scripts / name for name in SCRIPT_NAMES)]
    missing = [path for path in sources if not path.is_file()]
    if not distributions or missing:
        raise FileNotFoundError(f"Release inputs are incomplete: {', '.join(str(path) for path in missing) or 'no distributions'}")
    names = [path.name for path in sources]
    if len(names) != len(set(names)):
        raise ValueError("Release asset names must be unique")
    output.mkdir(parents=True, exist_ok=False)
    staged = [Path(shutil.copy2(path, output / path.name)) for path in sources]
    manifest = output / "SHA256SUMS.txt"
    manifest.write_text("".join(f"{_sha256(path)}  {path.name}\n" for path in staged), encoding="utf-8", newline="\n")
    return [*staged, manifest]


if __name__ == "__main__":
    stage_release(Path("dist"), Path("scripts"), Path("release"))
