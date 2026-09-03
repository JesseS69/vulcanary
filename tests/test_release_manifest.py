import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts.create_release_manifest import stage_release


class ReleaseManifestTests(unittest.TestCase):
    def test_manifest_covers_distributions_and_bootstrap_scripts_by_download_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist, scripts, output = root / "dist", root / "scripts", root / "release"
            dist.mkdir(); scripts.mkdir()
            payloads = {
                "vulcanary-1.0.0.whl": b"wheel",
                "vulcanary-1.0.0.tar.gz": b"source",
                "install-windows.ps1": b"install",
                "uninstall-windows.ps1": b"uninstall",
            }
            for name, content in payloads.items():
                destination = dist if name.startswith("vulcanary-") else scripts
                (destination / name).write_bytes(content)
            assets = stage_release(dist, scripts, output)
            self.assertEqual({path.name for path in assets}, {*payloads, "SHA256SUMS.txt"})
            lines = (output / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
            expected = {f"{hashlib.sha256(content).hexdigest()}  {name}" for name, content in payloads.items()}
            self.assertEqual(set(lines), expected)
            self.assertFalse(any("dist/" in line or "scripts/" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
