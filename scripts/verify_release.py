"""Verify release checksums and GitHub provenance without installing any artifact."""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess

REPO = "JesseS69/vulcanary"
WORKFLOW = REPO + "/.github/workflows/release.yml"


def assets(directory, tag):
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("Expected a stable vX.Y.Z release tag")
    version = tag[1:]
    names = {f"vulcanary-{version}-py3-none-any.whl", f"vulcanary-{version}.tar.gz",
             "install-windows.ps1", "uninstall-windows.ps1"}
    expected = names | {"SHA256SUMS.txt"}
    if {p.name for p in directory.iterdir()} != expected:
        raise ValueError("Use a directory containing exactly the five release assets")
    for name in expected:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Release assets must be regular files, not links")
    with (directory / "SHA256SUMS.txt").open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("Checksum manifest is too large")
    entries = {}
    for line in raw.decode("ascii").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match or match[2] not in names or match[2] in entries:
            raise ValueError("Invalid or duplicate checksum entry")
        entries[match[2]] = match[1]
    if set(entries) != names:
        raise ValueError("Checksum manifest must cover all four payload assets")
    for name, expected_hash in entries.items():
        digest = hashlib.sha256()
        with (directory / name).open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected_hash:
            raise ValueError("Release checksum mismatch: " + name)
    return [directory / name for name in sorted(expected)]


def verify(directory, tag, commit):
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("Supply the independently expected full release commit")
    paths = assets(directory, tag)
    for path in paths:
        subprocess.run([
            "gh", "attestation", "verify", str(path.resolve()),
            "--repo", REPO,
            "--cert-identity", f"https://github.com/{WORKFLOW}@refs/tags/{tag}",
            "--source-ref", f"refs/tags/{tag}", "--source-digest", commit,
            "--signer-digest", commit, "--deny-self-hosted-runners",
            "--predicate-type", "https://slsa.dev/provenance/v1",
        ], check=True, timeout=120)
    return len(paths)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args(argv)
    try:
        count = verify(args.directory, args.tag, args.commit)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        print("Release verification failed. Do not install; check the expected tag/commit, assets, trusted gh installation and network access.")
        return 2
    print(f"Verified checksums and expected workflow provenance for all {count} release assets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
