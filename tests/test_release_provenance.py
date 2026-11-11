import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('release_verifier', ROOT / 'scripts/verify_release.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class ReleaseProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.names = ['vulcanary-0.68.0-py3-none-any.whl', 'vulcanary-0.68.0.tar.gz',
                      'install-windows.ps1', 'uninstall-windows.ps1']
        for name in self.names:
            (self.root / name).write_bytes(b'synthetic asset')
        self.manifest = self.root / 'SHA256SUMS.txt'
        self.lines = ''.join(hashlib.sha256(b'synthetic asset').hexdigest() + '  ' + name + '\n' for name in self.names)
        self.manifest.write_text(self.lines)

    def test_verifies_every_asset_and_exact_trust_policy(self):
        with patch.object(verifier.subprocess, 'run') as run:
            self.assertEqual(verifier.verify(self.root, 'v0.68.0', 'a' * 40), 5)
        self.assertEqual({Path(c.args[0][3]).name for c in run.call_args_list}, set(self.names + ['SHA256SUMS.txt']))
        for call in run.call_args_list:
            command = call.args[0]
            for flag, value in {'--repo': 'JesseS69/vulcanary', '--source-ref': 'refs/tags/v0.68.0',
                                '--source-digest': 'a' * 40, '--signer-digest': 'a' * 40,
                                '--cert-identity': 'https://github.com/' + verifier.WORKFLOW + '@refs/tags/v0.68.0',
                                '--predicate-type': 'https://slsa.dev/provenance/v1'}.items():
                self.assertEqual(command[command.index(flag) + 1], value)
            self.assertIn('--deny-self-hosted-runners', command)
            # gh rejects combining an exact certificate identity with signer-workflow.
            self.assertNotIn('--signer-workflow', command)
            self.assertTrue(call.kwargs['check'])
            self.assertEqual(call.kwargs['timeout'], 120)

    def test_bad_manifest_never_reaches_network_verifier(self):
        for value in (self.lines + self.lines, '', self.lines.replace(self.names[0], '../escape'),
                      self.lines.replace(self.names[0], 'SHA256SUMS.txt'), 'x' * 65537):
            self.manifest.write_text(value)
            with patch.object(verifier.subprocess, 'run') as run:
                with self.assertRaises(ValueError):
                    verifier.verify(self.root, 'v0.68.0', 'a' * 40)
                run.assert_not_called()

    def test_tampered_missing_and_extra_assets_fail_closed(self):
        for name in self.names:
            path = self.root / name
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                verifier.assets(self.root, 'v0.68.0')
            path.unlink()
            with self.assertRaises(ValueError):
                verifier.assets(self.root, 'v0.68.0')
            path.write_bytes(b'synthetic asset')
        (self.root / 'extra').write_text('unexpected')
        with self.assertRaises(ValueError):
            verifier.assets(self.root, 'v0.68.0')

    def test_missing_attestation_wrong_identity_or_offline_is_failure(self):
        for failure in (subprocess.CalledProcessError(1, ['gh']), FileNotFoundError(),
                        subprocess.TimeoutExpired(['gh'], 120)):
            with patch.object(verifier.subprocess, 'run', side_effect=failure):
                self.assertEqual(verifier.main(['--directory', str(self.root), '--tag', 'v0.68.0', '--commit', 'a'*40]), 2)
        for tag, commit in (('main', 'a'*40), ('v0.68.0', 'main'), ('--help', 'a'*40)):
            with self.assertRaises(ValueError):
                verifier.verify(self.root, tag, commit)

    def test_release_publishing_depends_on_tag_only_attestation_gate(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text(encoding='utf-8')
        attest = workflow.split('  attest-release:', 1)[1].split('  publish-github-release:', 1)[0]
        self.assertIn("if: startsWith(github.ref, 'refs/tags/v')", attest)
        self.assertIn('subject-path: release/*', attest)
        self.assertIn('python scripts/verify_release.py', attest)
        self.assertIn('needs: [build, windows-lifecycle, attest-release]', workflow)
        self.assertIn('id-token: write', attest)
        self.assertNotIn('continue-on-error', attest)


if __name__ == '__main__':
    unittest.main()
