import json
import io
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

from vulcanary.cli import main
from vulcanary.config import Config
from vulcanary.dashboard import DashboardState, make_handler
from vulcanary.dependencies import discover_packages, scan_dependencies
from vulcanary.fixes import preview
from vulcanary.models import Severity
from vulcanary.scanners import scan


class ScannerTests(unittest.TestCase):
    def test_detects_code_secret_and_iac(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text('token = "AKIAABCDEFGHIJKLMNOP"\nvalue = eval(user_input)\n', encoding="utf-8")  # gitleaks:allow -- intentional detector fixture
            (root / "Dockerfile").write_text("FROM python:3.12\nUSER root\n", encoding="utf-8")
            findings = scan(root, Config())
            self.assertEqual({f.rule_id for f in findings}, {"SECRET-AWS-KEY", "CODE-PY-EVAL", "IAC-DOCKER-ROOT"})
            secret = next(f for f in findings if f.category == "secret")
            self.assertEqual(secret.evidence, "[redacted]")

    def test_exclusions_and_ignored_rules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vendor = root / "vendor"
            vendor.mkdir()
            (vendor / "bad.js").write_text("eval(input)", encoding="utf-8")
            (root / "main.js").write_text("eval(input)", encoding="utf-8")
            config = Config(exclude=["vendor/**"], ignored_rules={"CODE-JS-EVAL"})
            self.assertEqual(scan(root, config), [])

    def test_excluded_directories_are_not_traversed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dependencies = root / "nested" / "node_modules" / "package"
            dependencies.mkdir(parents=True)
            (dependencies / "bad.js").write_text("eval(input)", encoding="utf-8")
            self.assertEqual(scan(root, Config()), [])

    def test_loads_argument_array_verification_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".vulcanary.json").write_text(json.dumps({
                "verify_commands": [["python", "-m", "pytest"], ["python", "-m", "build"]],
                "verify_timeout_seconds": 45,
            }), encoding="utf-8")
            config = Config.load(root)
            self.assertEqual(config.verify_commands[0], ["python", "-m", "pytest"])
            self.assertEqual(config.verify_timeout_seconds, 45)

    def test_inline_rule_suppression(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.js").write_text("// vulcanary:ignore CODE-JS-EVAL\neval(input)\n", encoding="utf-8")
            self.assertEqual(scan(root, Config()), [])

    def test_cli_policy_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.js").write_text("element.innerHTML = input", encoding="utf-8")
            config = root / ".vulcanary.json"
            config.write_text(json.dumps({"fail_on": "medium"}), encoding="utf-8")
            json_path = root / "report.json"
            sarif_path = root / "report.sarif"
            self.assertEqual(main([str(root), "--json", str(json_path), "--sarif", str(sarif_path)]), 1)
            self.assertEqual(json.loads(json_path.read_text())["findings"][0]["severity"], "medium")
            sarif = json.loads(sarif_path.read_text())
            self.assertEqual(sarif["version"], "2.1.0")
            fingerprints = sarif["runs"][0]["results"][0]["partialFingerprints"]
            self.assertIn("vulcanaryFingerprint/v1", fingerprints)
            self.assertNotIn("primaryLocationLineHash", fingerprints)

    def test_default_threshold_allows_medium(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.js").write_text("element.innerHTML = input", encoding="utf-8")
            self.assertEqual(main([str(root)]), 0)

    def test_pr_baseline_gates_and_annotates_only_new_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".vulcanary.json").write_text(json.dumps({"fail_on": "medium"}), encoding="utf-8")
            (root / "existing.js").write_text("element.innerHTML = input\n", encoding="utf-8")
            baseline = root / "baseline.json"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(root), "--json", str(baseline), "--no-fail", "--offline"]), 0)
                self.assertEqual(main([str(root), "--baseline-json", str(baseline), "--offline"]), 0)
                (root / "existing.js").write_text("// line moved\nelement.innerHTML = input\n", encoding="utf-8")
                self.assertEqual(main([str(root), "--baseline-json", str(baseline), "--offline"]), 0)

            (root / "new.py").write_text("result = eval(user_input)\n", encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                status = main([str(root), "--baseline-json", str(baseline), "--github-annotations", "--offline"])
            self.assertEqual(status, 1)
            annotations = [line for line in output.getvalue().splitlines() if line.startswith("::")]
            self.assertEqual(len(annotations), 1)
            self.assertIn("::error file=new.py,line=1", annotations[0])
            self.assertIn("CODE-PY-EVAL", annotations[0])

    def test_pr_baseline_fails_closed_when_report_is_malformed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = root / "baseline.json"
            baseline.write_text('{"findings": [{"title": "missing fingerprint"}]}', encoding="utf-8")
            self.assertEqual(main([str(root), "--baseline-json", str(baseline), "--offline"]), 2)

    def test_dashboard_aggregates_repositories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.js").write_text("element.innerHTML = input", encoding="utf-8")
            state = DashboardState()
            state.scan_repository(root)
            snapshot = state.snapshot()
            self.assertEqual(snapshot["summary"]["total"], 1)
            self.assertEqual(snapshot["summary"]["counts"]["medium"], 1)
            self.assertEqual(snapshot["findings"][0]["repository"], root.name)

    def test_dashboard_rescan_all_refreshes_tracked_repositories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "main.js"
            source.write_text("element.innerHTML = input", encoding="utf-8")
            with patch("vulcanary.dashboard.scan_dependencies", return_value=([], None)):
                state = DashboardState()
                state.scan_repository(root)
                self.assertEqual(state.snapshot()["summary"]["total"], 1)
                source.write_text("element.textContent = input", encoding="utf-8")
                rescanned = state.rescan_all()
            self.assertEqual(len(rescanned), 1)
            self.assertEqual(state.snapshot()["summary"]["total"], 0)

    def test_dashboard_post_actions_reject_cross_site_and_non_json_requests(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(DashboardState()))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}/api/rescan"
        try:
            with self.assertRaises(HTTPError) as non_json:
                urlopen(Request(url, data=b"{}", method="POST", headers={"Content-Type": "text/plain"}), timeout=5)
            self.assertEqual(non_json.exception.code, 415)
            non_json.exception.close()
            with self.assertRaises(HTTPError) as cross_site:
                urlopen(Request(url, data=b"{}", method="POST", headers={"Content-Type": "application/json", "Origin": "https://attacker.invalid"}), timeout=5)
            self.assertEqual(cross_site.exception.code, 403)
            cross_site.exception.close()
            response = urlopen(Request(
                url, data=b"{}", method="POST",
                headers={"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{server.server_port}"},
            ), timeout=5)
            self.assertEqual(response.status, 200)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_dashboard_imports_and_reuses_external_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            report = Path(directory) / "semgrep.json"
            report.write_text(json.dumps({"results": [{"check_id": "demo.rule", "path": "app.py", "start": {"line": 3}, "extra": {"message": "External finding", "severity": "ERROR"}}]}), encoding="utf-8")
            with patch("vulcanary.dashboard.scan_dependencies", return_value=([], None)):
                state = DashboardState()
                first = state.scan_repository(root, {"semgrep": [report]})
                second = state.scan_repository(root)
            self.assertEqual(first.findings[0]["scanner"], "semgrep")
            self.assertEqual(first.report_sources, [{"scanner": "semgrep", "path": str(report.resolve())}])
            self.assertEqual(second.findings[0]["fingerprint"], first.findings[0]["fingerprint"])
            self.assertEqual(state.snapshot()["summary"]["scanners"], {"semgrep": 1})

            malformed = Path(directory) / "malformed.json"
            malformed.write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                state.scan_repository(root, {"semgrep": [malformed]})
            self.assertEqual(state.scan_repository(root).findings[0]["fingerprint"], first.findings[0]["fingerprint"])

    def test_dashboard_tracks_and_persists_inventory_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            history = Path(directory) / "dashboard-history.json"
            lock_path = root / "package-lock.json"
            lock_path.write_text(json.dumps({"packages": {"node_modules/one": {"version": "1.0.0"}}}), encoding="utf-8")
            with patch("vulcanary.dashboard.scan_dependencies", return_value=([], None)):
                state = DashboardState(history)
                baseline = state.scan_repository(root)
                self.assertTrue(baseline.inventory_change["baseline"])
                self.assertEqual(baseline.inventory_change["current_count"], 1)

                lock_path.write_text(json.dumps({"packages": {
                    "node_modules/one": {"version": "1.0.0"},
                    "node_modules/two": {"version": "2.0.0"},
                }}), encoding="utf-8")
                changed = state.scan_repository(root)
                self.assertFalse(changed.inventory_change["baseline"])
                self.assertEqual([item["name"] for item in changed.inventory_change["added"]], ["two"])

                restored = DashboardState(history).scan_repository(root)
                self.assertEqual(restored.inventory_change["added"], [])
                self.assertEqual(restored.inventory_change["removed"], [])

    def test_dashboard_persists_and_invalidates_verified_fixes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            source = root / "main.js"
            source.write_text("element.innerHTML = input", encoding="utf-8")
            history = Path(directory) / "dashboard-history.json"
            with patch("vulcanary.dashboard.scan_dependencies", return_value=([], None)):
                state = DashboardState(history)
                state.scan_repository(root)
                fingerprint = state.snapshot()["findings"][0]["fingerprint"]
                state.verified_fixes[fingerprint] = {
                    "strategy": "platform", "candidate_version": "1.2.3", "is_migration": False,
                    "resolved": ["GHSA-demo"], "repository": str(root.resolve()),
                }
                state.scan_repository(root)
                restored = DashboardState(history)
                restored.scan_repository(root)
                finding = restored.snapshot()["findings"][0]
                self.assertTrue(finding["metadata"]["fix_eligible"])
                source.write_text("element.textContent = input", encoding="utf-8")
                restored.scan_repository(root)
            self.assertEqual(restored.verified_fixes, {})

    def test_discovers_pinned_dependencies_and_skips_generated_copies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = {"packages": {"node_modules/lodash": {"version": "4.17.20"}}}
            (root / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
            generated = root / ".expo" / "archive"
            generated.mkdir(parents=True)
            (generated / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
            packages = discover_packages(root)
            self.assertEqual([(item.name, item.version, item.ecosystem) for item in packages], [("lodash", "4.17.20", "npm")])

    def test_discovers_yarn_classic_and_berry_locks_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4.17.20"}}), encoding="utf-8")
            (root / "yarn.lock").write_text(
                'lodash@^4.17.20:\n  version "4.17.20"\n\n"@scope/demo@npm:^2.0.0":\n  version: 2.1.0\n',
                encoding="utf-8",
            )
            packages = sorted(discover_packages(root), key=lambda item: item.name)
            self.assertEqual([(item.name, item.version, item.manager) for item in packages], [
                ("@scope/demo", "2.1.0", "yarn"), ("lodash", "4.17.20", "yarn"),
            ])
            self.assertTrue(next(item for item in packages if item.name == "lodash").direct)

    def test_discovers_pnpm_locks_and_strips_peer_suffixes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(json.dumps({"devDependencies": {"vite": "5.4.0"}}), encoding="utf-8")
            (root / "pnpm-lock.yaml").write_text(
                "lockfileVersion: '9.0'\npackages:\n  '@scope/demo@2.1.0':\n    resolution: {}\n  vite@5.4.0(@types/node@22.0.0):\n    resolution: {}\n",
                encoding="utf-8",
            )
            packages = sorted(discover_packages(root), key=lambda item: item.name)
            self.assertEqual([(item.name, item.version, item.manager) for item in packages], [
                ("@scope/demo", "2.1.0", "pnpm"), ("vite", "5.4.0", "pnpm"),
            ])
            self.assertTrue(next(item for item in packages if item.name == "vite").direct)

    def test_normalizes_osv_advisories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("demo==1.0.0\n", encoding="utf-8")
            batch = {"results": [{"vulns": [{"id": "GHSA-test"}]}]}
            record = {"summary": "Demo advisory", "database_specific": {"severity": "CRITICAL"}, "affected": [{"package": {"name": "demo"}, "ranges": [{"events": [{"fixed": "1.1.0"}]}]}]}
            with patch("vulcanary.dependencies._json_request", side_effect=[batch, record]):
                findings, warning = scan_dependencies(root, cache_dir=False)
            self.assertIsNone(warning)
            self.assertEqual(findings[0].severity, Severity.CRITICAL)
            self.assertIn("1.1.0", findings[0].remediation)

    def test_reuses_sanitized_osv_cache_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as cache_directory:
            root = Path(directory)
            cache = Path(cache_directory)
            (root / "requirements.txt").write_text("cached-demo==1.0.0\n", encoding="utf-8")
            batch = {"results": [{"vulns": [{"id": "GHSA-cached"}]}]}
            record = {"summary": "Cached advisory", "affected": [{"package": {"name": "cached-demo"}, "ranges": [{"events": [{"fixed": "1.0.1"}]}]}]}
            with patch("vulcanary.dependencies._json_request", side_effect=[batch, record]):
                first, warning = scan_dependencies(root, cache_dir=cache)
            self.assertIsNone(warning)
            with patch("vulcanary.dependencies._json_request", side_effect=AssertionError("network should not be used")):
                second, warning = scan_dependencies(root, cache_dir=cache)
            self.assertIsNone(warning)
            self.assertEqual([item.fingerprint for item in first], [item.fingerprint for item in second])
            cache_text = "".join(path.read_text(encoding="utf-8") for path in cache.rglob("*.json"))
            self.assertNotIn(str(root), cache_text)

    def test_only_direct_same_major_npm_dependencies_are_auto_fixable(self) -> None:
        record = {
            "summary": "Demo advisory",
            "affected": [{"package": {"name": "demo"}, "ranges": [{"events": [{"fixed": "1.1.0"}]}]}],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            direct_lock = {"packages": {
                "": {"dependencies": {"demo": "1.0.0"}},
                "node_modules/demo": {"version": "1.0.0"},
            }}
            (root / "package-lock.json").write_text(json.dumps(direct_lock), encoding="utf-8")
            with patch("vulcanary.dependencies._json_request", side_effect=[{"results": [{"vulns": [{"id": "GHSA-demo"}]}]}, record]):
                direct_findings, _ = scan_dependencies(root, cache_dir=False)
            self.assertTrue(direct_findings[0].metadata["fix_eligible"])

            transitive_lock = {"packages": {
                "": {"dependencies": {"parent": "1.0.0"}},
                "node_modules/parent": {"version": "1.0.0", "dependencies": {"demo": "1.0.0"}},
                "node_modules/demo": {"version": "1.0.0"},
            }}
            (root / "package-lock.json").write_text(json.dumps(transitive_lock), encoding="utf-8")
            batch = {"results": [{}, {"vulns": [{"id": "GHSA-demo"}]}]}
            with patch("vulcanary.dependencies._json_request", side_effect=[batch, record]):
                transitive_findings, _ = scan_dependencies(root, cache_dir=False)
            self.assertFalse(transitive_findings[0].metadata["fix_eligible"])
            self.assertIn("Upgrade parent", transitive_findings[0].metadata["fix_block_reason"])
            self.assertEqual(transitive_findings[0].metadata["parent_packages"], ["parent"])
            self.assertEqual(transitive_findings[0].metadata["parent_scopes"], {"parent": "runtime"})
            self.assertEqual(transitive_findings[0].metadata["dependency_paths"], [["parent@1.0.0", "demo@1.0.0"]])

    def test_fix_preview_separates_safe_and_manual_findings(self) -> None:
        findings = [
            {"fingerprint": "safe", "title": "Safe", "repository": "app", "repository_path": "C:/app", "metadata": {"fix_eligible": True, "package": "demo", "current_version": "1.0.0", "fixed_version": "1.1.0", "advisory": "GHSA-safe"}},
            {"fingerprint": "manual", "title": "Manual", "repository": "app", "repository_path": "C:/app", "metadata": {"fix_eligible": False}},
        ]
        plan = preview(findings, ["safe", "manual"])
        self.assertEqual(len(plan["changes"]), 1)
        self.assertEqual(len(plan["blocked"]), 1)


if __name__ == "__main__":
    unittest.main()
