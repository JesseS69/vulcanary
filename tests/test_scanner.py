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
from vulcanary.dashboard import DashboardState, make_handler, resolution_record_valid, serve
from vulcanary.dependencies import Package, dependency_context, discover_packages, scan_dependencies
from vulcanary.fixes import preview
from vulcanary.models import Finding, Severity
from vulcanary.scanners import rules_for, ruleset_manifest, scan


class ScannerTests(unittest.TestCase):
    def test_source_rules_are_compiled_once_per_scan_not_once_per_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.py").write_text("value = 1\n", encoding="utf-8")
            (root / "two.py").write_text("value = 2\n", encoding="utf-8")
            with patch("vulcanary.scanners.rules_for", wraps=rules_for) as build_rules:
                scan(root, Config())
            build_rules.assert_called_once()

    def test_dashboard_reuses_one_dependency_discovery_and_ruleset_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch("vulcanary.dashboard.discover_dependency_state", return_value=([], [])) as discovery,
                patch("vulcanary.dashboard.scan_dependencies", return_value=([], None)),
                patch("vulcanary.dashboard.ruleset_manifest", wraps=ruleset_manifest) as manifest,
            ):
                DashboardState().scan_repository(root)
            discovery.assert_called_once_with(root.resolve())
            manifest.assert_called_once()

    def test_dependency_graph_is_built_once_for_multiple_findings_in_one_lock(self) -> None:
        lock = json.dumps({"packages": {
            "": {"dependencies": {"parent": "1.0.0"}},
            "node_modules/parent": {"version": "1.0.0", "dependencies": {"first": "1.0.0", "second": "2.0.0"}},
            "node_modules/first": {"version": "1.0.0"},
            "node_modules/second": {"version": "2.0.0"},
        }})
        cache = {}
        with patch.object(Path, "read_text", return_value=lock) as read_lock:
            first = dependency_context(Path("repo"), Package("first", "1.0.0", "npm", "package-lock.json"), cache)
            second = dependency_context(Path("repo"), Package("second", "2.0.0", "npm", "package-lock.json"), cache)
        self.assertEqual(first[0], ["parent"])
        self.assertEqual(second[0], ["parent"])
        read_lock.assert_called_once()

    def test_corrupt_history_fails_closed_to_empty_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            history = Path(directory) / "history.json"
            history.write_text("{interrupted", encoding="utf-8")
            state = DashboardState(history)
        self.assertEqual(state.history, [])
        self.assertEqual(state.web_audits, {})

    def test_interrupted_history_write_preserves_previous_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            history = Path(directory) / "history.json"
            history.write_text('{"history": []}\n', encoding="utf-8")
            state = DashboardState(history)
            with patch("pathlib.Path.write_text", side_effect=OSError("disk full")):
                state._persist_history()
            self.assertEqual(history.read_text(encoding="utf-8"), '{"history": []}\n')

    def test_dashboard_binds_before_initial_repository_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); events = []
            class Server:
                server_port = 8765
                def __init__(self, address, handler): events.append("bound")
                def serve_forever(self): events.append("serving")
                def shutdown(self): pass
                def server_close(self): pass
            def scan_after_bind(_self, _path):
                self.assertIn("bound", events)
                events.append("scan")
            with patch("vulcanary.dashboard.ThreadingHTTPServer", Server), patch.object(DashboardState, "scan_repository", scan_after_bind), patch.object(DashboardState, "start_monitor"), patch.object(DashboardState, "stop_monitor"), patch("vulcanary.local_app.save_watched_repositories"):
                self.assertEqual(serve("127.0.0.1", 8765, [root], open_browser=False), 0)
            self.assertEqual(events[0], "bound")

    def test_initial_scan_failure_is_reported_and_monitor_still_starts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); finished = threading.Event(); captured = {}
            class Server:
                server_port = 8765
                def __init__(self, address, handler): captured["handler"] = handler
                def serve_forever(self): finished.wait(2)
                def shutdown(self): pass
                def server_close(self): pass
            def fail_scan(_self, _path): raise OSError("unavailable")
            def start_monitor(state): captured["state"] = state; finished.set()
            with patch("vulcanary.dashboard.ThreadingHTTPServer", Server), patch.object(DashboardState, "scan_repository", fail_scan), patch.object(DashboardState, "start_monitor", start_monitor), patch.object(DashboardState, "stop_monitor"), patch("vulcanary.local_app.save_watched_repositories") as save_repositories:
                self.assertEqual(serve("127.0.0.1", 8765, [root], open_browser=False), 0)
            state = captured["state"]
            self.assertEqual(state.startup_completed, 1)
            self.assertEqual(state.startup_errors[0]["repository"], root.name)
            save_repositories.assert_called_once_with([str(root)])

    def test_ruleset_manifest_is_canonical_and_complete(self) -> None:
        first = ruleset_manifest()
        self.assertEqual(first["digest"], ruleset_manifest()["digest"])
        self.assertEqual(len(first["digest"]), 64)
        self.assertEqual(first["rules"], sorted(first["rules"], key=lambda item: item["id"]))
        self.assertIn("CODE-PY-EVAL", {item["id"] for item in first["rules"]})
        self.assertTrue(all(item["pattern"] for item in first["rules"]))
        self.assertTrue(all(isinstance(item["pattern_flags"], int) for item in first["rules"]))
        engines = {item["id"]: item["engine"] for item in first["rules"]}
        self.assertEqual(engines["CODE-PY-EVAL"], "python_ast_with_regex_fallback")
        self.assertEqual(engines["CODE-JS-EVAL"], "regex")

    def test_detects_code_secret_and_iac(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text('token = "AKIAABCDEFGHIJKLMNOP"\nvalue = eval(user_input)\n', encoding="utf-8")  # gitleaks:allow -- intentional detector fixture
            (root / "Dockerfile").write_text("FROM python:3.12\nUSER root\n", encoding="utf-8")
            findings = scan(root, Config())
            self.assertEqual({f.rule_id for f in findings}, {"SECRET-AWS-KEY", "CODE-PY-EVAL", "IAC-DOCKER-ROOT"})
            secret = next(f for f in findings if f.category == "secret")
            self.assertEqual(secret.evidence, "[redacted]")

    def test_detects_high_confidence_python_container_terraform_and_ci_risks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "unsafe.py").write_text("import pickle\nvalue = pickle.loads(payload)\n", encoding="utf-8")
            (root / "Dockerfile").write_text("FROM python:latest\nRUN curl https://example.invalid/install | bash\n", encoding="utf-8")
            (root / "storage.tf").write_text('resource "aws_s3_bucket_acl" "demo" {\n  acl = "public-read"\n}\n', encoding="utf-8")
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "unsafe.yml").write_text(
                "name: unsafe\npermissions: write-all\nsteps:\n"
                "  - uses: vendor/action@main\n"
                "  - uses: ./local-action@main\n"
                "  - uses: actions/checkout@0123456789abcdef\n"
                "    with:\n      persist-credentials: true\n",
                encoding="utf-8",
            )
            (root / "ordinary.yml").write_text("permissions: write-all\n", encoding="utf-8")
            rules = {finding.rule_id for finding in scan(root, Config())}
            self.assertEqual(rules, {
                "CODE-PY-PICKLE", "IAC-DOCKER-LATEST", "IAC-DOCKER-CURL-PIPE",
                "IAC-TF-PUBLIC-ACL", "CI-GHA-WRITE-ALL", "CI-GHA-MUTABLE-ACTION",
                "CI-GHA-PERSIST-CREDENTIALS",
            })

    def test_python_ast_ignores_security_words_in_comments_and_strings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs.py").write_text(
                '# eval(user_input)\n'
                'example = "pickle.loads(payload)"\n'
                'command = "subprocess.run([tool], shell=True)"\n',
                encoding="utf-8",
            )
            self.assertEqual(scan(root, Config()), [])

    def test_python_ast_preserves_existing_fingerprints_for_existing_call_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "stable.py"
            source.write_text(
                "import pickle\nimport subprocess\n"
                "value = eval(user_input)\n"
                "data = pickle.loads(payload)\n"
                "subprocess.run(['tool'], shell=True)\n",
                encoding="utf-8",
            )
            ast_findings = scan(root, Config())
            with patch("vulcanary.scanners._python_ast_matches", return_value=None):
                regex_findings = scan(root, Config())
            self.assertEqual(
                {(item.rule_id, item.fingerprint) for item in ast_findings},
                {(item.rule_id, item.fingerprint) for item in regex_findings},
            )

    def test_python_ast_detects_aliases_direct_imports_and_multiline_calls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "unsafe.py").write_text(
                "import subprocess as process\n"
                "from pickle import loads as restore\n"
                "process.run(\n    ['tool', value],\n    shell=True,\n)\n"
                "result = restore(payload)\n",
                encoding="utf-8",
            )
            findings = scan(root, Config())
            self.assertEqual(
                [(item.rule_id, item.line) for item in findings],
                [("CODE-PY-SHELL", 3), ("CODE-PY-PICKLE", 7)],
            )

    def test_python_ast_keeps_function_local_import_aliases_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scoped.py").write_text(
                "def checked(value):\n"
                "    import subprocess as process\n"
                "    process.run(['tool', value], shell=True)\n"
                "\n"
                "process.run(['safe'], check=True)\n",
                encoding="utf-8",
            )
            findings = scan(root, Config())
            self.assertEqual([(item.rule_id, item.line) for item in findings], [("CODE-PY-SHELL", 3)])

    def test_invalid_python_keeps_conservative_regex_detection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "broken.py").write_text("if (:  # incomplete\nvalue = eval(user_input)\n", encoding="utf-8")
            self.assertEqual([item.rule_id for item in scan(root, Config())], ["CODE-PY-EVAL"])

    def test_exclusions_and_ignored_rules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vendor = root / "vendor"
            vendor.mkdir()
            (vendor / "bad.js").write_text("eval(input)", encoding="utf-8")
            (root / "main.js").write_text("eval(input)", encoding="utf-8")
            config = Config(exclude=["vendor/**"], ignored_rules={"CODE-JS-EVAL"})
            self.assertEqual(scan(root, config), [])

    def test_only_reviewed_custom_rules_are_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("dangerous_call(user_input)\n", encoding="utf-8")
            custom = {
                "id": "CUSTOM-DANGEROUS-CALL", "title": "Reviewed dangerous call",
                "pattern": r"dangerous_call\s*\(", "severity": "high", "category": "sast",
                "remediation": "Replace the dangerous call with a validated API.", "extensions": [".py"],
                "status": "approved", "tests": {
                    "matching": ["dangerous_call(value)"], "nonmatching": ["safe_call(value)"],
                },
            }
            (root / ".vulcanary.json").write_text(json.dumps({"custom_rules": [custom]}), encoding="utf-8")
            config = Config.load(root)
            self.assertEqual([item.rule_id for item in scan(root, config)], ["CUSTOM-DANGEROUS-CALL"])
            self.assertIn("CUSTOM-DANGEROUS-CALL", {item["id"] for item in ruleset_manifest(config)["rules"]})
            custom["status"] = "draft"
            (root / ".vulcanary.json").write_text(json.dumps({"custom_rules": [custom]}), encoding="utf-8")
            self.assertEqual(scan(root, Config.load(root)), [])

    def test_approved_custom_rule_fails_closed_without_review_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rule = {
                "id": "CUSTOM-UNTESTED", "title": "Untested", "pattern": "unsafe",
                "severity": "medium", "category": "sast", "remediation": "Review it.",
                "status": "approved", "tests": {"matching": [], "nonmatching": []},
            }
            (root / ".vulcanary.json").write_text(json.dumps({"custom_rules": [rule]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "requires matching and nonmatching"):
                Config.load(root)

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
            (root / "main.js").write_text("// vulcanary:ignore CODE-JS-EVAL owner=security@example.com expires=2099-01-01 -- Reviewed safe parser input only.\neval(input)\n", encoding="utf-8")
            self.assertEqual(scan(root, Config()), [])

    def test_normalized_report_preserves_inline_exception(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.js").write_text("// vulcanary:ignore CODE-JS-EVAL owner=security@example.com expires=2099-01-01 -- Reviewed safe parser input only.\neval(input)\n", encoding="utf-8")
            report = root / "report.json"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(root), "--json", str(report), "--offline"]), 0)
            record = json.loads(report.read_text(encoding="utf-8"))["exceptions"][0]
            self.assertEqual((record["scope"], record["rule_id"], record["status"]), ("inline", "CODE-JS-EVAL", "active"))

    def test_incomplete_and_expired_inline_suppressions_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "main.js"
            source.write_text("// vulcanary:ignore CODE-JS-EVAL\neval(input)\n", encoding="utf-8")
            self.assertEqual({item.rule_id for item in scan(root, Config())}, {"CODE-JS-EVAL", "GOV-INLINE-IGNORE-INVALID"})
            source.write_text("// vulcanary:ignore CODE-JS-EVAL owner=security@example.com expires=2000-01-01 -- Previously accepted risk.\neval(input)\n", encoding="utf-8")
            self.assertEqual({item.rule_id for item in scan(root, Config())}, {"CODE-JS-EVAL", "GOV-INLINE-IGNORE-EXPIRED"})

    def test_cli_policy_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.js").write_text("element.innerHTML = input", encoding="utf-8")
            config = root / ".vulcanary.json"
            config.write_text(json.dumps({"fail_on": "medium"}), encoding="utf-8")
            json_path = root / "report.json"
            sarif_path = root / "report.sarif"
            ruleset_path = root / "ruleset.json"
            provenance_path = root / "provenance.json"
            self.assertEqual(main([str(root), "--json", str(json_path), "--sarif", str(sarif_path), "--ruleset-manifest", str(ruleset_path), "--provenance", str(provenance_path)]), 1)
            self.assertEqual(json.loads(json_path.read_text())["findings"][0]["severity"], "medium")
            self.assertEqual(json.loads(json_path.read_text())["policy"]["repository_owner"], "unassigned")
            sarif = json.loads(sarif_path.read_text())
            self.assertEqual(sarif["version"], "2.1.0")
            fingerprints = sarif["runs"][0]["results"][0]["partialFingerprints"]
            self.assertIn("vulcanaryFingerprint/v1", fingerprints)
            self.assertNotIn("primaryLocationLineHash", fingerprints)
            self.assertEqual(sarif["runs"][0]["properties"]["vulcanaryPolicy"]["remediation_sla_days"]["high"], 7)
            self.assertEqual(json.loads(ruleset_path.read_text(encoding="utf-8"))["digest"], json.loads(json_path.read_text(encoding="utf-8"))["policy"]["ruleset"]["digest"])
            self.assertEqual({item["name"] for item in json.loads(provenance_path.read_text(encoding="utf-8"))["subject"]}, {"report.json", "report.sarif", "ruleset.json"})

    def test_default_threshold_allows_medium(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.js").write_text("element.innerHTML = input", encoding="utf-8")
            self.assertEqual(main([str(root)]), 0)

    def test_static_innerhtml_literal_is_not_reported_as_user_controlled_xss(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "notice.js").write_text("notice.innerHTML = '<strong>Static notice</strong>';\n", encoding="utf-8")
            (root / "dynamic.js").write_text("notice.innerHTML = `<strong>${message}</strong>`;\n", encoding="utf-8")
            findings = scan(root, Config())
        self.assertEqual([(item.rule_id, item.path) for item in findings], [("CODE-JS-INNERHTML", "dynamic.js")])

    def test_github_summary_is_source_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            (root / "main.js").write_text("element.innerHTML = private_customer_value\n", encoding="utf-8")
            summary = Path(directory) / "summary.md"
            with patch.dict("os.environ", {"GITHUB_STEP_SUMMARY": str(summary)}):
                self.assertEqual(main([str(root), "--github-summary", "--offline", "--no-fail"]), 0)
            rendered = summary.read_text(encoding="utf-8")
            self.assertIn("Vulcanary security summary", rendered)
            self.assertIn("main.js:1", rendered)
            self.assertNotIn("private_customer_value", rendered)

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
            self.assertEqual(snapshot["findings"][0]["metadata"]["policy"]["owner"], "unassigned")
            self.assertEqual(snapshot["repositories"][0]["policy"]["sla_days"]["medium"], 30)
            self.assertEqual(snapshot["repositories"][0]["health"]["status"], "healthy")

    def test_dashboard_can_stop_watching_without_erasing_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("vulcanary.dashboard.scan_dependencies", return_value=([], None)):
                state = DashboardState()
                state.scan_repository(root)
            self.assertEqual(len(state.history), 1)
            state.remove_repository(str(root))
            self.assertEqual(state.snapshot()["repositories"], [])
            self.assertEqual(len(state.history), 1)
            with self.assertRaisesRegex(ValueError, "not currently watched"):
                state.remove_repository(str(root))

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

    def test_dashboard_mutating_routes_require_the_local_control_token(self) -> None:
        """A loopback bind is not an authorization boundary: other local users can reach it too."""
        state = DashboardState()
        state.control_token = "test-control-token"
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for route in ("/api/rescan", "/api/scan", "/api/fixes/apply", "/api/fixes/commit", "/api/web-audit"):
                url = f"http://127.0.0.1:{server.server_port}{route}"
                for headers in (
                    {"Content-Type": "application/json"},
                    {"Content-Type": "application/json", "X-Vulcanary-Control": "wrong-token"},
                ):
                    with self.assertRaises(HTTPError) as refused:
                        urlopen(Request(url, data=b"{}", method="POST", headers=headers), timeout=5)
                    self.assertEqual(refused.exception.code, 403, route)
                    refused.exception.close()
            state_url = f"http://127.0.0.1:{server.server_port}/api/state"
            for request in (state_url, Request(state_url, headers={"X-Vulcanary-Control": "wrong-token"})):
                with self.assertRaises(HTTPError) as refused_state:
                    urlopen(request, timeout=5)
                self.assertEqual(refused_state.exception.code, 403)
                refused_state.exception.close()
            authorized = Request(state_url, headers={"X-Vulcanary-Control": state.control_token})
            self.assertEqual(urlopen(authorized, timeout=5).status, 200)
            ruleset_url = f"http://127.0.0.1:{server.server_port}/api/ruleset.json"
            for request in (ruleset_url, Request(ruleset_url, headers={"X-Vulcanary-Control": "wrong-token"})):
                with self.assertRaises(HTTPError) as protected_download:
                    urlopen(request, timeout=5)
                self.assertEqual(protected_download.exception.code, 403)
                protected_download.exception.close()
            ruleset = Request(ruleset_url, headers={"X-Vulcanary-Control": state.control_token})
            self.assertEqual(urlopen(ruleset, timeout=5).status, 200)
            health_url = f"http://127.0.0.1:{server.server_port}/api/health"
            health = json.loads(urlopen(health_url, timeout=5).read())
            self.assertEqual(health["status"], "ok")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_dashboard_post_actions_reject_cross_site_and_non_json_requests(self) -> None:
        state = DashboardState()
        state.control_token = "test-control-token"
        authorized = {"X-Vulcanary-Control": state.control_token}
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}/api/rescan"
        try:
            with self.assertRaises(HTTPError) as non_json:
                urlopen(Request(url, data=b"{}", method="POST", headers={"Content-Type": "text/plain", **authorized}), timeout=5)
            self.assertEqual(non_json.exception.code, 415)
            non_json.exception.close()
            with self.assertRaises(HTTPError) as cross_site:
                urlopen(Request(url, data=b"{}", method="POST", headers={"Content-Type": "application/json", "Origin": "https://attacker.invalid", **authorized}), timeout=5)
            self.assertEqual(cross_site.exception.code, 403)
            cross_site.exception.close()
            with self.assertRaises(HTTPError) as invalid_host:
                urlopen(Request(url, data=b"{}", method="POST", headers={"Content-Type": "application/json", "Host": "attacker.invalid", **authorized}), timeout=5)
            self.assertEqual(invalid_host.exception.code, 400)
            invalid_host.exception.close()
            with self.assertRaises(HTTPError) as non_object:
                urlopen(Request(url, data=b"[]", method="POST", headers={"Content-Type": "application/json", **authorized}), timeout=5)
            self.assertEqual(non_object.exception.code, 400)
            non_object.exception.close()
            response = urlopen(Request(
                url, data=b"{}", method="POST",
                headers={"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{server.server_port}", **authorized},
            ), timeout=5)
            self.assertEqual(response.status, 200)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_dashboard_shutdown_requires_the_local_control_token(self) -> None:
        state = DashboardState()
        state.control_token = "t" * 43
        stopped = threading.Event()
        state.shutdown_callback = stopped.set
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}/api/control/shutdown"
        try:
            with self.assertRaises(HTTPError) as missing:
                urlopen(Request(url, data=b"{}", method="POST", headers={"Content-Type": "application/json"}), timeout=5)
            self.assertEqual(missing.exception.code, 403)
            missing.exception.close()
            response = urlopen(Request(url, data=b"{}", method="POST", headers={
                "Content-Type": "application/json", "X-Vulcanary-Control": state.control_token,
            }), timeout=5)
            self.assertEqual(response.status, 200)
            self.assertTrue(stopped.wait(timeout=2))
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

    def test_dashboard_records_tamper_evident_resolution_and_recurrence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            source = root / "main.js"
            history = Path(directory) / "dashboard-history.json"
            source.write_text("element.innerHTML = input\n", encoding="utf-8")
            with (
                patch("vulcanary.dashboard.scan_dependencies", return_value=([], None)),
                patch("vulcanary.dashboard._git_identity", return_value=("a" * 40, "main")),
            ):
                state = DashboardState(history)
                state.scan_repository(root)
                fingerprint = state.snapshot()["findings"][0]["fingerprint"]

                source.write_text("element.textContent = input\n", encoding="utf-8")
                state.scan_repository(root)
                record = state.snapshot()["resolved_findings"][0]
                self.assertEqual(record["fingerprint"], fingerprint)
                self.assertEqual(record["resolution_type"], "observed_resolved")
                self.assertEqual(record["resolution_commit"], "a" * 40)
                self.assertEqual(record["status"], "resolved")
                self.assertTrue(record["proof_valid"])
                self.assertNotIn("evidence", record)
                self.assertNotIn(str(root.resolve()), json.dumps(record))

                restored = DashboardState(history)
                self.assertTrue(resolution_record_valid(restored.resolved_findings[0]))
                tampered = dict(restored.resolved_findings[0], title="Changed title")
                self.assertFalse(resolution_record_valid(tampered))

                source.write_text("element.innerHTML = input\n", encoding="utf-8")
                restored.scan_repository(root)
                reopened = restored.snapshot()["resolved_findings"][0]
                self.assertEqual(reopened["status"], "reopened")
                self.assertIsNotNone(reopened["reopened_at"])
                self.assertTrue(reopened["proof_valid"])
                alert = restored.snapshot()["monitor_events"][0]
                self.assertEqual(alert["event"], "reopened")
                self.assertEqual(alert["fingerprint"], fingerprint)
                self.assertNotIn("evidence", alert)

                restored.scan_repository(root)
                self.assertEqual(len(restored.resolved_findings), 1)

                source.write_text("element.textContent = input\n", encoding="utf-8")
                restored.scan_repository(root)
                latest = restored.snapshot()["resolved_findings"][0]
                self.assertEqual(latest["recurrence_index"], 1)
                self.assertEqual(len(restored.resolved_findings), 2)

    def test_monitor_configuration_is_validated_and_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            history = Path(directory) / "dashboard-history.json"
            state = DashboardState(history)
            state.configure_monitor(False, 900)
            restored = DashboardState(history)
            self.assertFalse(restored.monitor_enabled)
            self.assertEqual(restored.monitor_interval_seconds, 900)
            with self.assertRaisesRegex(ValueError, "between 30 and 86400"):
                restored.configure_monitor(True, 5)
            with self.assertRaisesRegex(ValueError, "boolean"):
                restored.configure_monitor("yes", 300)  # type: ignore[arg-type]

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

    def test_discovers_modern_python_locks_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = (
                'version = 1\n\n[[package]]\nname = "requests"\nversion = "2.32.0"\n'
                '\n[[package]]\nname = "urllib3"\nversion = "2.2.2"\n'
            )
            (root / "uv.lock").write_text(content, encoding="utf-8")
            nested = root / "service"
            nested.mkdir()
            (nested / "poetry.lock").write_text(content, encoding="utf-8")
            packages = discover_packages(root)
            self.assertEqual(
                {(item.name, item.version, item.manager, item.direct) for item in packages},
                {
                    ("requests", "2.32.0", "uv", False), ("urllib3", "2.2.2", "uv", False),
                    ("requests", "2.32.0", "poetry", False), ("urllib3", "2.2.2", "poetry", False),
                },
            )

    def test_discovers_go_requirements_with_directness_and_major_module_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.mod").write_text(
                "module example.test/app\n\ngo 1.23\n\nrequire github.com/gogo/protobuf v1.3.1\n"
                "require (\n  golang.org/x/text v0.3.7 // indirect\n  example.test/library/v2 v2.4.0+incompatible\n)\n",
                encoding="utf-8",
            )
            packages = sorted(discover_packages(root), key=lambda item: item.name)
            self.assertEqual([(item.name, item.version, item.ecosystem, item.direct) for item in packages], [
                ("example.test/library/v2", "2.4.0+incompatible", "Go", True),
                ("github.com/gogo/protobuf", "1.3.1", "Go", True),
                ("golang.org/x/text", "0.3.7", "Go", False),
            ])

    def test_discovers_only_crates_io_packages_and_derives_cargo_directness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text(
                '[dependencies]\nregex = "1"\nrenamed = { package = "serde", version = "1" }\n'
                '[target.\'cfg(unix)\'.dev-dependencies]\ntempfile = "3"\n'
                '[workspace.dependencies]\ncatalog-only = "1"\n',
                encoding="utf-8",
            )
            (root / "Cargo.lock").write_text(
                'version = 4\n\n[[package]]\nname = "workspace-app"\nversion = "0.1.0"\n'
                '\n[[package]]\nname = "regex"\nversion = "1.5.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
                '\n[[package]]\nname = "serde"\nversion = "1.0.100"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
                '\n[[package]]\nname = "tempfile"\nversion = "3.8.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
                '\n[[package]]\nname = "catalog-only"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'
                '\n[[package]]\nname = "git-only"\nversion = "1.0.0"\nsource = "git+https://example.test/repo"\n',
                encoding="utf-8",
            )
            packages = sorted(discover_packages(root), key=lambda item: item.name)
            self.assertEqual([(item.name, item.ecosystem, item.manager, item.direct) for item in packages], [
                ("catalog-only", "crates.io", "cargo", False),
                ("regex", "crates.io", "cargo", True),
                ("serde", "crates.io", "cargo", True),
                ("tempfile", "crates.io", "cargo", True),
            ])

    def test_go_and_cargo_known_vulnerabilities_reach_osv_with_exact_identities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "go.mod").write_text("module example.test/app\nrequire github.com/gogo/protobuf v1.3.1\n", encoding="utf-8")
            (root / "Cargo.toml").write_text('[dependencies]\nregex = "1.5.1"\n', encoding="utf-8")
            (root / "Cargo.lock").write_text(
                'version = 4\n[[package]]\nname = "regex"\nversion = "1.5.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
                encoding="utf-8",
            )
            captured = {}
            def osv(url, payload=None, timeout=10):
                if url.endswith("querybatch"):
                    captured["queries"] = payload["queries"]
                    return {"results": [
                        {"vulns": [{"id": "GHSA-rust-known"}]},
                        {"vulns": [{"id": "GHSA-go-known"}]},
                    ]}
                advisory = url.rsplit("/", 1)[-1]
                package = "regex" if advisory == "GHSA-rust-known" else "github.com/gogo/protobuf"
                return {"summary": "Known vulnerable fixture", "affected": [{"package": {"name": package}, "ranges": [{"events": [{"fixed": "9.9.9"}]}]}]}
            with patch("vulcanary.dependencies._json_request", side_effect=osv):
                findings, warning = scan_dependencies(root, cache_dir=False)
            self.assertIsNone(warning)
            self.assertEqual(captured["queries"], [
                {"package": {"name": "regex", "ecosystem": "crates.io"}, "version": "1.5.1"},
                {"package": {"name": "github.com/gogo/protobuf", "ecosystem": "Go"}, "version": "1.3.1"},
            ])
            self.assertEqual({item.metadata["manager"] for item in findings}, {"cargo", "go"})
            self.assertTrue(all(not item.metadata["fix_eligible"] for item in findings))
            self.assertTrue(all("read-only" in item.metadata["fix_block_reason"] for item in findings))

    def test_discovers_composer_runtime_and_development_packages_with_true_directness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "composer.json").write_text(json.dumps({
                "require": {"php": "^8.2", "ext-json": "*", "Symfony/Http-Foundation": "5.4.0"},
                "require-dev": {"phpunit/phpunit": "^10"},
            }), encoding="utf-8")
            (root / "composer.lock").write_text(json.dumps({
                "packages": [
                    {"name": "symfony/http-foundation", "version": "v5.4.0"},
                    {"name": "psr/log", "version": "3.0.0"},
                ],
                "packages-dev": [
                    {"name": "phpunit/phpunit", "version": "10.5.0"},
                    {"name": "fakerphp/faker", "version": "1.23.0"},
                ],
            }), encoding="utf-8")
            packages = sorted(discover_packages(root), key=lambda item: item.name)
            self.assertEqual([(item.name, item.version, item.direct, item.scope) for item in packages], [
                ("fakerphp/faker", "1.23.0", False, "development"),
                ("phpunit/phpunit", "10.5.0", True, "development"),
                ("psr/log", "3.0.0", False, "runtime"),
                ("symfony/http-foundation", "v5.4.0", True, "runtime"),
            ])

    def test_discovers_registry_gems_by_indent_and_normalizes_platform_versions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Gemfile.lock").write_text(
                "GIT\n  remote: https://example.test/private.git\n  revision: abcdef\n  specs:\n    private-gem (1.0.0)\n\n"
                "PATH\n  remote: local\n  specs:\n    local-gem (1.0.0)\n\n"
                "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.16.5-x86_64-linux)\n      mini_portile2 (~> 2.8)\n"
                "    rack (2.2.3)\n    mini_portile2 (2.8.7)\n\nPLATFORMS\n  ruby\n  x86_64-linux\n\n"
                "DEPENDENCIES\n  nokogiri (~> 1.16)\n  private-gem!\n  rack\n\nBUNDLED WITH\n   2.5.9\n",
                encoding="utf-8",
            )
            packages = sorted(discover_packages(root), key=lambda item: item.name)
            self.assertEqual([(item.name, item.version, item.direct, item.manager) for item in packages], [
                ("mini_portile2", "2.8.7", False, "bundler"),
                ("nokogiri", "1.16.5", True, "bundler"),
                ("rack", "2.2.3", True, "bundler"),
            ])

    def test_composer_and_rubygems_known_vulnerabilities_use_exact_osv_identities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "composer.json").write_text(json.dumps({"require": {"symfony/http-foundation": "5.4.0"}}), encoding="utf-8")
            (root / "composer.lock").write_text(json.dumps({"packages": [{"name": "symfony/http-foundation", "version": "5.4.0"}]}), encoding="utf-8")
            (root / "Gemfile.lock").write_text("GEM\n  specs:\n    rack (2.2.3)\n\nDEPENDENCIES\n  rack\n", encoding="utf-8")
            captured = {}
            def osv(url, payload=None, timeout=10):
                if url.endswith("querybatch"):
                    captured["queries"] = payload["queries"]
                    return {"results": [
                        {"vulns": [{"id": "GHSA-composer-known"}]},
                        {"vulns": [{"id": "GHSA-ruby-known"}]},
                    ]}
                advisory = url.rsplit("/", 1)[-1]
                package = "symfony/http-foundation" if advisory == "GHSA-composer-known" else "rack"
                return {"database_specific": {"severity": "HIGH"}, "affected": [{"package": {"name": package}, "ranges": [{"events": [{"fixed": "9.9.9"}]}]}]}
            with patch("vulcanary.dependencies._json_request", side_effect=osv):
                findings, warning = scan_dependencies(root, cache_dir=False)
            self.assertIsNone(warning)
            self.assertEqual(captured["queries"], [
                {"package": {"name": "symfony/http-foundation", "ecosystem": "Packagist"}, "version": "5.4.0"},
                {"package": {"name": "rack", "ecosystem": "RubyGems"}, "version": "2.2.3"},
            ])
            self.assertEqual({item.metadata["manager"] for item in findings}, {"composer", "bundler"})
            self.assertTrue(all(not item.metadata["fix_eligible"] for item in findings))

    def test_rubygems_stable_fix_wins_over_dot_separated_prerelease(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Gemfile.lock").write_text("GEM\n  specs:\n    demo (1.0.0.beta1)\n\nDEPENDENCIES\n  demo\n", encoding="utf-8")
            batch = {"results": [{"vulns": [{"id": "GHSA-ruby-prerelease"}]}]}
            record = {"affected": [{"package": {"name": "demo"}, "ranges": [
                {"events": [{"fixed": "1.0.0.beta2"}]}, {"events": [{"fixed": "1.0.0"}]},
            ]}]}
            with patch("vulcanary.dependencies._json_request", side_effect=[batch, record]):
                findings, warning = scan_dependencies(root, cache_dir=False)
            self.assertIsNone(warning)
            self.assertEqual(findings[0].metadata["fixed_version"], "1.0.0")

    def test_discovers_pipfile_lock_default_and_development_packages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Pipfile.lock").write_text(json.dumps({
                "default": {"Requests": {"version": "==2.31.0"}},
                "develop": {"PyTest": {"version": "===8.3.1"}},
            }), encoding="utf-8")
            packages = sorted(discover_packages(root), key=lambda item: item.name)
            self.assertEqual([(item.name, item.version, item.manager, item.scope) for item in packages], [
                ("pytest", "8.3.1", "pipenv", "development"),
                ("requests", "2.31.0", "pipenv", "runtime"),
            ])

    def test_requirements_exact_pins_support_extras_and_arbitrary_equality(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text(
                "PyYAML===5.4.1\ncelery [redis]==5.2.0\nrequests==2.31.0 ; python_version >= '3.9'\n",
                encoding="utf-8",
            )
            packages = sorted(discover_packages(root), key=lambda item: item.name)
            self.assertEqual([(item.name, item.version) for item in packages], [
                ("celery", "5.2.0"), ("pyyaml", "5.4.1"), ("requests", "2.31.0"),
            ])

    def test_unpinned_python_requirements_are_reported_as_coverage_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text(
                "requests>=2.20.0\nflask~=2.0.1\nurllib3<2.0,>=1.26\njinja2\n",
                encoding="utf-8",
            )
            findings, warning = scan_dependencies(root, cache_dir=False)
            self.assertEqual(findings, [])
            self.assertIn("4 unpinned Python requirement(s) were not evaluated", warning)
            self.assertIn("requirements.txt:requests", warning)
            self.assertIn("requirements.txt:jinja2", warning)

    def test_pipfile_non_exact_versions_are_reported_not_guessed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Pipfile.lock").write_text(json.dumps({
                "default": {"requests": {"version": ">=2.20"}, "flask": {"git": "https://example.test/flask.git"}},
            }), encoding="utf-8")
            findings, warning = scan_dependencies(root, cache_dir=False)
            self.assertEqual(findings, [])
            self.assertIn("2 unpinned Python requirement(s) were not evaluated", warning)

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
            self.assertTrue(findings[0].metadata["fix_eligible"])
            self.assertEqual(findings[0].metadata["fix_strategy"], "pip")

    def test_osv_uses_cvss_v3_and_v4_base_scores(self) -> None:
        cases = [
            ("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Severity.CRITICAL, 9.8),
            ("CVSS_V4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", Severity.HIGH, 8.7),
        ]
        for kind, vector, expected_severity, expected_score in cases:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "requirements.txt").write_text("demo==1.0.0\n", encoding="utf-8")
                batch = {"results": [{"vulns": [{"id": f"GHSA-{kind.lower()}"}]}]}
                record = {
                    "summary": "CVSS-only advisory", "severity": [{"type": kind, "score": vector}],
                    "affected": [{"package": {"name": "demo"}, "ranges": [{"events": [{"fixed": "1.1.0"}]}]}],
                }
                with patch("vulcanary.dependencies._json_request", side_effect=[batch, record]):
                    findings, warning = scan_dependencies(root, cache_dir=False)
                self.assertIsNone(warning)
                self.assertEqual(findings[0].severity, expected_severity)
                self.assertEqual(findings[0].metadata["cvss"], {"score": expected_score, "vector": vector})

    def test_osv_ignores_withdrawn_advisories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("demo==1.0.0\n", encoding="utf-8")
            batch = {"results": [{"vulns": [{"id": "GHSA-withdrawn"}]}]}
            record = {"withdrawn": "2026-01-01T00:00:00Z", "affected": [{"package": {"name": "demo"}}]}
            with patch("vulcanary.dependencies._json_request", side_effect=[batch, record]):
                findings, warning = scan_dependencies(root, cache_dir=False)
            self.assertIsNone(warning)
            self.assertEqual(findings, [])

    def test_osv_collapses_alias_connected_records_and_unions_fixes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("django==3.2.0\n", encoding="utf-8")
            batch = {"results": [{"vulns": [{"id": "GHSA-django"}, {"id": "PYSEC-django"}]}]}
            vector = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N"
            records = {
                "GHSA-django": {
                    "summary": "Django request vulnerability", "aliases": ["CVE-2026-0001"],
                    "severity": [{"type": "CVSS_V3", "score": vector}],
                    "affected": [{"package": {"name": "django"}, "ranges": [{"events": [{"fixed": "3.2.1"}]}]}],
                },
                "PYSEC-django": {
                    "summary": "Duplicate Python advisory", "aliases": ["CVE-2026-0001"],
                    "affected": [{"package": {"name": "django"}, "ranges": [{"events": [{"fixed": "3.2.2"}]}]}],
                },
            }
            with patch("vulcanary.dependencies._json_request", side_effect=lambda url, payload=None, timeout=10: batch if url.endswith("querybatch") else records[url.rsplit("/", 1)[-1]]):
                findings, warning = scan_dependencies(root, cache_dir=False)
            self.assertIsNone(warning)
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertEqual(finding.rule_id, "SCA-GHSA-django")
            self.assertEqual(finding.severity, Severity.MEDIUM)
            self.assertEqual(finding.metadata["fixed_version"], "3.2.2")
            self.assertEqual(finding.metadata["fixed_version_candidates"], ["3.2.1", "3.2.2"])
            self.assertEqual(finding.metadata["advisories"], ["GHSA-django", "PYSEC-django"])
            self.assertEqual(finding.metadata["aliases"], ["CVE-2026-0001", "GHSA-django", "PYSEC-django"])
            self.assertEqual(finding.metadata["severity_source"], "cvss")
            self.assertEqual(len(finding.metadata["legacy_fingerprints"]), 1)

    def test_osv_alias_groups_are_transitive_and_missing_severity_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("demo==1.0.0\n", encoding="utf-8")
            ids = ["GO-demo", "GHSA-demo", "CVE-record"]
            batch = {"results": [{"vulns": [{"id": item} for item in ids]}]}
            records = {
                "GO-demo": {"aliases": ["CVE-2026-1000"], "affected": [{"package": {"name": "demo"}}]},
                "GHSA-demo": {"aliases": ["CVE-2026-1000", "CVE-2026-2000"], "affected": [{"package": {"name": "demo"}}]},
                "CVE-record": {"aliases": ["CVE-2026-2000"], "affected": [{"package": {"name": "demo"}}]},
            }
            with patch("vulcanary.dependencies._json_request", side_effect=lambda url, payload=None, timeout=10: batch if url.endswith("querybatch") else records[url.rsplit("/", 1)[-1]]):
                findings, warning = scan_dependencies(root, cache_dir=False)
            self.assertIsNone(warning)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, Severity.UNKNOWN)
            self.assertEqual(findings[0].metadata["severity_source"], "unknown")
            self.assertLess(findings[0].severity, Severity.HIGH)
            with patch("vulcanary.dashboard.scan_dependencies", return_value=(findings, None)):
                snapshot = DashboardState().scan_repository(root).to_dict()
            self.assertEqual(snapshot["findings"][0]["metadata"]["policy"]["status"], "unknown")
            self.assertIsNone(snapshot["findings"][0]["metadata"]["policy"]["deadline"])

    def test_dashboard_migrates_alias_fingerprints_without_false_lifecycle_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_primary = Finding("SCA-GHSA-demo", "Demo", "Demo", Severity.MEDIUM, "dependency", "requirements.txt", 1, "demo@1.0.0", scanner="osv")
            old_duplicate = Finding("SCA-PYSEC-demo", "Demo", "Demo", Severity.HIGH, "dependency", "requirements.txt", 1, "demo@1.0.0", scanner="osv")
            merged = Finding(
                "SCA-GHSA-demo", "Demo", "Demo", Severity.MEDIUM, "dependency", "requirements.txt", 1,
                "demo@1.0.0", scanner="osv", metadata={"legacy_fingerprints": [old_duplicate.fingerprint]},
            )
            state = DashboardState()
            with patch("vulcanary.dashboard.scan_dependencies", side_effect=[([old_primary, old_duplicate], None), ([merged], None)]):
                first = state.scan_repository(root)
                first_seen = next(item for item in first.findings if item["fingerprint"] == old_primary.fingerprint)["metadata"]["policy"]["first_seen"]
                second = state.scan_repository(root)
            self.assertEqual(len(second.findings), 1)
            self.assertEqual(second.findings[0]["metadata"]["policy"]["first_seen"], first_seen)
            self.assertEqual(state.monitor_events, [])
            self.assertEqual(state.resolved_findings, [])

    def test_legacy_alias_suppression_still_suppresses_the_merged_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy = Finding("SCA-PYSEC-demo", "Demo", "Demo", Severity.HIGH, "dependency", "requirements.txt", 1, "demo@1.0.0", scanner="osv")
            merged = Finding(
                "SCA-GHSA-demo", "Demo", "Demo", Severity.MEDIUM, "dependency", "requirements.txt", 1,
                "demo@1.0.0", scanner="osv", metadata={"legacy_fingerprints": [legacy.fingerprint]},
            )
            (root / ".vulcanary.json").write_text(json.dumps({"ignored_fingerprints": [legacy.fingerprint]}), encoding="utf-8")
            with patch("vulcanary.dashboard.scan_dependencies", return_value=([merged], None)):
                result = DashboardState().scan_repository(root)
            self.assertFalse(any(finding["category"] == "dependency" for finding in result.findings))
            self.assertEqual([finding["rule_id"] for finding in result.findings], ["GOV-LEGACY-SUPPRESSION"])

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

    def test_osv_selects_compatible_fixed_release_line(self) -> None:
        record = {
            "summary": "Multiple maintained release lines",
            "affected": [{"package": {"name": "demo"}, "ranges": [
                {"events": [{"introduced": "0"}, {"fixed": "4.3.1"}]},
                {"events": [{"introduced": "3.0.0"}, {"fixed": "3.15.2"}]},
            ]}],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package-lock.json").write_text(json.dumps({"packages": {
                "": {"dependencies": {"demo": "^3.13.1"}},
                "node_modules/demo": {"version": "3.15.0"},
            }}), encoding="utf-8")
            with patch("vulcanary.dependencies._json_request", side_effect=[{"results": [{"vulns": [{"id": "GHSA-lines"}]}]}, record]):
                findings, _ = scan_dependencies(root, cache_dir=False)
            self.assertEqual(findings[0].metadata["fixed_version"], "3.15.2")
            self.assertTrue(findings[0].metadata["fix_eligible"])

    def test_osv_prefers_a_stable_fix_over_a_prerelease(self) -> None:
        record = {
            "affected": [{"package": {"name": "demo"}, "ranges": [
                {"events": [{"fixed": "1.2.0-rc.1"}]},
                {"events": [{"fixed": "1.2.0"}]},
            ]}],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("demo==1.0.0\n", encoding="utf-8")
            with patch("vulcanary.dependencies._json_request", side_effect=[{"results": [{"vulns": [{"id": "GHSA-stable"}]}]}, record]):
                findings, _ = scan_dependencies(root, cache_dir=False)
            self.assertEqual(findings[0].metadata["fixed_version"], "1.2.0")

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
