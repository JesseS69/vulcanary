import json
import tempfile
import unittest
from pathlib import Path

from vulcanary.cli import main
from vulcanary.dataflow import analyze_python_dataflow, benchmark_python_score


class DataflowPrototypeTests(unittest.TestCase):
    def test_tracks_request_data_across_same_module_calls_to_eval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def sink(value):\n    return eval(value)\n\n"
                "def middle(value):\n    return sink(value)\n\n"
                "def handler():\n    supplied = request.args.get('value')\n    return middle(supplied)\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root, max_depth=3)
        self.assertEqual(len(report["exposures"]), 1)
        exposure = report["exposures"][0]
        self.assertEqual((exposure["path"], exposure["line"], exposure["confidence"]), ("app.py", 2, "high"))
        self.assertEqual(report["policy_effect"], "none")
        self.assertEqual(report["analysis_truncations"], [])

    def test_sanitizer_is_evidence_not_a_propagation_stop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def handler():\n    value = request.form.get('value')\n    parsed = json.loads(value)\n    return eval(parsed)\n",
                encoding="utf-8",
            )
            exposure = analyze_python_dataflow(root)["exposures"][0]
        self.assertEqual(exposure["confidence"], "lower")
        self.assertEqual(exposure["sanitizers"], ["json.loads"])

    def test_depth_limit_is_reported_instead_of_silently_stopping(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def sink(value):\n    return eval(value)\n\n"
                "def middle(value):\n    return sink(value)\n\n"
                "def handler():\n    return middle(request.GET.get('value'))\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root, max_depth=1)
        self.assertEqual(report["exposures"], [])
        self.assertEqual(report["analysis_truncations"][0]["function"], "sink")

    def test_source_producing_helper_without_tainted_arguments_remains_an_explicit_gap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def get_value():\n    return request.args.get('value')\n\n"
                "def handler():\n    return eval(get_value())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(report["exposures"], [])
        self.assertEqual(report["unmodeled_construct_count"], 1)
        self.assertEqual(report["unmodeled_constructs"][0]["construct"], "unresolved return from get_value")

    def test_external_helper_return_flow_remains_an_explicit_gap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def handler():\n    value = helpers.get_value(request)\n    return eval(value)\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(report["exposures"], [])
        self.assertEqual(report["unmodeled_construct_count"], 1)
        self.assertEqual(report["unmodeled_constructs"][0]["construct"], "unresolved return from helpers.get_value")

    def test_config_parser_return_flow_is_key_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def unsafe():\n"
                "    value = request.form.get('value')\n"
                "    config = configparser.ConfigParser()\n"
                "    config.set('section', 'safe', 'literal')\n"
                "    config.set('section', 'user', value)\n"
                "    eval(config.get('section', 'user'))\n\n"
                "def safe():\n"
                "    value = request.form.get('value')\n"
                "    config = configparser.ConfigParser()\n"
                "    config.set('section', 'safe', 'literal')\n"
                "    config.set('section', 'user', value)\n"
                "    eval(config.get('section', 'safe'))\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([item["line"] for item in report["exposures"]], [6])

    def test_known_request_wrapper_and_encoding_returns_propagate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def handler():\n"
                "    wrapped = helpers.request_wrapper(request)\n"
                "    value = wrapped.get_query_parameter('value')\n"
                "    encoded = base64.b64encode(value.encode('utf-8'))\n"
                "    decoded = base64.b64decode(encoded).decode('utf-8')\n"
                "    exec(decoded)\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(len(report["exposures"]), 1)
        self.assertEqual(report["unmodeled_construct_count"], 0)

    def test_taint_propagates_through_container_subscripts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def handler():\n"
                "    values = []\n"
                "    values.append(request.args.get('value'))\n"
                "    exec(values[0])\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(len(report["exposures"]), 1)
        self.assertEqual(report["exposures"][0]["line"], 4)

    def test_fingerprint_is_anchored_to_sink_not_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app.py"
            target.write_text("def handler():\n    value = request.args.get('a')\n    return eval(value)\n", encoding="utf-8")
            first = analyze_python_dataflow(root)["exposures"][0]["fingerprint"]
            target.write_text("def handler():\n    value = request.form.get('b')\n    return eval(value)\n", encoding="utf-8")
            second = analyze_python_dataflow(root)["exposures"][0]["fingerprint"]
        self.assertEqual(first, second)

    def test_scores_benchmarkpython_cwe_94_with_tpr_minus_fpr(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            expected = Path(directory) / "expectedresults-0.1.csv"
            expected.write_text(
                "# test name, category, real vulnerability, cwe\n"
                "BenchmarkTest00001,codeinj,true,94\n"
                "BenchmarkTest00002,codeinj,false,94\n"
                "BenchmarkTest00003,pathtraver,true,22\n",
                encoding="utf-8",
            )
            score = benchmark_python_score({"exposures": [{"path": "BenchmarkTest00001.py"}]}, expected)
        self.assertEqual(score["true_positives"], 1)
        self.assertEqual(score["true_negatives"], 1)
        self.assertEqual(score["benchmark_score"], 1.0)

    def test_cli_writes_separate_experimental_report_and_never_gates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "report.json"
            (root / "app.py").write_text("eval(request.args.get('value'))\n", encoding="utf-8")
            exit_code = main(["dataflow-prototype", str(root), "--json", str(destination)])
            document = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(exit_code, 0)
        self.assertEqual(document["schema"], "vulcanary.experimental-dataflow.v1")
        self.assertEqual(document["policy_effect"], "none")
        self.assertEqual(document["unmodeled_construct_count"], 0)


if __name__ == "__main__":
    unittest.main()
