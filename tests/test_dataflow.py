import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vulcanary.cli import main
from vulcanary.dataflow import analyze_python_dataflow, benchmark_python_score


class DataflowPrototypeTests(unittest.TestCase):
    def test_nested_closures_surface_captured_taint_without_flagging_clean_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def handler():\n"
                "    value = request.args.get('value')\n"
                "    def callback():\n"
                "        return eval(value)\n"
                "    return callback()\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(report["exposures"], [])
        self.assertEqual(
            [(item["category"], item["sink_line"]) for item in report["unmodeled_constructs"]],
            [("unsupported_closure", 4)],
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def handler():\n"
                "    value = 'safe'\n"
                "    def callback():\n"
                "        return eval(value)\n"
                "    return callback()\n",
                encoding="utf-8",
            )
            clean = analyze_python_dataflow(root)
        self.assertEqual(clean["exposures"], [])
        self.assertEqual(clean["unmodeled_constructs"], [])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def handler():\n"
                "    value = request.args.get('value')\n"
                "    def callback():\n"
                "        value = 'shadowed-safe'\n"
                "        return eval(value)\n"
                "    return callback()\n",
                encoding="utf-8",
            )
            shadowed = analyze_python_dataflow(root)
        self.assertEqual(shadowed["exposures"], [])
        self.assertEqual(shadowed["unmodeled_constructs"], [])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def handler():\n"
                "    value = request.args.get('value')\n"
                "    def decorator():\n"
                "        def callback():\n"
                "            return eval(value)\n"
                "        return callback\n"
                "    return decorator()()\n",
                encoding="utf-8",
            )
            nested = analyze_python_dataflow(root)
        self.assertEqual(nested["exposures"], [])
        self.assertEqual(
            [(item["category"], item["construct"], item["sink_line"]) for item in nested["unmodeled_constructs"]],
            [("unsupported_closure", "nested function callback may carry captured taint", 5)],
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def handler():\n"
                "    value = 'safe'\n"
                "    def decorator():\n"
                "        def callback():\n"
                "            return eval(value)\n"
                "        return callback\n"
                "    return decorator()()\n",
                encoding="utf-8",
            )
            clean_nested = analyze_python_dataflow(root)
        self.assertEqual(clean_nested["exposures"], [])
        self.assertEqual(clean_nested["unmodeled_constructs"], [])

    def test_unsupported_statement_forms_surface_taint_analysis_gaps(self) -> None:
        cases = {
            "named_expression": (
                "if value := request.args.get('value'):\n    pass\neval(value)\n",
                "unsupported_named_expression",
            ),
            "unpacking": (
                "pair = (request.args.get('value'), 'safe')\nvalue, other = pair\neval(value)\n",
                "unsupported_unpacking",
            ),
            "match": (
                "value = request.args.get('value')\n"
                "match 'A':\n"
                "    case 'A':\n"
                "        result = value\n"
                "    case _:\n"
                "        result = 'safe'\n"
                "eval(result)\n",
                "unsupported_match",
            ),
        }
        for name, (source, category) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "app.py").write_text(source, encoding="utf-8")
                report = analyze_python_dataflow(root)
            self.assertIn(category, {item["category"] for item in report["unmodeled_constructs"]})

    def test_augmented_assignments_propagate_taint_and_visit_nested_sinks(self) -> None:
        cases = {
            "augmented_sink": "value = request.args.get('value')\nresult = ''\nresult += eval(value)\n",
            "augmented_value": "value = ''\nvalue += request.args.get('value')\neval(value)\n",
            "attribute_augmented_value": (
                "class Handler:\n"
                "    def run(self):\n"
                "        self.value = ''\n"
                "        self.value += request.args.get('value')\n"
                "        return eval(self.value)\n"
            ),
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "app.py").write_text(source, encoding="utf-8")
                report = analyze_python_dataflow(root)
            self.assertEqual(len(report["exposures"]), 1)
            self.assertFalse(
                any(item["category"].startswith("unsupported_augmented") for item in report["unmodeled_constructs"])
            )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("value = 'safe'\nvalue += '-still-safe'\neval(value)\n", encoding="utf-8")
            clean = analyze_python_dataflow(root)
        self.assertEqual(clean["exposures"], [])

    def test_loop_targets_and_comprehensions_propagate_taint(self) -> None:
        cases = {
            "for": "for value in request.args.getlist('value'):\n    eval(value)\n",
            "async_for": "async def run():\n    async for value in request.args.getlist('value'):\n        eval(value)\n",
            "list_comprehension": "values = request.args.getlist('value')\n[eval(value) for value in values]\n",
            "generator": "values = request.args.getlist('value')\ntuple(eval(value) for value in values)\n",
            "query_string": "value = request.query_string.decode('utf-8')\neval(value)\n",
        }
        for name, source in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "app.py").write_text(source, encoding="utf-8")
                report = analyze_python_dataflow(root)
            self.assertEqual(len(report["exposures"]), 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "for value in ['safe']:\n    eval(value)\n[eval(value) for value in ['safe']]\n",
                encoding="utf-8",
            )
            clean = analyze_python_dataflow(root)
        self.assertEqual(clean["exposures"], [])

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

    def test_source_producing_helper_return_is_resolved_without_tainted_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def get_value():\n    return request.args.get('value')\n\n"
                "def handler():\n    return eval(get_value())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(len(report["exposures"]), 1)
        self.assertEqual(report["exposures"][0]["line"], 5)
        self.assertEqual(report["unmodeled_construct_count"], 0)

    def test_source_return_resolves_across_three_same_module_functions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def source():\n    return request.args.get('value')\n\n"
                "def middle():\n    return source()\n\n"
                "def outer():\n    return middle()\n\n"
                "def handler():\n    return eval(outer())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root, max_depth=3)
            truncated = analyze_python_dataflow(root, max_depth=2)
        self.assertEqual(len(report["exposures"]), 1)
        self.assertEqual(report["analysis_truncations"], [])
        self.assertEqual(truncated["exposures"], [])
        self.assertEqual(truncated["analysis_truncations"][0]["function"], "source")
        self.assertEqual(truncated["unmodeled_construct_count"], 1)
        self.assertEqual(truncated["unmodeled_constructs"][0]["category"], "depth_limit")

    def test_recursive_source_helper_is_bounded_and_reported_as_unmodeled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def get_value():\n    return get_value()\n\n"
                "def handler():\n    return eval(get_value())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(report["exposures"], [])
        self.assertEqual(report["analysis_truncations"], [])
        self.assertEqual(report["unmodeled_construct_count"], 1)
        self.assertEqual(report["unmodeled_constructs"][0]["category"], "unresolved_call")

    def test_tainted_recursion_fires_recursion_cycle_category(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def recurse(value):\n    return recurse(value)\n\n"
                "def handler():\n    return eval(recurse(request.args.get('value')))\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(len(report["exposures"]), 1)
        self.assertEqual(report["unmodeled_constructs"][0]["category"], "recursion_cycle")
        self.assertEqual(report["analysis_truncations"][0]["function"], "recurse")

    def test_module_call_and_time_limits_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.py").write_text("eval(request.args.get('a'))\n", encoding="utf-8")
            (root / "b.py").write_text("eval(request.args.get('b'))\n", encoding="utf-8")
            module_limited = analyze_python_dataflow(root, max_modules=1)
            call_limited = analyze_python_dataflow(root, max_calls=1)
            with patch("vulcanary.dataflow.time.monotonic", side_effect=[0.0, 2.0]):
                time_limited = analyze_python_dataflow(root, timeout_seconds=1.0)
        self.assertEqual(module_limited["analysis_limits"][0]["category"], "module_limit")
        self.assertEqual(module_limited["analyzed_modules"], 1)
        self.assertEqual(call_limited["analysis_limits"][0]["category"], "call_limit")
        self.assertEqual(call_limited["analyzed_calls"], 1)
        self.assertEqual(time_limited["analysis_limits"][0]["category"], "time_limit")
        self.assertEqual(time_limited["analyzed_modules"], 0)

    def test_trivially_static_helper_return_does_not_dilute_gap_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def clean_helper():\n    return 'fixed literal'\n\n"
                "def handler():\n    return eval(clean_helper())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(report["exposures"], [])
        self.assertEqual(report["unmodeled_constructs"], [])

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
        self.assertEqual(report["unmodeled_constructs"][0]["category"], "dynamic_dispatch")

    def test_resolves_repository_local_imported_function_returns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "helpers.py").write_text(
                "def get_value():\n    return request.args.get('value')\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "import helpers as h\nfrom helpers import get_value as direct\n\n"
                "def first():\n    eval(h.get_value())\n\n"
                "def second():\n    exec(direct())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([item["line"] for item in report["exposures"]], [5, 8])
        self.assertFalse(any(item["category"] == "cross_module_call" for item in report["unmodeled_constructs"]))

    def test_resolves_repository_local_imported_object_methods_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "helpers.py").write_text(
                "raise RuntimeError('scanned code executed')\n\n"
                "class Reader:\n"
                "    def value(self):\n"
                "        return request.headers.get('X-Value')\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from helpers import Reader\n\n"
                "def handler():\n"
                "    reader = Reader()\n"
                "    return eval(reader.value())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([(item["path"], item["line"]) for item in report["exposures"]], [("app.py", 5)])
        self.assertFalse(any(item["category"] == "dynamic_dispatch" for item in report["unmodeled_constructs"]))

    def test_resolves_local_and_module_aliased_object_methods(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "helpers.py").write_text(
                "class Reader:\n    def value(self):\n        return request.cookies.get('value')\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "import helpers as h\n\nclass LocalReader:\n"
                "    def value(self):\n        return request.args.get('value')\n\n"
                "eval(LocalReader().value())\nreader = h.Reader()\nexec(reader.value())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([(item["path"], item["line"]) for item in report["exposures"]], [("app.py", 7), ("app.py", 9)])

    def test_resolves_objects_stored_on_instance_attributes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "helpers.py").write_text(
                "raise RuntimeError('scanned code executed')\n\n"
                "class Reader:\n"
                "    def read(self):\n"
                "        return request.headers.get('X-Value')\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from helpers import Reader\n\n"
                "class Handler:\n"
                "    def __init__(self):\n"
                "        self.reader = Reader()\n"
                "    def handle(self):\n"
                "        return eval(self.reader.read())\n\n"
                "Handler().handle()\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([(item["path"], item["line"]) for item in report["exposures"]], [("app.py", 7)])
        self.assertFalse(any(item["category"] == "dynamic_dispatch" for item in report["unmodeled_constructs"]))

    def test_propagates_tainted_values_through_instance_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "class Handler:\n"
                "    def __init__(self, value):\n"
                "        self.value = value\n"
                "    def read(self):\n"
                "        return self.value\n\n"
                "handler = Handler(request.args.get('value'))\n"
                "exec(handler.read())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([(item["path"], item["line"]) for item in report["exposures"]], [("app.py", 8)])
        self.assertFalse(any(item["category"] == "dynamic_dispatch" for item in report["unmodeled_constructs"]))

    def test_instance_state_mutation_is_tracked_without_tainting_clean_returns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "class Handler:\n"
                "    def store(self, value):\n"
                "        self.value = value\n"
                "        return 'constant'\n"
                "    def execute(self, value):\n"
                "        self.store(value)\n"
                "        return eval(self.value)\n"
                "    def clean(self):\n"
                "        return 'constant'\n\n"
                "handler = Handler()\n"
                "handler.execute(request.form.get('value'))\n"
                "exec(handler.clean())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([(item["path"], item["line"]) for item in report["exposures"]], [("app.py", 7)])

    def test_self_method_state_mutation_reaches_a_later_method(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "class Handler:\n"
                "    def store(self):\n"
                "        self.value = request.args.get('value')\n"
                "    def prepare(self):\n"
                "        self.store()\n"
                "    def consume(self):\n"
                "        return eval(self.value)\n\n"
                "handler = Handler()\n"
                "handler.prepare()\n"
                "handler.consume()\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([(item["path"], item["line"]) for item in report["exposures"]], [("app.py", 7)])
        self.assertFalse(report["unmodeled_constructs"])

    def test_instance_alias_mutation_updates_the_original_receiver(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "class Holder:\n"
                "    def __init__(self):\n"
                "        self.value = 'clean'\n"
                "    def store(self, value):\n"
                "        self.value = value\n"
                "    def consume(self):\n"
                "        return eval(self.value)\n\n"
                "holder = Holder()\n"
                "alias = holder\n"
                "alias.store(request.args.get('value'))\n"
                "holder.consume()\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([item["line"] for item in report["exposures"]], [7])

    def test_nested_instance_alias_mutation_flows_back_to_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "class Reader:\n"
                "    def store(self, value):\n"
                "        self.value = value\n"
                "    def read(self):\n"
                "        return self.value\n\n"
                "class Handler:\n"
                "    def __init__(self):\n"
                "        self.reader = Reader()\n"
                "    def consume(self):\n"
                "        return exec(self.reader.read())\n\n"
                "handler = Handler()\n"
                "alias = handler.reader\n"
                "alias.store(request.form.get('value'))\n"
                "handler.consume()\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([item["line"] for item in report["exposures"]], [11])

    def test_instance_aliases_do_not_conflate_separate_allocations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "class Holder:\n"
                "    def __init__(self):\n"
                "        self.value = 'clean'\n"
                "    def store(self, value):\n"
                "        self.value = value\n"
                "    def consume(self):\n"
                "        return eval(self.value)\n\n"
                "first = Holder()\n"
                "second = Holder()\n"
                "alias = first\n"
                "alias.store(request.args.get('value'))\n"
                "second.consume()\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(report["exposures"], [])

    def test_truncated_constructor_state_is_not_reused_from_cache(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "class Holder:\n"
                "    def __init__(self):\n"
                "        self.value = request.args.get('value')\n"
                "    def consume(self):\n"
                "        return eval(self.value)\n\n"
                "def nested(value):\n"
                "    return Holder()\n\n"
                "nested(request.form.get('trigger'))\n"
                "direct = Holder()\n"
                "direct.consume()\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root, max_depth=1)
        self.assertEqual([item["line"] for item in report["exposures"]], [5])
        self.assertTrue(any(item["function"].endswith("Holder.__init__") for item in report["analysis_truncations"]))

    def test_inherited_constructor_and_method_propagate_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "class Base:\n"
                "    def __init__(self):\n"
                "        self.value = request.args.get('value')\n"
                "    def consume(self):\n"
                "        return eval(self.value)\n\n"
                "class Child(Base):\n"
                "    pass\n\n"
                "Child().consume()\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([item["line"] for item in report["exposures"]], [5])
        self.assertFalse(report["unmodeled_constructs"])

    def test_imported_base_is_resolved_without_executing_scanned_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "base.py").write_text(
                "raise RuntimeError('scanned code executed')\n\n"
                "class Base:\n"
                "    def read(self):\n"
                "        return request.args.get('value')\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from base import Base\n\n"
                "class Child(Base):\n"
                "    def read(self):\n"
                "        return super().read()\n\n"
                "eval(Child().read())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(
            [(item["path"], item["line"]) for item in report["exposures"]],
            [("app.py", 7)],
        )
        self.assertFalse(report["unmodeled_constructs"])

    def test_clean_child_override_wins_over_tainted_parent_method(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "class Base:\n"
                "    def value(self):\n"
                "        return request.args.get('value')\n\n"
                "class Child(Base):\n"
                "    def value(self):\n"
                "        return 'clean'\n\n"
                "eval(Child().value())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(report["exposures"], [])

    def test_multiple_inheritance_is_an_explicit_gap_instead_of_a_guess(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "class Left:\n"
                "    def value(self):\n"
                "        return request.args.get('left')\n\n"
                "class Right:\n"
                "    def value(self):\n"
                "        return 'clean'\n\n"
                "class Child(Left, Right):\n"
                "    pass\n\n"
                "eval(Child().value())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(report["exposures"], [])
        self.assertEqual(report["unmodeled_constructs"][0]["category"], "ambiguous_inheritance")

    def test_inheritance_cycle_is_bounded_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "class First(Second):\n"
                "    pass\n\n"
                "class Second(First):\n"
                "    pass\n\n"
                "eval(First().value())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(report["exposures"], [])
        self.assertEqual(report["unmodeled_constructs"][0]["category"], "inheritance_cycle")

    def test_missing_external_base_and_generic_marker_are_distinguished(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "from typing import Generic, TypeVar\n"
                "from framework import ExternalBase\n\n"
                "T = TypeVar('T')\n\n"
                "class GenericChild(Generic[T]):\n"
                "    def value(self):\n"
                "        return request.args.get('value')\n\n"
                "class ExternalChild(ExternalBase):\n"
                "    pass\n\n"
                "eval(GenericChild().value())\n"
                "eval(ExternalChild().value())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([item["line"] for item in report["exposures"]], [13])
        self.assertEqual(
            {item["category"] for item in report["unmodeled_constructs"]},
            {"missing_base"},
        )

    def test_zero_argument_super_resolves_parent_return(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "class Base:\n"
                "    def value(self, supplied):\n"
                "        return supplied\n\n"
                "class Child(Base):\n"
                "    def value(self):\n"
                "        return super().value(request.args.get('value'))\n\n"
                "eval(Child().value())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([item["line"] for item in report["exposures"]], [9])
        self.assertFalse(report["unmodeled_constructs"])

    def test_super_method_mutation_updates_child_instance_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "class Base:\n"
                "    def store(self, value):\n"
                "        self.value = value\n\n"
                "class Child(Base):\n"
                "    def store(self, value):\n"
                "        super().store(value)\n"
                "    def consume(self):\n"
                "        return eval(self.value)\n\n"
                "child = Child()\n"
                "child.store(request.form.get('value'))\n"
                "child.consume()\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([item["line"] for item in report["exposures"]], [9])
        self.assertFalse(report["unmodeled_constructs"])

    def test_cross_file_super_mutation_updates_child_instance_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "base.py").write_text(
                "raise RuntimeError('scanned code executed')\n\n"
                "class Base:\n"
                "    def load(self):\n"
                "        self.data = request.args.get('value')\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from base import Base\n\n"
                "class Child(Base):\n"
                "    def load(self):\n"
                "        super().load()\n"
                "    def consume(self):\n"
                "        return eval(self.data)\n\n"
                "child = Child()\n"
                "child.load()\n"
                "child.consume()\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(
            [(item["path"], item["line"]) for item in report["exposures"]],
            [("app.py", 7)],
        )
        self.assertEqual(
            {item["category"] for item in report["unmodeled_constructs"]},
            {"cross_module_inherited_state"},
        )

    def test_cross_file_super_mutation_reaches_sink_in_same_method(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "base.py").write_text(
                "class Base:\n"
                "    def load(self):\n"
                "        self.data = request.args.get('value')\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "import base\n\n"
                "class Child(base.Base):\n"
                "    def consume(self):\n"
                "        super().load()\n"
                "        return eval(self.data)\n\n"
                "Child().consume()\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(
            [(item["path"], item["line"]) for item in report["exposures"]],
            [("app.py", 6)],
        )
        self.assertEqual(
            {item["category"] for item in report["unmodeled_constructs"]},
            {"cross_module_inherited_state"},
        )

    def test_cross_file_super_mutation_propagates_tainted_argument(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "base.py").write_text(
                "class Base:\n"
                "    def load(self, value):\n"
                "        self.data = value\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from base import Base\n\n"
                "class Child(Base):\n"
                "    def load(self, value):\n"
                "        super().load(value)\n"
                "    def consume(self):\n"
                "        return eval(self.data)\n\n"
                "child = Child()\n"
                "child.load(request.form.get('value'))\n"
                "child.consume()\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(
            [(item["path"], item["line"]) for item in report["exposures"]],
            [("app.py", 7)],
        )
        self.assertEqual(
            {item["category"] for item in report["unmodeled_constructs"]},
            {"cross_module_inherited_state"},
        )

    def test_plain_cross_file_inherited_mutation_is_never_silent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "base.py").write_text(
                "class Base:\n"
                "    def load(self):\n"
                "        self.data = request.args.get('value')\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from base import Base\n\n"
                "class Child(Base):\n"
                "    def consume(self):\n"
                "        return eval(self.data)\n\n"
                "child = Child()\n"
                "child.load()\n"
                "child.consume()\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([item["line"] for item in report["exposures"]], [5])
        self.assertEqual(
            {item["category"] for item in report["unmodeled_constructs"]},
            {"cross_module_inherited_state"},
        )

    def test_cross_file_inherited_state_survives_local_function_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "base.py").write_text(
                "class Base:\n"
                "    def load(self, value):\n"
                "        self.data = value\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from base import Base\n\n"
                "class Child(Base):\n"
                "    def consume(self):\n"
                "        return eval(self.data)\n\n"
                "def handler():\n"
                "    child = Child()\n"
                "    child.load(request.args.get('value'))\n"
                "    return child.consume()\n\n"
                "handler()\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([item["line"] for item in report["exposures"]], [5])
        self.assertEqual(
            {item["category"] for item in report["unmodeled_constructs"]},
            {"cross_module_inherited_state"},
        )

    def test_unresolved_cross_file_inherited_attribute_at_sink_is_never_silent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "base.py").write_text("class Base:\n    pass\n", encoding="utf-8")
            (root / "app.py").write_text(
                "from base import Base\n\n"
                "class Child(Base):\n"
                "    def consume(self):\n"
                "        return eval(self.data)\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(report["exposures"], [])
        self.assertEqual(
            {item["category"] for item in report["unmodeled_constructs"]},
            {"cross_module_inherited_state"},
        )

    def test_uninvoked_child_method_with_inherited_state_sink_is_never_silent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "base.py").write_text(
                "class Base:\n"
                "    def load(self):\n"
                "        self.data = request.args.get('value')\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from base import Base\n\n"
                "class Child(Base):\n"
                "    def load_data(self):\n"
                "        self.load()\n"
                "    def consume(self):\n"
                "        return eval(self.data)\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertTrue(
            report["exposures"] or any(
                item["category"] == "cross_module_inherited_state"
                for item in report["unmodeled_constructs"]
            )
        )

    def test_plain_inherited_mutation_reaches_read_in_same_child_method(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "base.py").write_text(
                "class Base:\n"
                "    def load(self, value):\n"
                "        self.data = value\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from base import Base\n\n"
                "class Child(Base):\n"
                "    def run(self):\n"
                "        self.load(request.args.get('value'))\n"
                "        return eval(self.data)\n\n"
                "Child().run()\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([item["line"] for item in report["exposures"]], [6])
        self.assertEqual(
            {item["category"] for item in report["unmodeled_constructs"]},
            {"cross_module_inherited_state"},
        )

    def test_plain_inherited_mutation_reaches_different_child_method(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "base.py").write_text(
                "class Base:\n"
                "    def load(self, value):\n"
                "        self.data = value\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from base import Base\n\n"
                "class Child(Base):\n"
                "    def consume(self):\n"
                "        return eval(self.data)\n"
                "    def run(self):\n"
                "        self.load(request.args.get('value'))\n"
                "        return self.consume()\n\n"
                "Child().run()\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([item["line"] for item in report["exposures"]], [5])
        self.assertEqual(
            {item["category"] for item in report["unmodeled_constructs"]},
            {"cross_module_inherited_state"},
        )

    def test_cross_file_super_call_does_not_taint_clean_child_return(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "base.py").write_text(
                "class Base:\n"
                "    def read(self):\n"
                "        return request.args.get('value')\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from base import Base\n\n"
                "class Child(Base):\n"
                "    def read(self):\n"
                "        super().read()\n"
                "        return 'clean'\n\n"
                "eval(Child().read())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(report["exposures"], [])
        self.assertFalse(report["unmodeled_constructs"])

    def test_super_with_multiple_bases_is_an_explicit_gap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "class Left:\n"
                "    def value(self, supplied):\n"
                "        return supplied\n\n"
                "class Right:\n"
                "    def value(self, supplied):\n"
                "        return 'clean'\n\n"
                "class Child(Left, Right):\n"
                "    def value(self):\n"
                "        return super().value(request.args.get('value'))\n\n"
                "eval(Child().value())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([item["line"] for item in report["exposures"]], [13])
        self.assertEqual(
            {item["category"] for item in report["unmodeled_constructs"]},
            {"ambiguous_inheritance"},
        )

    def test_explicit_argument_super_remains_an_explicit_gap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "class Base:\n"
                "    def value(self, supplied):\n"
                "        return supplied\n\n"
                "class Child(Base):\n"
                "    def value(self):\n"
                "        return super(Child, self).value(request.args.get('value'))\n\n"
                "eval(Child().value())\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([item["line"] for item in report["exposures"]], [9])
        self.assertEqual(
            {item["category"] for item in report["unmodeled_constructs"]},
            {"dynamic_dispatch"},
        )

    def test_unknown_receiver_method_remains_an_explicit_dynamic_dispatch_gap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def handler(runtime):\n    return eval(runtime.value(request.args.get('value')))\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(len(report["exposures"]), 1)
        self.assertEqual(report["unmodeled_constructs"][0]["category"], "dynamic_dispatch")

    def test_static_and_class_methods_are_honest_unsupported_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "helpers.py").write_text(
                "class Reader:\n"
                "    @staticmethod\n    def static(value):\n        return value\n"
                "    @classmethod\n    def class_value(cls, value):\n        return value\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from helpers import Reader\n"
                "eval(Reader.static(request.args.get('a')))\n"
                "exec(Reader.class_value(request.args.get('b')))\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(
            [item["category"] for item in report["unmodeled_constructs"]],
            ["unsupported_method_kind", "unsupported_method_kind"],
        )

    def test_class_methods_remain_in_the_independent_analysis_workload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "class Handler:\n"
                "    def run(self):\n"
                "        value = request.args.get('value')\n"
                "        return eval(value)\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual([(item["path"], item["line"]) for item in report["exposures"]], [("app.py", 4)])

    def test_resolves_package_relative_import_and_bounds_cross_module_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "package"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "source.py").write_text(
                "from .cycle import again\n\ndef value():\n    return request.form.get('value')\n\n"
                "def recurse(value):\n    return again(value)\n",
                encoding="utf-8",
            )
            (package / "cycle.py").write_text(
                "from .source import recurse\n\ndef again(value):\n    return recurse(value)\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from package.source import value, recurse\n\neval(value())\nexec(recurse(request.args.get('x')))\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root, max_depth=6)
        self.assertEqual([item["line"] for item in report["exposures"] if item["path"] == "app.py"], [3, 4])
        self.assertTrue(any(item["category"] == "recursion_cycle" for item in report["unmodeled_constructs"]))

    def test_resolves_package_initializer_and_imported_submodule(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); package = root / "package"; package.mkdir()
            (package / "__init__.py").write_text("from .source import value\n\ndef exported():\n    return value()\n", encoding="utf-8")
            (package / "source.py").write_text("def value():\n    return request.args.get('value')\n", encoding="utf-8")
            (root / "app.py").write_text("import package\nfrom package import source\n\neval(package.exported())\nexec(source.value())\n", encoding="utf-8")
            report = analyze_python_dataflow(root)
        self.assertEqual([item["line"] for item in report["exposures"] if item["path"] == "app.py"], [4, 5])

    def test_index_distinguishes_missing_modules_and_missing_symbols(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "helpers.py").write_text("def known(value):\n    return value\n", encoding="utf-8")
            (root / "app.py").write_text(
                "import absent\nfrom helpers import absent as missing_symbol\n\n"
                "eval(absent.value(request.args.get('a')))\nexec(missing_symbol(request.args.get('b')))\n", encoding="utf-8")
            report = analyze_python_dataflow(root)
        self.assertEqual({item["category"] for item in report["unmodeled_constructs"]}, {"missing_module", "ambiguous_symbol"})

    def test_imported_calls_are_distinct_from_dynamic_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "import helpers as h\n"
                "from transforms import clean\n\n"
                "def handler():\n"
                "    value = request.args.get('value')\n"
                "    eval(h.clean(value))\n"
                "    exec(clean(value))\n"
                "    eval(runtime.clean(value))\n",
                encoding="utf-8",
            )
            report = analyze_python_dataflow(root)
        self.assertEqual(
            sorted(item["category"] for item in report["unmodeled_constructs"]),
            ["dynamic_dispatch", "missing_module", "missing_module"],
        )

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
