from __future__ import annotations

import ast
import csv
import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .models import relative_path
from .scanners import iter_files


@dataclass(frozen=True)
class _Taint:
    sources: tuple[str, ...] = ()
    sanitizers: tuple[str, ...] = ()
    unmodeled: tuple[str, ...] = ()

    def merge(self, other: "_Taint") -> "_Taint":
        return _Taint(
            tuple(dict.fromkeys(self.sources + other.sources)),
            tuple(dict.fromkeys(self.sanitizers + other.sanitizers)),
            tuple(dict.fromkeys(self.unmodeled + other.unmodeled)),
        )


@dataclass
class _AnalysisBudget:
    max_calls: int
    deadline: float
    calls: int = 0
    time_exhausted: bool = False
    call_exhausted: bool = False

    def consume_call(self) -> str | None:
        if time.monotonic() >= self.deadline:
            self.time_exhausted = True
            return "time_limit"
        if self.calls >= self.max_calls:
            self.call_exhausted = True
            return "call_limit"
        self.calls += 1
        return None


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _source(node: ast.AST) -> str | None:
    target = node.func if isinstance(node, ast.Call) else node.value if isinstance(node, ast.Subscript) else node
    name = _name(target)
    if name in {"input", "request.get_json"}:
        return name
    if name.startswith(("request.args", "request.form", "request.cookies", "request.headers", "request.values", "request.GET", "request.POST", "request.data", "request.json")):
        return name
    if name.endswith((".get_form_parameter", ".get_query_parameter", ".get_cookie")):
        return name
    return None


def _subscript_key(node: ast.Subscript) -> str | None:
    if isinstance(node.value, ast.Name) and isinstance(node.slice, ast.Constant):
        return f"{node.value.id}[{node.slice.value!r}]"
    return None


def _static_expression(node: ast.AST | None) -> bool:
    if node is None or isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_static_expression(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(_static_expression(item) for item in (*node.keys, *node.values))
    if isinstance(node, ast.UnaryOp):
        return _static_expression(node.operand)
    if isinstance(node, ast.BinOp):
        return _static_expression(node.left) and _static_expression(node.right)
    if isinstance(node, ast.BoolOp):
        return all(_static_expression(item) for item in node.values)
    if isinstance(node, ast.Compare):
        return _static_expression(node.left) and all(_static_expression(item) for item in node.comparators)
    if isinstance(node, ast.JoinedStr):
        return all(_static_expression(item.value) if isinstance(item, ast.FormattedValue) else _static_expression(item) for item in node.values)
    return False


def _returns_only_static(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    returns: list[ast.Return] = []

    class Visitor(ast.NodeVisitor):
        def visit_Return(self, node: ast.Return) -> None:
            returns.append(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node is function:
                self.generic_visit(node)

        visit_AsyncFunctionDef = visit_FunctionDef

    Visitor().visit(function)
    return all(_static_expression(item.value) for item in returns)


def _gap(category: str, construct: str) -> str:
    return f"{category}\0{construct}"


def _split_gap(value: str) -> tuple[str, str]:
    return tuple(value.split("\0", 1)) if "\0" in value else ("unclassified", value)


def _source_capable_functions(tree: ast.Module) -> set[str]:
    direct: set[str] = set()
    calls: dict[str, set[str]] = {}

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.stack: list[str] = []

        def visit(self, node: ast.AST) -> None:
            if self.stack and _source(node):
                direct.add(self.stack[-1])
            if self.stack and isinstance(node, ast.Call):
                calls.setdefault(self.stack[-1], set()).add(_name(node.func))
            super().visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

    Visitor().visit(tree)
    capable = set(direct)
    changed = True
    while changed:
        changed = False
        for name, callees in calls.items():
            if name not in capable and callees & capable:
                capable.add(name)
                changed = True
    return capable


def _import_bindings(tree: ast.Module) -> tuple[set[str], set[str]]:
    modules: set[str] = set()
    symbols: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.asname or alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            symbols.update(alias.asname or alias.name for alias in node.names if alias.name != "*")
    return modules, symbols


class _ModuleAnalyzer:
    def __init__(self, path: str, tree: ast.Module, max_depth: int, budget: _AnalysisBudget) -> None:
        self.path = path
        self.max_depth = max_depth
        self.functions = {node.name: node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.source_functions = _source_capable_functions(tree)
        self.imported_modules, self.imported_symbols = _import_bindings(tree)
        self.budget = budget
        self.exposures: dict[str, dict] = {}
        self.truncations: set[tuple[str, int]] = set()
        self.unmodeled_constructs: set[tuple[str, int, int]] = set()

    def expression(self, node: ast.AST | None, env: dict[str, _Taint], depth: int, stack: tuple[str, ...]) -> _Taint:
        if node is None:
            return _Taint()
        source = _source(node)
        if source:
            return _Taint((f"{source}@{getattr(node, 'lineno', 0)}",))
        if isinstance(node, ast.Name):
            return env.get(node.id, _Taint())
        if isinstance(node, ast.Subscript):
            key = _subscript_key(node)
            return env[key] if key and key in env else self.expression(node.value, env, depth, stack)
        if isinstance(node, ast.Call):
            if limit := self.budget.consume_call():
                return _Taint(unmodeled=(_gap(limit, f"analysis stopped at {limit}"),))
            function_name = _name(node.func)
            argument_taints = [self.expression(item, env, depth, stack) for item in (*node.args, *(item.value for item in node.keywords))]
            combined = _Taint()
            for item in argument_taints:
                combined = combined.merge(item)
            receiver_name = _name(node.func.value) if isinstance(node.func, ast.Attribute) else ""
            receiver_taint = self.expression(node.func.value, env, depth, stack) if isinstance(node.func, ast.Attribute) else _Taint()
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"encode", "decode"}:
                return combined.merge(receiver_taint)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "set" and len(node.args) >= 3:
                section = node.args[0].value if isinstance(node.args[0], ast.Constant) else None
                option = node.args[1].value if isinstance(node.args[1], ast.Constant) else None
                if receiver_name and isinstance(section, str) and isinstance(option, str):
                    env[f"{receiver_name}.config[{section!r},{option!r}]"] = argument_taints[2]
                    return _Taint()
            if isinstance(node.func, ast.Attribute) and node.func.attr == "get" and len(node.args) >= 2:
                section = node.args[0].value if isinstance(node.args[0], ast.Constant) else None
                option = node.args[1].value if isinstance(node.args[1], ast.Constant) else None
                key = f"{receiver_name}.config[{section!r},{option!r}]"
                if receiver_name and isinstance(section, str) and isinstance(option, str) and key in env:
                    return env[key]
            if function_name.endswith(".append") and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                container = node.func.value.id
                env[container] = env.get(container, _Taint()).merge(combined)
            if function_name in {"eval", "builtins.eval", "exec", "builtins.exec"} and combined.sources:
                sink = function_name.rsplit(".", 1)[-1]
                fingerprint = hashlib.sha256(f"PY-DATAFLOW-CODE-INJECTION\0{self.path}\0{node.lineno}\0{node.col_offset}".encode()).hexdigest()[:20]
                self.exposures[fingerprint] = {
                    "fingerprint": fingerprint, "rule_id": "PY-DATAFLOW-CODE-INJECTION", "path": self.path,
                    "line": node.lineno, "sink": sink, "sources": list(combined.sources),
                    "sanitizers": list(combined.sanitizers), "confidence": "lower" if combined.sanitizers else "high",
                    "experimental": True, "lifecycle": "prototype_only",
                }
            if function_name in {"eval", "builtins.eval", "exec", "builtins.exec"} and combined.unmodeled:
                for unresolved in combined.unmodeled:
                    self.unmodeled_constructs.add((unresolved, node.lineno, node.col_offset))
            if function_name in {"ast.literal_eval", "json.loads", "int", "float", "bool"} and combined.sources:
                return _Taint(combined.sources, tuple(dict.fromkeys(combined.sanitizers + (function_name,))), combined.unmodeled)
            if function_name in {"base64.b64encode", "base64.b64decode", "urllib.parse.unquote_plus", "urllib.parse.unquote"}:
                return combined
            callee = self.functions.get(function_name)
            if callee and function_name in stack:
                if combined.sources or combined.unmodeled or function_name in self.source_functions:
                    self.truncations.add((function_name, getattr(node, "lineno", 0)))
                gap = _gap("recursion_cycle", f"unresolved return from {function_name}")
                return _Taint(combined.sources, combined.sanitizers, tuple(dict.fromkeys(combined.unmodeled + (gap,))))
            if callee and (combined.sources or function_name in self.source_functions):
                if depth >= self.max_depth:
                    if combined.sources or combined.unmodeled or function_name in self.source_functions:
                        self.truncations.add((function_name, getattr(node, "lineno", 0)))
                    gap = _gap("depth_limit", f"unresolved return from {function_name}")
                    return _Taint(combined.sources, combined.sanitizers, tuple(dict.fromkeys(combined.unmodeled + (gap,))))
                return self.execute(callee, argument_taints, depth + 1, stack + (function_name,))
            if callee and _returns_only_static(callee):
                return _Taint()
            if function_name and function_name not in {"eval", "builtins.eval", "exec", "builtins.exec"}:
                receiver_root = _name(node.func.value).split(".", 1)[0] if isinstance(node.func, ast.Attribute) else ""
                if function_name in self.imported_symbols or receiver_root in self.imported_modules | self.imported_symbols:
                    category = "cross_module_call"
                elif isinstance(node.func, ast.Attribute):
                    category = "dynamic_dispatch"
                else:
                    category = "unresolved_call"
                gap = _gap(category, f"unresolved return from {function_name}")
                return _Taint(combined.sources, combined.sanitizers, tuple(dict.fromkeys(combined.unmodeled + (gap,))))
            return combined
        combined = _Taint()
        for child in ast.iter_child_nodes(node):
            combined = combined.merge(self.expression(child, env, depth, stack))
        return combined

    def statements(self, statements: list[ast.stmt], env: dict[str, _Taint], depth: int, stack: tuple[str, ...]) -> _Taint:
        returned = _Taint()
        for statement in statements:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = self.expression(statement.value, env, depth, stack)
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = value
                    elif isinstance(target, ast.Subscript) and (key := _subscript_key(target)):
                        env[key] = value
            elif isinstance(statement, ast.Return):
                returned = returned.merge(self.expression(statement.value, env, depth, stack))
            elif isinstance(statement, ast.Expr):
                self.expression(statement.value, env, depth, stack)
            elif isinstance(statement, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                branch_environments = []
                for body in (getattr(statement, "body", []), getattr(statement, "orelse", []), getattr(statement, "finalbody", [])):
                    branch_env = dict(env)
                    returned = returned.merge(self.statements(body, branch_env, depth, stack))
                    branch_environments.append(branch_env)
                for handler in getattr(statement, "handlers", []):
                    branch_env = dict(env)
                    returned = returned.merge(self.statements(handler.body, branch_env, depth, stack))
                    branch_environments.append(branch_env)
                for name in set().union(*(branch.keys() for branch in branch_environments)):
                    merged = _Taint()
                    for branch in branch_environments:
                        merged = merged.merge(branch.get(name, env.get(name, _Taint())))
                    env[name] = merged
        return returned

    def execute(self, function: ast.FunctionDef | ast.AsyncFunctionDef, arguments: list[_Taint], depth: int, stack: tuple[str, ...]) -> _Taint:
        env = {parameter.arg: arguments[index] if index < len(arguments) else _Taint() for index, parameter in enumerate(function.args.args)}
        return self.statements(function.body, env, depth, stack)

    def run(self, tree: ast.Module) -> None:
        self.statements(tree.body, {}, 0, ())
        for function in self.functions.values():
            self.execute(function, [], 0, (function.name,))


def analyze_python_dataflow(
    root: Path, max_depth: int = 3, max_modules: int = 10_000,
    max_calls: int = 1_000_000, timeout_seconds: float = 120.0,
) -> dict:
    """Prototype Python taint analysis; results never enter normal findings or policy gates."""
    root = root.resolve()
    if min(max_depth, max_modules, max_calls, timeout_seconds) <= 0:
        raise ValueError("analysis limits must be positive")
    budget = _AnalysisBudget(max_calls=max_calls, deadline=time.monotonic() + timeout_seconds)
    exposures: dict[str, dict] = {}
    truncations: list[dict] = []
    unmodeled: list[dict] = []
    parse_errors = 0
    analyzed_modules = 0
    module_exhausted = False
    for path in iter_files(root, Config.load(root)):
        if path.suffix.lower() != ".py":
            continue
        if time.monotonic() >= budget.deadline:
            budget.time_exhausted = True
            break
        if analyzed_modules >= max_modules:
            module_exhausted = True
            break
        analyzed_modules += 1
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, SyntaxError):
            parse_errors += 1
            continue
        analyzer = _ModuleAnalyzer(relative_path(path, root), tree, max_depth, budget)
        analyzer.run(tree)
        exposures.update(analyzer.exposures)
        truncations.extend({"path": relative_path(path, root), "function": name, "line": line} for name, line in sorted(analyzer.truncations))
        for encoded, line, column in sorted(analyzer.unmodeled_constructs):
            category, construct = _split_gap(encoded)
            unmodeled.append({"path": relative_path(path, root), "category": category, "construct": construct, "sink_line": line, "sink_column": column})
    limits = []
    if module_exhausted:
        limits.append({"category": "module_limit", "limit": max_modules, "observed": analyzed_modules})
    if budget.call_exhausted:
        limits.append({"category": "call_limit", "limit": max_calls, "observed": budget.calls})
    if budget.time_exhausted:
        limits.append({"category": "time_limit", "limit": timeout_seconds, "observed": None})
    return {
        "schema": "vulcanary.experimental-dataflow.v1", "experimental": True,
        "policy_effect": "none", "max_call_depth": max_depth,
        "exposures": sorted(exposures.values(), key=lambda item: (item["path"], item["line"])),
        "analysis_truncations": truncations, "unmodeled_constructs": unmodeled,
        "unmodeled_construct_count": len(unmodeled), "parse_errors": parse_errors,
        "analysis_limits": limits, "analyzed_modules": analyzed_modules, "analyzed_calls": budget.calls,
        "analysis_budget": {"max_modules": max_modules, "max_calls": max_calls, "timeout_seconds": timeout_seconds},
    }


def benchmark_python_score(report: dict, expected_results: Path) -> dict:
    """Score CWE-94 predictions against BenchmarkPython's expectedresults CSV."""
    predicted = {
        match.group(0) for item in report.get("exposures", [])
        if (match := re.search(r"BenchmarkTest\d{5}", str(item.get("path", ""))))
    }
    labels: dict[str, bool] = {}
    with expected_results.open(newline="", encoding="utf-8") as source:
        for row in csv.reader(line for line in source if not line.startswith("#")):
            if len(row) >= 4 and (row[1] == "codeinj" or row[3] == "94"):
                labels[row[0]] = row[2].lower() == "true"
    tp = sum(name in predicted and vulnerable for name, vulnerable in labels.items())
    fp = sum(name in predicted and not vulnerable for name, vulnerable in labels.items())
    fn = sum(name not in predicted and vulnerable for name, vulnerable in labels.items())
    tn = sum(name not in predicted and not vulnerable for name, vulnerable in labels.items())
    recall = tp / (tp + fn) if tp + fn else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    return {"true_positives": tp, "false_positives": fp, "false_negatives": fn, "true_negatives": tn, "recall": recall, "precision": precision, "false_positive_rate": false_positive_rate, "benchmark_score": recall - false_positive_rate}


def write_dataflow_report(report: dict, destination: Path) -> None:
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
