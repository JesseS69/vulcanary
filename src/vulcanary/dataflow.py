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
    object_types: tuple[str, ...] = ()
    attributes: tuple[tuple[str, "_Taint"], ...] = ()
    object_ids: tuple[str, ...] = ()

    def merge(self, other: "_Taint") -> "_Taint":
        merged_attributes = dict(self.attributes)
        for name, value in other.attributes:
            merged_attributes[name] = merged_attributes.get(name, _Taint()).merge(value)
        return _Taint(
            tuple(dict.fromkeys(self.sources + other.sources)),
            tuple(dict.fromkeys(self.sanitizers + other.sanitizers)),
            tuple(dict.fromkeys(self.unmodeled + other.unmodeled)),
            tuple(dict.fromkeys(self.object_types + other.object_types)),
            tuple(merged_attributes.items()),
            tuple(dict.fromkeys(self.object_ids + other.object_ids)),
        )


def _replace_object(value: _Taint, object_ids: tuple[str, ...], replacement: _Taint) -> _Taint:
    """Replace an allocation and its nested aliases without executing repository code."""
    if set(value.object_ids) & set(object_ids):
        return replacement
    attributes = tuple((name, _replace_object(item, object_ids, replacement)) for name, item in value.attributes)
    if attributes == value.attributes:
        return value
    return _Taint(value.sources, value.sanitizers, value.unmodeled, value.object_types, attributes, value.object_ids)


def _has_flow_state(value: _Taint) -> bool:
    return bool(value.sources or value.unmodeled) or any(_has_flow_state(item) for _, item in value.attributes)


def _has_unmodeled_state(value: _Taint) -> bool:
    return bool(value.unmodeled) or any(_has_unmodeled_state(item) for _, item in value.attributes)


def _reidentify_objects(value: _Taint, allocation: str) -> _Taint:
    """Give a cached object graph fresh IDs while preserving internal aliases."""
    identifiers: dict[str, str] = {}
    if value.object_ids:
        identifiers[value.object_ids[0]] = allocation

    def visit(item: _Taint) -> _Taint:
        object_ids = []
        for identifier in item.object_ids:
            if identifier not in identifiers:
                identifiers[identifier] = f"{allocation}/nested/{len(identifiers)}"
            object_ids.append(identifiers[identifier])
        attributes = tuple((name, visit(attribute)) for name, attribute in item.attributes)
        return _Taint(
            item.sources, item.sanitizers, item.unmodeled,
            item.object_types, attributes, tuple(object_ids),
        )

    return visit(value)


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


def _base_name(node: ast.AST) -> str:
    """Return the class named by a base expression without evaluating type arguments."""
    return _name(node.value) if isinstance(node, ast.Subscript) else _name(node)


def _contains_zero_arg_super(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "super"
        and not node.args
        and not node.keywords
        for node in ast.walk(function)
    )


def _mutates_receiver_attributes(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    if not function.args.args:
        return False
    receiver = function.args.args[0].arg
    for node in ast.walk(function):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        if any(isinstance(target, ast.Attribute) and _name(target).startswith(f"{receiver}.") for target in targets):
            return True
    return False


def _source(node: ast.AST) -> str | None:
    target = node.func if isinstance(node, ast.Call) else node.value if isinstance(node, ast.Subscript) else node
    name = _name(target)
    if name in {"input", "request.get_json"}:
        return name
    if name.startswith(("request.args", "request.form", "request.cookies", "request.headers", "request.values", "request.GET", "request.POST", "request.data", "request.json", "request.query_string")):
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


def _contains_direct_source(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return whether this function directly reads a recognized request source."""
    return any(_source(node) is not None for node in ast.walk(function))


def _gap(category: str, construct: str) -> str:
    return f"{category}\0{construct}"


def _split_gap(value: str) -> tuple[str, str]:
    return tuple(value.split("\0", 1)) if "\0" in value else ("unclassified", value)


def _assignment_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(name for item in node.elts for name in _assignment_names(item))
    return ()


def _sink_calls(node: ast.AST) -> tuple[ast.Call, ...]:
    return tuple(
        child for child in ast.walk(node)
        if isinstance(child, ast.Call)
        and _name(child.func) in {"eval", "builtins.eval", "exec", "builtins.exec"}
    )


def _captured_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    """Return lexically captured names without executing or importing scanned code."""
    parameters = {
        argument.arg
        for argument in (
            *function.args.posonlyargs, *function.args.args,
            *function.args.kwonlyargs,
            *((function.args.vararg,) if function.args.vararg else ()),
            *((function.args.kwarg,) if function.args.kwarg else ()),
        )
    }
    bound = set(parameters)
    loaded: set[str] = set()
    globals_: set[str] = set()

    class Visitor(ast.NodeVisitor):
        def visit_Name(self, node: ast.Name) -> None:
            (bound if isinstance(node.ctx, (ast.Store, ast.Del)) else loaded).add(node.id)

        def visit_Global(self, node: ast.Global) -> None:
            globals_.update(node.names)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if node is function:
                for statement in node.body:
                    self.visit(statement)
            else:
                bound.add(node.name)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            bound.add(node.name)

    Visitor().visit(function)
    return tuple(sorted(loaded - bound - globals_))


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
                callee = _name(node.func)
                if callee.startswith(("self.", "cls.")):
                    callee = callee.rsplit(".", 1)[-1]
                calls.setdefault(self.stack[-1], set()).add(callee)
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


def _module_name(path: str) -> str:
    parts = Path(path).with_suffix("").parts
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _absolute_import(module_name: str, imported: str | None, level: int, is_package: bool = False) -> str:
    if level == 0:
        return imported or ""
    package = module_name if is_package else module_name.rsplit(".", 1)[0] if "." in module_name else ""
    parts = package.split(".") if package else []
    keep = max(0, len(parts) - level + 1)
    prefix = parts[:keep]
    if imported:
        prefix.extend(imported.split("."))
    return ".".join(prefix)


def _import_bindings(tree: ast.Module, module_name: str, is_package: bool = False) -> tuple[dict[str, str], dict[str, tuple[str, str]], set[str], set[str]]:
    module_bindings: dict[str, str] = {}
    symbol_bindings: dict[str, tuple[str, str]] = {}
    modules: set[str] = set()
    symbols: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                binding = alias.asname or alias.name.split(".", 1)[0]
                module_bindings[binding] = alias.name if alias.asname else binding
                modules.add(binding)
        elif isinstance(node, ast.ImportFrom):
            imported_module = _absolute_import(module_name, node.module, node.level, is_package)
            for alias in node.names:
                if alias.name == "*":
                    continue
                binding = alias.asname or alias.name
                symbol_bindings[binding] = (imported_module, alias.name)
                symbols.add(binding)
    return module_bindings, symbol_bindings, modules, symbols


class _ModuleAnalyzer:
    def __init__(self, path: str, tree: ast.Module, max_depth: int, budget: _AnalysisBudget,
                 project: dict[str, tuple[str, ast.Module]] | None = None,
                 analyzer_cache: dict[str, "_ModuleAnalyzer"] | None = None,
                 exposures: dict[str, dict] | None = None,
                 truncations: set[tuple[str, str, int]] | None = None,
                 unmodeled_constructs: set[tuple[str, str, int, int]] | None = None) -> None:
        self.path = path
        self.module_name = _module_name(path)
        self.max_depth = max_depth
        self.functions = {node.name: node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.module_functions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.classes = {node.name: node for node in tree.body if isinstance(node, ast.ClassDef)}
        self.method_owners = {
            id(method): class_node.name
            for class_node in self.classes.values()
            for method in class_node.body
            if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.source_functions = _source_capable_functions(tree)
        self.module_bindings, self.symbol_bindings, self.imported_modules, self.imported_symbols = _import_bindings(
            tree, self.module_name, Path(path).name == "__init__.py"
        )
        self.project = project or {}
        self.analyzer_cache = analyzer_cache if analyzer_cache is not None else {}
        self.analyzer_cache[self.module_name] = self
        self.budget = budget
        self.constructor_cache: dict[str, _Taint] = {}
        self.exposures = exposures if exposures is not None else {}
        self.truncations = truncations if truncations is not None else set()
        self.unmodeled_constructs = unmodeled_constructs if unmodeled_constructs is not None else set()

    def _class_type(self, name: str) -> str | None:
        if name in self.classes:
            return f"{self.module_name}:{name}"
        module = ""
        symbol = ""
        if name in self.symbol_bindings:
            module, symbol = self.symbol_bindings[name]
        elif "." in name:
            binding, symbol = name.rsplit(".", 1)
            root, _, remainder = binding.partition(".")
            if root in self.module_bindings:
                module = ".".join(part for part in (self.module_bindings[root], remainder) if part)
        if module in self.project:
            analyzer = self.analyzer_cache.get(module)
            if analyzer is None:
                path, tree = self.project[module]
                analyzer = _ModuleAnalyzer(path, tree, self.max_depth, self.budget, self.project, self.analyzer_cache,
                                           self.exposures, self.truncations, self.unmodeled_constructs)
            if symbol in analyzer.classes:
                return f"{module}:{symbol}"
        return None

    def _object_method(
        self, object_type: str, method: str, seen: tuple[str, ...] = (),
    ) -> tuple[tuple["_ModuleAnalyzer", ast.FunctionDef | ast.AsyncFunctionDef, str] | None, str | None]:
        if object_type in seen:
            return None, "inheritance_cycle"
        module, _, class_name = object_type.partition(":")
        analyzer = self.analyzer_cache.get(module)
        if analyzer is None and module in self.project:
            path, tree = self.project[module]
            analyzer = _ModuleAnalyzer(path, tree, self.max_depth, self.budget, self.project, self.analyzer_cache,
                                       self.exposures, self.truncations, self.unmodeled_constructs)
        class_node = analyzer.classes.get(class_name) if analyzer else None
        if class_node:
            target = next((item for item in class_node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == method), None)
            if target:
                if any(_name(item) in {"staticmethod", "classmethod"} for item in target.decorator_list):
                    return None, "unsupported_method_kind"
                return (analyzer, target, f"{module}.{class_name}.{method}"), None
            base_names = [_base_name(base) for base in class_node.bases]
            bases = [analyzer._class_type(base) for base in base_names if base not in {"object", "Generic", "typing.Generic"}]
            if any(base is None for base in bases):
                return None, "missing_base"
            resolved_bases = [base for base in bases if base]
            if len(resolved_bases) > 1:
                return None, "ambiguous_inheritance"
            if resolved_bases:
                return analyzer._object_method(resolved_bases[0], method, seen + (object_type,))
        return None, None

    def _has_cross_module_base(self, object_type: str, seen: tuple[str, ...] = ()) -> bool:
        if object_type in seen:
            return False
        module, _, class_name = object_type.partition(":")
        analyzer = self.analyzer_cache.get(module)
        if analyzer is None and module in self.project:
            path, tree = self.project[module]
            analyzer = _ModuleAnalyzer(
                path, tree, self.max_depth, self.budget, self.project, self.analyzer_cache,
                self.exposures, self.truncations, self.unmodeled_constructs,
            )
        class_node = analyzer.classes.get(class_name) if analyzer else None
        if not class_node:
            return False
        for base_node in class_node.bases:
            base_name = _base_name(base_node)
            if base_name in {"object", "Generic", "typing.Generic"}:
                continue
            base_type = analyzer._class_type(base_name)
            if not base_type:
                continue
            base_module = base_type.partition(":")[0]
            if base_module != module or analyzer._has_cross_module_base(base_type, seen + (object_type,)):
                return True
        return False

    def _lexical_receiver_has_cross_module_base(
        self, node: ast.Attribute, stack: tuple[str, ...],
    ) -> bool:
        """Recognize unresolved self/cls state even when inferred receiver state was lost."""
        if not isinstance(node.value, ast.Name) or not stack:
            return False
        current = stack[-1]
        for class_name, class_node in self.classes.items():
            prefix = f"{self.module_name}.{class_name}."
            if not current.startswith(prefix):
                continue
            function = next(
                (
                    item for item in class_node.body
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and current == f"{prefix}{item.name}"
                ),
                None,
            )
            receiver = function.args.args[0].arg if function and function.args.args else "self"
            return node.value.id == receiver and self._has_cross_module_base(
                f"{self.module_name}:{class_name}"
            )
        return False

    def _super_method(
        self, method: str, stack: tuple[str, ...],
    ) -> tuple[tuple["_ModuleAnalyzer", ast.FunctionDef | ast.AsyncFunctionDef, str] | None, str | None, str]:
        """Resolve zero-argument super() from the current lexical method only."""
        current = stack[-1] if stack else ""
        for class_name, class_node in self.classes.items():
            prefix = f"{self.module_name}.{class_name}."
            if not current.startswith(prefix):
                continue
            function = next(
                (item for item in class_node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and current == f"{prefix}{item.name}"),
                None,
            )
            receiver = function.args.args[0].arg if function and function.args.args else "self"
            base_names = [_base_name(base) for base in class_node.bases]
            bases = [self._class_type(base) for base in base_names if base not in {"object", "Generic", "typing.Generic"}]
            if any(base is None for base in bases) or not bases:
                return None, "missing_base", receiver
            resolved_bases = [base for base in bases if base]
            if len(resolved_bases) != 1:
                return None, "ambiguous_inheritance", receiver
            result, gap = self._object_method(resolved_bases[0], method, (f"{self.module_name}:{class_name}",))
            return result, gap, receiver
        return None, "dynamic_dispatch", "self"

    def _unsupported_class_method(self, function_name: str) -> bool:
        if "." not in function_name:
            return False
        owner, method = function_name.rsplit(".", 1)
        object_type = self._class_type(owner)
        if not object_type:
            return False
        module, _, class_name = object_type.partition(":")
        analyzer = self.analyzer_cache.get(module)
        class_node = analyzer.classes.get(class_name) if analyzer else None
        _, gap = self._object_method(object_type, method)
        return gap == "unsupported_method_kind"

    def _project_callee(self, function_name: str) -> tuple[tuple["_ModuleAnalyzer", ast.FunctionDef | ast.AsyncFunctionDef, str] | None, str | None]:
        module = ""
        symbol = ""
        imported = False
        if function_name in self.symbol_bindings:
            module, symbol = self.symbol_bindings[function_name]
            imported = True
        elif "." in function_name:
            binding, symbol = function_name.rsplit(".", 1)
            root, _, remainder = binding.partition(".")
            if root in self.module_bindings:
                module = ".".join(part for part in (self.module_bindings[root], remainder) if part)
                imported = True
            elif root in self.symbol_bindings:
                parent, imported_name = self.symbol_bindings[root]
                module = ".".join(part for part in (parent, imported_name, remainder) if part)
                imported = True
        if not imported:
            return None, None
        if not module or module not in self.project:
            return None, "missing_module"
        analyzer = self.analyzer_cache.get(module)
        if analyzer is None:
            path, tree = self.project[module]
            analyzer = _ModuleAnalyzer(
                path, tree, self.max_depth, self.budget, self.project, self.analyzer_cache,
                self.exposures, self.truncations, self.unmodeled_constructs,
            )
        callee = analyzer.functions.get(symbol)
        return ((analyzer, callee, f"{module}.{symbol}"), None) if callee else (None, "ambiguous_symbol")

    def expression(self, node: ast.AST | None, env: dict[str, _Taint], depth: int, stack: tuple[str, ...]) -> _Taint:
        if node is None:
            return _Taint()
        source = _source(node)
        if source:
            return _Taint((f"{source}@{getattr(node, 'lineno', 0)}",))
        if isinstance(node, ast.Name):
            return env.get(node.id, _Taint())
        if isinstance(node, ast.Attribute):
            qualified = _name(node)
            if qualified in env:
                return env[qualified]
            receiver = self.expression(node.value, env, depth, stack)
            attribute = _Taint()
            attribute_found = False
            for name, value in receiver.attributes:
                if name == node.attr:
                    attribute_found = True
                    attribute = attribute.merge(value)
            if not attribute_found and (
                any(self._has_cross_module_base(kind) for kind in receiver.object_types)
                or self._lexical_receiver_has_cross_module_base(node, stack)
            ):
                gap = _gap(
                    "cross_module_inherited_state",
                    f"unresolved inherited attribute {qualified}",
                )
                attribute = attribute.merge(_Taint(unmodeled=(gap,)))
            return attribute
        if isinstance(node, ast.Subscript):
            key = _subscript_key(node)
            return env[key] if key and key in env else self.expression(node.value, env, depth, stack)
        if isinstance(node, ast.NamedExpr):
            gap = _gap("unsupported_named_expression", "assignment expression may carry taint")
            value = _Taint(unmodeled=(gap,))
            if isinstance(node.target, ast.Name):
                env[node.target.id] = value
            for sink in _sink_calls(node):
                self.unmodeled_constructs.add((self.path, gap, sink.lineno, sink.col_offset))
            return value
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            comprehension_env = dict(env)
            combined = _Taint()
            for generator in node.generators:
                iterable = self.expression(generator.iter, comprehension_env, depth, stack)
                names = _assignment_names(generator.target)
                if not names:
                    gap = _gap("unsupported_comprehension_target", "comprehension target is not modeled")
                    combined = combined.merge(_Taint(unmodeled=(gap,)))
                for name in names:
                    comprehension_env[name] = iterable
                for condition in generator.ifs:
                    combined = combined.merge(self.expression(condition, comprehension_env, depth, stack))
            values = (node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)
            for value in values:
                combined = combined.merge(self.expression(value, comprehension_env, depth, stack))
            return combined
        if isinstance(node, ast.Call):
            if limit := self.budget.consume_call():
                return _Taint(unmodeled=(_gap(limit, f"analysis stopped at {limit}"),))
            function_name = _name(node.func)
            argument_taints = [self.expression(item, env, depth, stack) for item in (*node.args, *(item.value for item in node.keywords))]
            combined = _Taint()
            for item in argument_taints:
                combined = combined.merge(item)
            is_zero_arg_super = bool(
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Call)
                and isinstance(node.func.value.func, ast.Name)
                and node.func.value.func.id == "super"
                and not node.func.value.args
                and not node.func.value.keywords
            )
            super_candidate = None
            super_gap = None
            if is_zero_arg_super:
                super_candidate, super_gap, receiver_name = self._super_method(node.func.attr, stack)
                receiver_taint = env.get(receiver_name, _Taint())
                function_name = f"super().{node.func.attr}"
            else:
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
                    self.unmodeled_constructs.add((self.path, unresolved, node.lineno, node.col_offset))
            if function_name in {"ast.literal_eval", "json.loads", "int", "float", "bool"} and combined.sources:
                return _Taint(combined.sources, tuple(dict.fromkeys(combined.sanitizers + (function_name,))), combined.unmodeled)
            if function_name in {"base64.b64encode", "base64.b64decode", "urllib.parse.unquote_plus", "urllib.parse.unquote"}:
                return combined
            if class_type := self._class_type(function_name):
                initializer_result, inheritance_gap = self._object_method(class_type, "__init__")
                allocation = f"{self.path}:{getattr(node, 'lineno', 0)}:{getattr(node, 'col_offset', 0)}:{class_type}"
                instance = _Taint(
                    combined.sources, combined.sanitizers, combined.unmodeled,
                    (class_type,), object_ids=(allocation,),
                )
                if inheritance_gap:
                    instance = instance.merge(_Taint(unmodeled=(
                        _gap(inheritance_gap, f"unresolved initialization of {function_name}"),
                    )))
                if initializer_result:
                    analyzer, initializer, qualified_initializer = initializer_result
                    if depth >= self.max_depth:
                        self.truncations.add((self.path, qualified_initializer, getattr(node, "lineno", 0)))
                        instance = instance.merge(_Taint(unmodeled=(
                            _gap("depth_limit", f"unresolved initialization of {function_name}"),
                        )))
                    else:
                        cacheable = not any(
                            item.sources or item.sanitizers or item.unmodeled or item.object_types or item.attributes
                            for item in argument_taints
                        )
                        cached = analyzer.constructor_cache.get(class_type) if cacheable else None
                        if cached is not None:
                            instance = _reidentify_objects(cached, allocation)
                        else:
                            truncation_count = len(self.truncations)
                            instance = analyzer.initialize_instance(initializer, instance, argument_taints, depth + 1, stack)
                            if (
                                cacheable and not _has_unmodeled_state(instance)
                                and len(self.truncations) == truncation_count
                            ):
                                analyzer.constructor_cache[class_type] = instance
                return instance
            if isinstance(node.func, ast.Attribute) and (receiver_taint.object_types or is_zero_arg_super):
                candidates = [(super_candidate, super_gap)] if is_zero_arg_super else [
                    self._object_method(kind, node.func.attr) for kind in receiver_taint.object_types
                ]
                resolved = [item for item, _ in candidates if item is not None]
                inheritance_gaps = sorted({gap for _, gap in candidates if gap})
                if len(resolved) == 1:
                    analyzer, target, qualified_target = resolved[0]
                    # Do not recursively interpret every clean method call in the
                    # repository. Follow methods only when taint enters as an
                    # argument/receiver state or the method directly produces
                    # recognized input.
                    stateful_receiver = _has_flow_state(receiver_taint)
                    if not (
                        combined.sources or combined.unmodeled or stateful_receiver
                        or target.name in analyzer.source_functions or _contains_zero_arg_super(target)
                    ):
                        return combined
                    if qualified_target in stack:
                        self.truncations.add((self.path, qualified_target, getattr(node, "lineno", 0)))
                        gap = _gap("recursion_cycle", f"unresolved return from {function_name}")
                        return _Taint(combined.sources, combined.sanitizers, tuple(dict.fromkeys(combined.unmodeled + (gap,))))
                    if depth >= self.max_depth:
                        self.truncations.add((self.path, qualified_target, getattr(node, "lineno", 0)))
                        gap = _gap("depth_limit", f"unresolved return from {function_name}")
                        return _Taint(combined.sources, combined.sanitizers, tuple(dict.fromkeys(combined.unmodeled + (gap,))))
                    result, updated_receiver = analyzer.execute_method(
                        target, receiver_taint, argument_taints, depth + 1, stack + (qualified_target,)
                    )
                    receiver_modules = {kind.partition(":")[0] for kind in receiver_taint.object_types}
                    if _mutates_receiver_attributes(target) and any(module != analyzer.module_name for module in receiver_modules):
                        boundary_gap = _gap(
                            "cross_module_inherited_state",
                            f"cross-module inherited attribute state from {qualified_target}",
                        )
                        updated_receiver = _Taint(
                            updated_receiver.sources,
                            updated_receiver.sanitizers,
                            tuple(dict.fromkeys(updated_receiver.unmodeled + (boundary_gap,))),
                            updated_receiver.object_types,
                            tuple(
                                (
                                    name,
                                    _Taint(
                                        value.sources,
                                        value.sanitizers,
                                        tuple(dict.fromkeys(value.unmodeled + (boundary_gap,))),
                                        value.object_types,
                                        value.attributes,
                                        value.object_ids,
                                    ),
                                )
                                for name, value in updated_receiver.attributes
                            ),
                            updated_receiver.object_ids,
                        )
                    if receiver_taint.object_ids:
                        for name, value in tuple(env.items()):
                            env[name] = _replace_object(value, receiver_taint.object_ids, updated_receiver)
                    if receiver_name:
                        env[receiver_name] = updated_receiver
                        for name, value in updated_receiver.attributes:
                            env[f"{receiver_name}.{name}"] = value
                    return result
                if inheritance_gaps:
                    gap = _gap(inheritance_gaps[0], f"unresolved return from {function_name}")
                    return _Taint(
                        combined.sources, combined.sanitizers,
                        tuple(dict.fromkeys(combined.unmodeled + (gap,))),
                    )
            if self._unsupported_class_method(function_name):
                gap = _gap("unsupported_method_kind", f"unresolved return from {function_name}")
                return _Taint(combined.sources, combined.sanitizers, tuple(dict.fromkeys(combined.unmodeled + (gap,))))
            callee = self.module_functions.get(function_name)
            qualified_name = f"{self.module_name}.{function_name}" if self.module_name else function_name
            if callee and qualified_name in stack:
                if combined.sources or combined.unmodeled or function_name in self.source_functions:
                    self.truncations.add((self.path, function_name, getattr(node, "lineno", 0)))
                gap = _gap("recursion_cycle", f"unresolved return from {function_name}")
                return _Taint(combined.sources, combined.sanitizers, tuple(dict.fromkeys(combined.unmodeled + (gap,))))
            if callee and (combined.sources or function_name in self.source_functions):
                if depth >= self.max_depth:
                    if combined.sources or combined.unmodeled or function_name in self.source_functions:
                        self.truncations.add((self.path, function_name, getattr(node, "lineno", 0)))
                    gap = _gap("depth_limit", f"unresolved return from {function_name}")
                    return _Taint(combined.sources, combined.sanitizers, tuple(dict.fromkeys(combined.unmodeled + (gap,))))
                return self.execute(callee, argument_taints, depth + 1, stack + (qualified_name,))
            if callee and _returns_only_static(callee):
                return _Taint()
            project_callee, project_gap = self._project_callee(function_name)
            if project_callee:
                analyzer, target, qualified_target = project_callee
                if qualified_target in stack:
                    self.truncations.add((self.path, qualified_target, getattr(node, "lineno", 0)))
                    gap = _gap("recursion_cycle", f"unresolved return from {function_name}")
                    return _Taint(combined.sources, combined.sanitizers, tuple(dict.fromkeys(combined.unmodeled + (gap,))))
                if depth >= self.max_depth:
                    self.truncations.add((self.path, qualified_target, getattr(node, "lineno", 0)))
                    gap = _gap("depth_limit", f"unresolved return from {function_name}")
                    return _Taint(combined.sources, combined.sanitizers, tuple(dict.fromkeys(combined.unmodeled + (gap,))))
                result = analyzer.execute(target, argument_taints, depth + 1, stack + (qualified_target,))
                return result
            if function_name and function_name not in {"eval", "builtins.eval", "exec", "builtins.exec"}:
                receiver_root = _name(node.func.value).split(".", 1)[0] if isinstance(node.func, ast.Attribute) else ""
                if project_gap:
                    category = project_gap
                elif function_name in self.imported_symbols or receiver_root in self.imported_modules | self.imported_symbols:
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
                    elif isinstance(target, ast.Attribute) and (qualified := _name(target)):
                        env[qualified] = value
                    elif isinstance(target, ast.Subscript) and (key := _subscript_key(target)):
                        env[key] = value
                    elif isinstance(target, (ast.Tuple, ast.List)):
                        gap = _gap("unsupported_unpacking", "assignment unpacking may carry taint")
                        for name in _assignment_names(target):
                            env[name] = _Taint(unmodeled=(gap,))
            elif isinstance(statement, ast.AugAssign):
                value = self.expression(statement.target, env, depth, stack).merge(
                    self.expression(statement.value, env, depth, stack)
                )
                if isinstance(statement.target, ast.Name):
                    env[statement.target.id] = value
                elif isinstance(statement.target, ast.Attribute) and (qualified := _name(statement.target)):
                    env[qualified] = value
                elif isinstance(statement.target, ast.Subscript) and (key := _subscript_key(statement.target)):
                    env[key] = value
                else:
                    gap = _gap("unsupported_augmented_target", "augmented assignment target is not modeled")
                    for sink in _sink_calls(statement):
                        self.unmodeled_constructs.add((self.path, gap, sink.lineno, sink.col_offset))
            elif isinstance(statement, ast.Return):
                returned = returned.merge(self.expression(statement.value, env, depth, stack))
            elif isinstance(statement, ast.Expr):
                self.expression(statement.value, env, depth, stack)
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                captured = _Taint()
                for name in _captured_names(statement):
                    captured = captured.merge(env.get(name, _Taint()))
                # Module-level functions are analyzed independently by run(). A
                # nested definition is a closure only while executing its owner.
                if stack and _has_flow_state(captured):
                    gap = _gap(
                        "unsupported_closure",
                        f"nested function {statement.name} may carry captured taint",
                    )
                    for sink in _sink_calls(statement):
                        self.unmodeled_constructs.add((self.path, gap, sink.lineno, sink.col_offset))
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                iterable = self.expression(statement.iter, env, depth, stack)
                branch_env = dict(env)
                names = _assignment_names(statement.target)
                if not names:
                    gap = _gap("unsupported_loop_target", "loop target is not modeled")
                    iterable = iterable.merge(_Taint(unmodeled=(gap,)))
                for name in names:
                    branch_env[name] = iterable
                returned = returned.merge(self.statements(statement.body, branch_env, depth, stack))
                for name, value in branch_env.items():
                    env[name] = env.get(name, _Taint()).merge(value)
                returned = returned.merge(self.statements(statement.orelse, dict(env), depth, stack))
            elif isinstance(statement, ast.Match):
                gap = _gap("unsupported_match", "match/case binding and branch selection are not modeled")
                branch_environments = []
                for case in statement.cases:
                    branch_env = dict(env)
                    assigned = {
                        name for child in case.body
                        for node in ast.walk(child)
                        if isinstance(node, (ast.Assign, ast.AnnAssign))
                        for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
                        for name in _assignment_names(target)
                    }
                    returned = returned.merge(self.statements(case.body, branch_env, depth, stack))
                    for name in assigned:
                        branch_env[name] = _Taint(unmodeled=(gap,))
                    branch_environments.append(branch_env)
                for name in set().union(*(branch.keys() for branch in branch_environments)):
                    merged = _Taint()
                    for branch in branch_environments:
                        merged = merged.merge(branch.get(name, env.get(name, _Taint())))
                    env[name] = merged
            elif isinstance(statement, (ast.If, ast.While, ast.With, ast.Try)):
                if isinstance(statement, (ast.If, ast.While)):
                    self.expression(statement.test, env, depth, stack)
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
        if function.args.args and arguments:
            receiver_name = function.args.args[0].arg
            for name, value in arguments[0].attributes:
                env[f"{receiver_name}.{name}"] = value
        return self.statements(function.body, env, depth, stack)

    def execute_method(
        self, function: ast.FunctionDef | ast.AsyncFunctionDef, receiver: _Taint,
        arguments: list[_Taint], depth: int, stack: tuple[str, ...],
    ) -> tuple[_Taint, _Taint]:
        parameters = function.args.args
        supplied = [receiver, *arguments]
        env = {parameter.arg: supplied[index] if index < len(supplied) else _Taint() for index, parameter in enumerate(parameters)}
        receiver_name = parameters[0].arg if parameters else "self"
        for name, value in receiver.attributes:
            env[f"{receiver_name}.{name}"] = value
        returned = self.statements(function.body, env, depth, stack)
        prefix = f"{receiver_name}."
        attributes = tuple((name[len(prefix):], value) for name, value in env.items() if name.startswith(prefix))
        updated = _Taint(
            receiver.sources, receiver.sanitizers, receiver.unmodeled,
            receiver.object_types, attributes, receiver.object_ids,
        )
        return returned, updated

    def initialize_instance(
        self, initializer: ast.FunctionDef | ast.AsyncFunctionDef, instance: _Taint,
        arguments: list[_Taint], depth: int, stack: tuple[str, ...],
    ) -> _Taint:
        qualified = f"{self.module_name}.{self.method_owners.get(id(initializer), '')}.__init__"
        if qualified in stack:
            return instance.merge(_Taint(unmodeled=(_gap("recursion_cycle", "unresolved instance initialization"),)))
        parameters = initializer.args.args
        supplied = [instance, *arguments]
        env = {parameter.arg: supplied[index] if index < len(supplied) else _Taint() for index, parameter in enumerate(parameters)}
        receiver = parameters[0].arg if parameters else "self"
        self.initialize_statements(initializer.body, env, receiver, depth, stack + (qualified,))
        prefix = f"{receiver}."
        attributes = tuple((name[len(prefix):], value) for name, value in env.items() if name.startswith(prefix))
        return _Taint(
            instance.sources, instance.sanitizers, instance.unmodeled,
            instance.object_types, attributes, instance.object_ids,
        )

    def initialize_statements(
        self, statements: list[ast.stmt], env: dict[str, _Taint], receiver: str,
        depth: int, stack: tuple[str, ...],
    ) -> None:
        """Summarize constructor state without interpreting unrelated body calls."""
        prefix = f"{receiver}."
        for statement in statements:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                relevant = [target for target in targets if isinstance(target, ast.Attribute) and _name(target).startswith(prefix)]
                if relevant:
                    value = self.expression(statement.value, env, depth, stack)
                    for target in relevant:
                        env[_name(target)] = value
            elif isinstance(statement, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                branches: list[dict[str, _Taint]] = []
                for body in (getattr(statement, "body", []), getattr(statement, "orelse", []), getattr(statement, "finalbody", [])):
                    branch = dict(env)
                    self.initialize_statements(body, branch, receiver, depth, stack)
                    branches.append(branch)
                for handler in getattr(statement, "handlers", []):
                    branch = dict(env)
                    self.initialize_statements(handler.body, branch, receiver, depth, stack)
                    branches.append(branch)
                for name in set().union(*(branch.keys() for branch in branches)):
                    if not name.startswith(prefix):
                        continue
                    merged = _Taint()
                    for branch in branches:
                        merged = merged.merge(branch.get(name, env.get(name, _Taint())))
                    env[name] = merged

    def run(self, tree: ast.Module) -> None:
        self.statements(tree.body, {}, 0, ())
        instance_seeds: dict[str, _Taint] = {}
        for function in self.functions.values():
            qualified = f"{self.module_name}.{function.name}" if self.module_name else function.name
            arguments: list[_Taint] = []
            owner = self.method_owners.get(id(function))
            if owner and function.args.args:
                instance = instance_seeds.get(owner)
                if instance is None:
                    instance = _Taint(
                        object_types=(f"{self.module_name}:{owner}",),
                        object_ids=(f"entry:{self.path}:{owner}",),
                    )
                    class_node = self.classes[owner]
                    initializer = next(
                        (item for item in class_node.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "__init__"),
                        None,
                    )
                    if initializer:
                        instance = self.initialize_instance(initializer, instance, [], 1, ())
                    instance_seeds[owner] = instance
                arguments = [instance]
            self.execute(function, arguments, 0, (qualified,))


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
    parsed_modules: list[tuple[str, ast.Module]] = []
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
        parsed_modules.append((relative_path(path, root), tree))
    project = {_module_name(path): (path, tree) for path, tree in parsed_modules}
    analyzer_cache: dict[str, _ModuleAnalyzer] = {}
    project_exposures: dict[str, dict] = {}
    project_truncations: set[tuple[str, str, int]] = set()
    project_unmodeled: set[tuple[str, str, int, int]] = set()
    for module_path, tree in parsed_modules:
        if time.monotonic() >= budget.deadline:
            budget.time_exhausted = True
            break
        module_name = _module_name(module_path)
        analyzer = analyzer_cache.get(module_name)
        if analyzer is None:
            analyzer = _ModuleAnalyzer(
                module_path, tree, max_depth, budget, project, analyzer_cache,
                project_exposures, project_truncations, project_unmodeled,
            )
        analyzer.run(tree)
    exposures.update(project_exposures)
    truncations.extend({"path": path, "function": name, "line": line} for path, name, line in sorted(project_truncations))
    for path, encoded, line, column in sorted(project_unmodeled):
        category, construct = _split_gap(encoded)
        unmodeled.append({"path": path, "category": category, "construct": construct, "sink_line": line, "sink_column": column})
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
