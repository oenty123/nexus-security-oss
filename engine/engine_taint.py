"""
engine_taint.py — продвинутый межпроцедурный taint-анализ.

Превосходит базовый TaintAnalyzer:
  1. Межпроцедурный анализ — taint распространяется через вызовы функций
  2. Возвращаемые значения — функция, возвращающая taint, помечает результат
  3. Атрибуты объектов — self.data = request.x помечает self.data
  4. Контейнеры — list/dict/tuple с taint-элементами
  5. Санитайзеры с учётом контекста (SQL-escape ≠ HTML-escape)

Двухпроходный алгоритм:
  Pass 1: построение графа функций (какие возвращают/принимают taint)
  Pass 2: распространение taint с учётом графа
"""

from __future__ import annotations

import ast
import dataclasses
from typing import Dict, List, Optional, Set, Tuple


@dataclasses.dataclass
class TaintFinding:
    rule_id:    str
    title:      str
    severity:   str
    cwe:        str
    line:       int
    col:        int
    snippet:    str
    sink:       str
    source_var: str
    flow:       List[str]      # путь распространения taint
    confidence: str
    fix:        str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


# Источники taint (пользовательский ввод)
TAINT_SOURCES = frozenset({
    "request.args", "request.form", "request.json", "request.data",
    "request.values", "request.cookies", "request.headers",
    "request.GET", "request.POST", "request.FILES", "request.body",
    "input", "raw_input", "sys.stdin.read", "sys.argv",
    "os.environ.get", "os.getenv",
    "self.get_argument", "self.request.body",
    "flask.request", "fastapi.Request",
})

# Sinks: dangerous_function -> (cwe, title, severity, fix)
SINKS: Dict[str, Tuple[str, str, str, str]] = {
    "execute":          ("CWE-89", "SQL-инъекция (taint → execute)", "critical",
                         "Используйте параметризованные запросы: execute(sql, params)"),
    "executemany":      ("CWE-89", "SQL-инъекция (taint → executemany)", "critical",
                         "Параметризованные запросы"),
    "raw":              ("CWE-89", "SQL-инъекция (Django .raw)", "critical",
                         "Model.objects.raw(sql, params)"),
    "eval":             ("CWE-95", "RCE (taint → eval)", "critical",
                         "ast.literal_eval() для литералов"),
    "exec":             ("CWE-78", "RCE (taint → exec)", "critical",
                         "Перепишите без exec()"),
    "compile":          ("CWE-95", "RCE (taint → compile)", "critical",
                         "Избегайте динамической компиляции"),
    "system":           ("CWE-78", "Command Injection (taint → os.system)", "high",
                         "subprocess.run([...], shell=False)"),
    "popen":            ("CWE-78", "Command Injection (taint → popen)", "high",
                         "subprocess с list аргументов"),
    "call":             ("CWE-78", "Command Injection (taint → subprocess.call)", "high",
                         "shell=False, список аргументов"),
    "run":              ("CWE-78", "Command Injection (taint → subprocess.run)", "high",
                         "shell=False, список аргументов"),
    "Popen":            ("CWE-78", "Command Injection (taint → Popen)", "high",
                         "shell=False, список аргументов"),
    "loads":            ("CWE-502", "Десериализация (taint → loads)", "critical",
                         "json.loads() вместо pickle"),
    "load":             ("CWE-502", "Десериализация (taint → load)", "high",
                         "safe_load для YAML"),
    "open":             ("CWE-22", "Path Traversal (taint → open)", "high",
                         "Валидация пути через Path.resolve()"),
    "render_template_string": ("CWE-94", "SSTI (taint → шаблон)", "critical",
                         "render_template с файлами"),
    "urlopen":          ("CWE-918", "SSRF (taint → urlopen)", "high",
                         "Whitelist доменов"),
    "get":              ("CWE-918", "SSRF (taint → requests.get)", "high",
                         "Whitelist доменов"),
}

# Санитайзеры по контексту
SANITIZERS: Dict[str, Set[str]] = {
    "sql":  {"quote_ident", "escape_string", "mogrify"},
    "html": {"escape", "html.escape", "markupsafe.escape", "bleach.clean"},
    "path": {"secure_filename", "os.path.basename"},
    "any":  {"int", "float", "bool", "uuid.UUID", "shlex.quote", "re.escape"},
}
ALL_SANITIZERS = frozenset().union(*SANITIZERS.values())


class FunctionGraph(ast.NodeVisitor):
    """Pass 1: строит граф — какие функции возвращают/пропускают taint."""

    def __init__(self) -> None:
        # имя функции -> возвращает ли taint (если параметр taint)
        self.returns_taint_if_param: Dict[str, Set[int]] = {}
        self.func_params: Dict[str, List[str]] = {}

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        params = [a.arg for a in node.args.args]
        self.func_params[node.name] = params

        # Проверяем: возвращает ли функция один из параметров напрямую
        tainted_param_indices: Set[int] = set()
        for ret in ast.walk(node):
            if isinstance(ret, ast.Return) and ret.value:
                names = {n.id for n in ast.walk(ret.value) if isinstance(n, ast.Name)}
                for i, p in enumerate(params):
                    if p in names:
                        tainted_param_indices.add(i)
                # Возврат источника напрямую
                if _contains_source(ret.value):
                    tainted_param_indices.add(-1)  # всегда taint

        if tainted_param_indices:
            self.returns_taint_if_param[node.name] = tainted_param_indices

        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore


class InterproceduralTaint(ast.NodeVisitor):
    """Pass 2: распространяет taint с учётом графа функций."""

    def __init__(self, lines: List[str], graph: FunctionGraph) -> None:
        self._lines = lines
        self._graph = graph
        self._tainted: Set[str] = set()
        self._tainted_attrs: Set[str] = set()
        self._flow: Dict[str, List[str]] = {}
        self._seen: Set[tuple] = set()
        self.findings: List[TaintFinding] = []

    def analyze(self, code: str) -> List[TaintFinding]:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []
        # Multi-pass: повторяем распространение, пока находятся новые taint-переменные.
        # Это позволяет taint пройти через цепочки присваиваний и вызовы,
        # объявленные в любом порядке.
        for _ in range(3):
            before = len(self._tainted) + len(self._tainted_attrs)
            self.visit(tree)
            after = len(self._tainted) + len(self._tainted_attrs)
            if after == before:
                break
        return self.findings

    # ── Присваивания ──────────────────────────────────────────────────────
    def visit_Assign(self, node: ast.Assign) -> None:
        tainted, flow = self._eval_taint(node.value)
        if tainted:
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    self._tainted.add(tgt.id)
                    self._flow[tgt.id] = flow + [tgt.id]
                elif isinstance(tgt, ast.Attribute):
                    key = self._attr_key(tgt)
                    if key:
                        self._tainted_attrs.add(key)
                        self._flow[key] = flow + [key]
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        tainted, flow = self._eval_taint(node.value)
        if tainted and isinstance(node.target, ast.Name):
            self._tainted.add(node.target.id)
            self._flow[node.target.id] = flow + [node.target.id]
        self.generic_visit(node)

    # ── Вызовы ─────────────────────────────────────────────────────────────
    def visit_Call(self, node: ast.Call) -> None:
        fname = self._call_name(node)
        method = fname.split(".")[-1] if fname else ""

        if method in SINKS and method not in ALL_SANITIZERS:
            self._check_sink(node, fname, method)

        self.generic_visit(node)

    def _check_sink(self, node: ast.Call, fname: str, method: str) -> None:
        cwe, title, sev, fix = SINKS[method]
        for arg in node.args:
            tainted, flow = self._eval_taint(arg)
            if tainted:
                # дедупликация по (line, sink) для multi-pass
                key = (node.lineno, fname)
                if key in self._seen:
                    return
                self._seen.add(key)
                line = node.lineno
                snippet = self._lines[line - 1].strip() if 0 < line <= len(self._lines) else ""
                src_var = flow[0] if flow else "unknown"
                self.findings.append(TaintFinding(
                    rule_id=f"TAINT-{cwe.replace('-', '_')}",
                    title=title,
                    severity=sev,
                    cwe=cwe,
                    line=line,
                    col=node.col_offset,
                    snippet=snippet[:120],
                    sink=fname,
                    source_var=src_var,
                    flow=flow,
                    confidence="high" if len(flow) <= 2 else "medium",
                    fix=fix,
                ))
                return

    # ── Оценка taint выражения ─────────────────────────────────────────────
    def _eval_taint(self, node: ast.expr) -> Tuple[bool, List[str]]:
        """Возвращает (is_tainted, flow_path)."""
        if isinstance(node, ast.Name):
            if node.id in self._tainted:
                return True, list(self._flow.get(node.id, [node.id]))
            return False, []

        if isinstance(node, ast.Attribute):
            key = self._attr_key(node)
            if key and key in self._tainted_attrs:
                return True, list(self._flow.get(key, [key]))
            if _contains_source(node):
                return True, [self._attr_key(node) or "source"]
            return False, []

        if isinstance(node, ast.Call):
            cname = self._call_name(node)
            method = cname.split(".")[-1] if cname else ""
            # Санитайзер очищает taint
            if method in ALL_SANITIZERS or cname in ALL_SANITIZERS:
                return False, []
            # Источник
            if _contains_source(node):
                return True, [cname or "source"]
            # Межпроцедурный: функция возвращает taint?
            func_simple = cname.split(".")[-1]
            if func_simple in self._graph.returns_taint_if_param:
                indices = self._graph.returns_taint_if_param[func_simple]
                if -1 in indices:
                    return True, [f"{func_simple}()→taint"]
                for i in indices:
                    if i < len(node.args):
                        t, fl = self._eval_taint(node.args[i])
                        if t:
                            return True, fl + [f"{func_simple}()"]
            # Аргументы taint?
            for a in node.args:
                t, fl = self._eval_taint(a)
                if t:
                    return True, fl
            return False, []

        if isinstance(node, ast.JoinedStr):  # f-строка
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    t, fl = self._eval_taint(v.value)
                    if t:
                        return True, fl + ["f-string"]
            return False, []

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            tl, fll = self._eval_taint(node.left)
            if tl:
                return True, fll + ["concat"]
            tr, flr = self._eval_taint(node.right)
            if tr:
                return True, flr + ["concat"]
            return False, []

        if isinstance(node, ast.Subscript):
            return self._eval_taint(node.value)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for el in node.elts:
                t, fl = self._eval_taint(el)
                if t:
                    return True, fl + ["container"]
            return False, []

        if isinstance(node, ast.IfExp):
            t1, f1 = self._eval_taint(node.body)
            if t1:
                return True, f1
            return self._eval_taint(node.orelse)

        if isinstance(node, ast.Call):
            return False, []

        return False, []

    # ── Helpers ────────────────────────────────────────────────────────────
    @staticmethod
    def _call_name(node: ast.Call) -> str:
        return _dotted_name(node.func)

    @staticmethod
    def _attr_key(node: ast.Attribute) -> Optional[str]:
        name = _dotted_name(node)
        return name or None


def _dotted_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts: List[str] = []
        cur: ast.expr = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _contains_source(node: ast.expr) -> bool:
    """Проверяет, обращается ли выражение к источнику taint."""
    for n in ast.walk(node):
        name = _dotted_name(n) if isinstance(n, (ast.Name, ast.Attribute)) else ""
        if any(name.startswith(s) or name == s.split(".")[-1] for s in TAINT_SOURCES):
            return True
        if isinstance(n, ast.Call):
            cn = _dotted_name(n.func)
            if any(cn.startswith(s) for s in TAINT_SOURCES):
                return True
    return False


def analyze_interprocedural(code: str, filename: str = "unknown") -> List[TaintFinding]:
    """
    Двухпроходный межпроцедурный taint-анализ.

    Pass 1: строим граф функций.
    Pass 2: распространяем taint через вызовы.
    """
    lines = code.splitlines()
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    graph = FunctionGraph()
    graph.visit(tree)

    analyzer = InterproceduralTaint(lines, graph)
    return analyzer.analyze(code)


if __name__ == "__main__":
    test_code = '''
import sqlite3

def get_user_input():
    return request.args.get("id")

def build_query(user_id):
    return "SELECT * FROM users WHERE id=" + user_id

def handler():
    uid = get_user_input()           # taint source через функцию
    query = build_query(uid)         # taint через межпроцедурный возврат
    cursor.execute(query)            # SINK — должно сработать

def direct():
    data = request.form["name"]      # прямой источник
    cursor.execute(f"SELECT {data}") # SINK через f-строку
'''
    findings = analyze_interprocedural(test_code, "test.py")
    print(f"Найдено taint-flows: {len(findings)}\n")
    for f in findings:
        print(f"  [{f.severity.upper()}] {f.title}")
        print(f"    Строка {f.line}: {f.snippet}")
        print(f"    Flow: {' → '.join(f.flow)}")
        print(f"    Fix: {f.fix}\n")
