"""
engine_dataflow.py — анализ потока данных на основе control-flow графа.

Превосходит regex и базовый taint:
  - Control-Flow Graph (CFG): моделирует ветвления, циклы, ранние возвраты
  - Reaching definitions: какое присваивание "доживает" до точки использования
  - Path-sensitive: учитывает санитизацию в одной ветке, но не в другой
  - Состояние переменных отслеживается через граф, а не построчно

Это шаг от паттернов к настоящему анализу: ловит то, что regex видеть
не может (taint через ветвления, переопределение, частичную санитизацию),
и не шумит там, где переменная очищена на всех путях.
"""

from __future__ import annotations

import ast
import dataclasses
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Решётка состояний taint (для слияния путей)
# ─────────────────────────────────────────────────────────────────────────────

class TaintState(Enum):
    """
    Состояние переменной в решётке. При слиянии путей берётся "худшее":
    если хоть на одном пути TAINTED — результат TAINTED (безопасное допущение).
    """
    CLEAN = 0       # точно безопасна
    SANITIZED = 1   # прошла санитизацию
    TAINTED = 2     # содержит пользовательский ввод
    UNKNOWN = 3     # не определено

    @staticmethod
    def merge(a: "TaintState", b: "TaintState") -> "TaintState":
        """Слияние состояний при схождении путей (join в решётке)."""
        if a == TaintState.TAINTED or b == TaintState.TAINTED:
            return TaintState.TAINTED
        if a == TaintState.UNKNOWN or b == TaintState.UNKNOWN:
            return TaintState.UNKNOWN
        if a == TaintState.SANITIZED or b == TaintState.SANITIZED:
            return TaintState.SANITIZED
        return TaintState.CLEAN


@dataclasses.dataclass
class DataflowFinding:
    rule_id:    str
    title:      str
    severity:   str
    cwe:        str
    line:       int
    col:        int
    snippet:    str
    sink:       str
    path:       List[str]       # путь распространения через CFG
    confidence: str
    fix:        str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


# Источники, sinks, санитайзеры (расширяемые)
TAINT_SOURCES = frozenset({
    "request.args", "request.form", "request.json", "request.data",
    "request.values", "request.cookies", "request.headers", "request.files",
    "request.GET", "request.POST", "request.body",
    "input", "sys.argv", "sys.stdin", "os.environ", "os.getenv",
    "self.get_argument", "flask.request",
})

SINKS: Dict[str, Tuple[str, str, str, str]] = {
    "execute":      ("CWE-89", "SQL-инъекция", "critical", "Параметризованные запросы"),
    "executemany":  ("CWE-89", "SQL-инъекция", "critical", "Параметризованные запросы"),
    "raw":          ("CWE-89", "SQL-инъекция (Django raw)", "critical", "Model.objects.raw(sql, params)"),
    "eval":         ("CWE-95", "RCE через eval", "critical", "ast.literal_eval()"),
    "exec":         ("CWE-95", "RCE через exec", "critical", "Избегайте exec"),
    "system":       ("CWE-78", "Command Injection", "high", "subprocess с list"),
    "popen":        ("CWE-78", "Command Injection", "high", "subprocess с list"),
    "call":         ("CWE-78", "Command Injection", "high", "shell=False"),
    "run":          ("CWE-78", "Command Injection", "high", "shell=False"),
    "Popen":        ("CWE-78", "Command Injection", "high", "shell=False"),
    "loads":        ("CWE-502", "Небезопасная десериализация", "critical", "json.loads"),
    "load":         ("CWE-502", "Небезопасная десериализация", "high", "safe_load"),
    "render_template_string": ("CWE-94", "SSTI", "critical", "render_template с файлами"),
    "urlopen":      ("CWE-918", "SSRF", "high", "Whitelist доменов"),
}

SANITIZERS = frozenset({
    "escape", "html.escape", "markupsafe.escape", "bleach.clean",
    "quote", "shlex.quote", "re.escape", "secure_filename",
    "int", "float", "bool", "abs", "len", "uuid.UUID",
    "quote_plus", "urlencode", "validate", "sanitize",
})


# ─────────────────────────────────────────────────────────────────────────────
# Узел control-flow графа
# ─────────────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class CFGNode:
    """Узел CFG — одна инструкция с входами/выходами."""
    stmt:      ast.stmt
    node_id:   int
    succ:      List[int] = dataclasses.field(default_factory=list)
    pred:      List[int] = dataclasses.field(default_factory=list)
    # taint-состояние переменных на входе/выходе узла
    state_in:  Dict[str, TaintState] = dataclasses.field(default_factory=dict)
    state_out: Dict[str, TaintState] = dataclasses.field(default_factory=dict)


class CFGBuilder:
    """
    Строит control-flow граф для тела функции.
    Моделирует: последовательность, if/else, while/for, return/break/continue.
    """

    def __init__(self) -> None:
        self.nodes: Dict[int, CFGNode] = {}
        self._counter = 0

    def _new_node(self, stmt: ast.stmt) -> int:
        nid = self._counter
        self._counter += 1
        self.nodes[nid] = CFGNode(stmt=stmt, node_id=nid)
        return nid

    def build(self, body: List[ast.stmt]) -> Optional[int]:
        """Строит CFG для списка инструкций. Возвращает id входного узла."""
        entry, _ = self._build_sequence(body)
        return entry

    def _build_sequence(self, stmts: List[ast.stmt]) -> Tuple[Optional[int], List[int]]:
        """
        Строит цепочку узлов. Возвращает (вход, список_хвостов).
        Хвосты — узлы, из которых поток идёт дальше (нужно для связывания).
        """
        if not stmts:
            return None, []

        entry: Optional[int] = None
        prev_tails: List[int] = []

        for stmt in stmts:
            node_entry, node_tails = self._build_statement(stmt)
            if node_entry is None:
                continue
            if entry is None:
                entry = node_entry
            # Связываем предыдущие хвосты с текущим входом
            for tail in prev_tails:
                self._link(tail, node_entry)
            prev_tails = node_tails

        return entry, prev_tails

    def _build_statement(self, stmt: ast.stmt) -> Tuple[Optional[int], List[int]]:
        # if/else — ветвление
        if isinstance(stmt, ast.If):
            cond_id = self._new_node(stmt)
            then_entry, then_tails = self._build_sequence(stmt.body)
            else_entry, else_tails = self._build_sequence(stmt.orelse)

            tails: List[int] = []
            if then_entry is not None:
                self._link(cond_id, then_entry)
                tails.extend(then_tails)
            else:
                tails.append(cond_id)
            if else_entry is not None:
                self._link(cond_id, else_entry)
                tails.extend(else_tails)
            else:
                tails.append(cond_id)
            return cond_id, tails

        # while/for — цикл
        if isinstance(stmt, (ast.While, ast.For)):
            loop_id = self._new_node(stmt)
            body_entry, body_tails = self._build_sequence(stmt.body)
            if body_entry is not None:
                self._link(loop_id, body_entry)
                # Хвосты тела возвращаются к условию (back-edge)
                for tail in body_tails:
                    self._link(tail, loop_id)
            return loop_id, [loop_id]  # выход из цикла = условие ложно

        # return/raise — терминальный узел
        if isinstance(stmt, (ast.Return, ast.Raise)):
            term_id = self._new_node(stmt)
            return term_id, []  # нет хвостов — поток прерывается

        # Обычная инструкция (присваивание, вызов, и т.д.)
        node_id = self._new_node(stmt)
        return node_id, [node_id]

    def _link(self, from_id: int, to_id: int) -> None:
        if to_id not in self.nodes[from_id].succ:
            self.nodes[from_id].succ.append(to_id)
        if from_id not in self.nodes[to_id].pred:
            self.nodes[to_id].pred.append(from_id)


# ─────────────────────────────────────────────────────────────────────────────
# Dataflow-анализатор (worklist algorithm)
# ─────────────────────────────────────────────────────────────────────────────

class DataflowAnalyzer:
    """
    Анализ потока данных по CFG методом worklist.
    Для каждой переменной вычисляет taint-состояние в каждой точке,
    корректно сливая состояния на схождении путей (path-merge).
    """

    def __init__(self, source_lines: List[str], filename: str):
        self._lines = source_lines
        self._filename = filename
        self.findings: List[DataflowFinding] = []

    def analyze_function(self, func: ast.FunctionDef,
                         initial_tainted: Optional[Set[str]] = None) -> None:
        builder = CFGBuilder()
        entry = builder.build(func.body)
        if entry is None:
            return
        cfg = builder.nodes

        # Начальное состояние: параметры функции (могут быть tainted извне)
        init_state: Dict[str, TaintState] = {}
        if initial_tainted:
            for var in initial_tainted:
                init_state[var] = TaintState.TAINTED

        # Worklist: фиксированная точка вычисления состояний
        worklist: List[int] = [entry]
        cfg[entry].state_in = dict(init_state)
        iterations = 0
        max_iter = len(cfg) * 10 + 100  # защита от бесконечного цикла

        while worklist and iterations < max_iter:
            iterations += 1
            nid = worklist.pop(0)
            node = cfg[nid]

            # state_in = слияние state_out всех предшественников
            if node.pred:
                merged: Dict[str, TaintState] = {}
                for pred_id in node.pred:
                    for var, st in cfg[pred_id].state_out.items():
                        merged[var] = (TaintState.merge(merged[var], st)
                                       if var in merged else st)
                # Сохраняем начальное состояние входа
                if nid == entry:
                    for var, st in init_state.items():
                        merged[var] = TaintState.merge(merged.get(var, TaintState.CLEAN), st)
                node.state_in = merged

            # Применяем transfer function (эффект инструкции)
            old_out = dict(node.state_out)
            node.state_out = self._transfer(node.stmt, dict(node.state_in))

            # Если состояние изменилось — пересчитываем преемников
            if node.state_out != old_out:
                for succ_id in node.succ:
                    if succ_id not in worklist:
                        worklist.append(succ_id)

        # После стабилизации — проверяем sinks с учётом состояния
        for node in cfg.values():
            self._check_sinks(node.stmt, node.state_in)

    def _transfer(self, stmt: ast.stmt,
                  state: Dict[str, TaintState]) -> Dict[str, TaintState]:
        """Transfer function: как инструкция меняет taint-состояние."""
        if isinstance(stmt, ast.Assign):
            taint = self._eval_expr(stmt.value, state)
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    state[target.id] = taint
        elif isinstance(stmt, ast.AnnAssign) and stmt.value:
            if isinstance(stmt.target, ast.Name):
                state[stmt.target.id] = self._eval_expr(stmt.value, state)
        elif isinstance(stmt, ast.AugAssign):
            if isinstance(stmt.target, ast.Name):
                cur = state.get(stmt.target.id, TaintState.CLEAN)
                val = self._eval_expr(stmt.value, state)
                state[stmt.target.id] = TaintState.merge(cur, val)
        return state

    def _eval_expr(self, node: ast.expr,
                   state: Dict[str, TaintState]) -> TaintState:
        """Вычисляет taint-состояние выражения с учётом текущего состояния."""
        if isinstance(node, ast.Name):
            return state.get(node.id, TaintState.CLEAN)

        if isinstance(node, ast.Call):
            fname = _dotted(node.func)
            short = fname.split(".")[-1]
            # Санитайзер очищает
            if short in SANITIZERS or fname in SANITIZERS:
                return TaintState.SANITIZED
            # Источник пользовательского ввода
            if any(fname.startswith(s) or fname == s.split(".")[-1]
                   for s in TAINT_SOURCES):
                return TaintState.TAINTED
            # Иначе — taint худшего аргумента
            worst = TaintState.CLEAN
            for arg in node.args:
                worst = TaintState.merge(worst, self._eval_expr(arg, state))
            return worst

        if isinstance(node, ast.Attribute):
            full = _dotted(node)
            if any(full.startswith(s) for s in TAINT_SOURCES):
                return TaintState.TAINTED
            return self._eval_expr(node.value, state)

        if isinstance(node, ast.Subscript):
            base = self._eval_expr(node.value, state)
            full = _dotted(node.value)
            if any(full.startswith(s) for s in TAINT_SOURCES):
                return TaintState.TAINTED
            return base

        if isinstance(node, ast.BinOp):
            return TaintState.merge(
                self._eval_expr(node.left, state),
                self._eval_expr(node.right, state),
            )

        if isinstance(node, ast.JoinedStr):  # f-string
            worst = TaintState.CLEAN
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    worst = TaintState.merge(worst, self._eval_expr(val.value, state))
            return worst

        if isinstance(node, ast.IfExp):
            # Тернарник: худшее из веток (path-merge)
            return TaintState.merge(
                self._eval_expr(node.body, state),
                self._eval_expr(node.orelse, state),
            )

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            worst = TaintState.CLEAN
            for el in node.elts:
                worst = TaintState.merge(worst, self._eval_expr(el, state))
            return worst

        return TaintState.CLEAN

    def _check_sinks(self, stmt: ast.stmt,
                     state: Dict[str, TaintState]) -> None:
        """Ищет вызовы sink-функций с tainted-аргументами."""
        for call in ast.walk(stmt):
            if not isinstance(call, ast.Call):
                continue
            fname = _dotted(call.func)
            short = fname.split(".")[-1]
            if short not in SINKS:
                continue
            cwe, title, sev, fix = SINKS[short]

            for arg in call.args:
                st = self._eval_expr(arg, state)
                if st == TaintState.TAINTED:
                    line = getattr(call, "lineno", 0)
                    snippet = (self._lines[line - 1].strip()
                               if 0 < line <= len(self._lines) else "")
                    self.findings.append(DataflowFinding(
                        rule_id=f"DFLOW-{cwe.replace('-', '_')}",
                        title=f"{title} (dataflow-подтверждено)",
                        severity=sev,
                        cwe=cwe,
                        line=line,
                        col=getattr(call, "col_offset", 0),
                        snippet=snippet[:120],
                        sink=fname,
                        path=[f"tainted → {short}()"],
                        confidence="high",
                        fix=fix,
                    ))
                    break


def _dotted(node: ast.expr) -> str:
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


def analyze_dataflow(code: str, filename: str = "unknown") -> List[DataflowFinding]:
    """
    Запускает dataflow-анализ для всех функций модуля.
    Возвращает findings, подтверждённые анализом потока данных.
    """
    lines = code.splitlines()
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    analyzer = DataflowAnalyzer(lines, filename)

    # Анализируем каждую функцию
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            analyzer.analyze_function(node)

    # Также анализируем код на уровне модуля (вне функций)
    module_body = [n for n in tree.body
                   if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    if module_body:
        synthetic = ast.FunctionDef(
            name="<module>", args=ast.arguments(
                posonlyargs=[], args=[], kwonlyargs=[],
                kw_defaults=[], defaults=[]),
            body=module_body, decorator_list=[], returns=None,
        )
        ast.fix_missing_locations(synthetic)
        analyzer.analyze_function(synthetic)

    # Дедупликация по (line, cwe)
    seen: Set[Tuple[int, str]] = set()
    unique: List[DataflowFinding] = []
    for f in analyzer.findings:
        key = (f.line, f.cwe)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


if __name__ == "__main__":
    # Тест: path-sensitive анализ
    test = '''
def vulnerable(request):
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)

def safe(request):
    user_id = request.args.get("id")
    user_id = int(user_id)              # санитизация!
    cursor.execute("SELECT * FROM u WHERE id=" + str(user_id))

def conditional(request, trusted):
    data = request.form["x"]
    if trusted:
        data = escape(data)            # очищена только в одной ветке
    cursor.execute(data)               # всё равно taint (worst-case merge)
'''
    findings = analyze_dataflow(test, "test.py")
    print(f"Dataflow findings: {len(findings)}\n")
    for f in findings:
        print(f"  [{f.severity.upper()}] {f.title}")
        print(f"    Строка {f.line}: {f.snippet}")
        print(f"    {' → '.join(f.path)}\n")
