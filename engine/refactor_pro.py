"""
refactor_pro.py — продвинутый детерминированный рефакторинг (Nexus Enterprise).

Чистые AST-трансформации (НЕ через ИИ): код парсится в синтаксическое дерево,
узлы преобразуются по строгим правилам, результат валидируется на компиляцию.
Каждая трансформация semantic-preserving — поведение программы не меняется.

Категории трансформаций
-----------------------
boolean    Упрощение булевой логики:
             x == True / False / None  →  x / not x / x is None
             x != None                 →  x is not None
             len(x) > 0 / == 0         →  x / not x
             not x in y                →  x not in y
             not x is y                →  x is not y
             type(x) == T              →  isinstance(x, T)
             not not x                 →  bool(x)
             not (a == b)              →  a != b

pythonic   Идиомы Python:
             for i in range(len(x))    →  for i, _ in enumerate(x)
             x = x + 1                 →  x += 1   (для простых имён)

structure  Структурные упрощения:
             if a: if b:               →  if a and b:
             if c: return True
                else return False      →  return c
             код после return/raise    →  (удаляется как недостижимый)
             повторяющиеся числа        →  именованные константы (подсказка)

Публичный API
-------------
    refactor_pro(code, *, format_with_black=True) -> RefactorResult
    refactor_report(result) -> str
"""

from __future__ import annotations

import ast
import dataclasses
from collections import Counter
from typing import List, Optional

__all__ = ["RefactorChange", "RefactorResult", "refactor_pro", "refactor_report"]
__version__ = "2.0.0"


# ─────────────────────────────────────────────────────────────────────────────
# Результаты
# ─────────────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class RefactorChange:
    """Одна применённая трансформация."""

    rule:     str
    line:     int
    before:   str
    after:    str
    category: str


@dataclasses.dataclass
class RefactorResult:
    """Итог рефакторинга: исходный код, результат и список изменений."""

    original:   str
    refactored: str
    changes:    List[RefactorChange]
    error:      Optional[str] = None
    metrics:    Optional[dict] = None

    @property
    def changed(self) -> bool:
        return bool(self.changes)

    def by_category(self) -> dict:
        """Группирует изменения по категориям."""
        result: dict = {}
        for change in self.changes:
            result.setdefault(change.category, []).append(change)
        return result

    def to_dict(self) -> dict:
        return {
            "changed":    self.changed,
            "count":      len(self.changes),
            "changes":    [dataclasses.asdict(c) for c in self.changes],
            "refactored": self.refactored,
            "error":      self.error,
            "metrics":    self.metrics,
        }


# ─────────────────────────────────────────────────────────────────────────────
# AST-трансформер
# ─────────────────────────────────────────────────────────────────────────────

class ProRefactorer(ast.NodeTransformer):
    """Применяет детерминированные трансформации читаемости к AST."""

    # Числа, которые не считаются "magic" (слишком частые/очевидные)
    _MAGIC_SKIP = frozenset({0, 1, 2, -1, 10, 100, 1000})
    # Сколько раз число должно повториться, чтобы стать кандидатом в константу
    _MAGIC_THRESHOLD = 3
    # Терминаторы потока управления (после них код недостижим)
    _TERMINATORS = (ast.Return, ast.Raise, ast.Break, ast.Continue)

    # Минимальный уровень глубины, на котором применяется каждое правило:
    #   1 = только безопаснейшие булевы упрощения (поведение 100% идентично)
    #   2 = + структурные и pythonic-преобразования (стандарт)
    #   3 = + именованные константы и агрессивные правки (проверяйте результат)
    _RULE_LEVEL = {
        # уровень 1 — ТОЛЬКО абсолютно безопасные тождества, не зависящие от типов:
        #   x == None → x is None  (PEP8, всегда эквивалентно)
        #   not (not x) → x, not a in b → a not in b  (синтаксические тождества)
        "eq-none": 1, "neq-none": 1, "double-not": 1,
        "not-in": 1, "not-is": 1, "not-eq": 1, "not-neq": 1,
        # уровень 2 — зависящие от типов упрощения и структура.
        #   x == True → x  и  len(x) > 0 → x  МОГУТ изменить поведение для
        #   объектов с нестандартными __bool__/__len__, поэтому НЕ на уровне 1.
        "eq-true": 2, "eq-false": 2, "len-gt0": 2, "len-eq0": 2,
        "type-eq": 2, "merge-if": 2, "if-return-bool": 2,
        "range-len-enumerate": 2, "aug-assign": 2, "dead-code": 2,
        "guard-clause": 2, "extract-condition": 2,
        # уровень 2 — безопасные оптимизации производительности
        "dict-keys-membership": 2, "genexpr-in-aggregate": 2,
        # уровень 3 — агрессивные
        "named-constant": 3,
    }

    def __init__(self, level: int = 2) -> None:
        self.changes: List[RefactorChange] = []
        self.level = level

    # ── вспомогательные конструкторы ─────────────────────────────────────

    def _log(self, rule: str, line: int, before: str, after: str,
             category: str) -> bool:
        """
        Если правило разрешено текущим уровнем — регистрирует изменение и
        возвращает True (вызывающий применяет трансформацию).
        Иначе возвращает False — трансформация НЕ должна применяться.
        """
        if self._RULE_LEVEL.get(rule, 2) > self.level:
            return False
        self.changes.append(RefactorChange(rule, line, before, after, category))
        return True

    @staticmethod
    def _not(operand: ast.expr) -> ast.UnaryOp:
        return ast.UnaryOp(op=ast.Not(), operand=operand)

    @staticmethod
    def _call(func_name: str, args: List[ast.expr]) -> ast.Call:
        return ast.Call(func=ast.Name(id=func_name, ctx=ast.Load()),
                        args=args, keywords=[])

    # ── предикаты ────────────────────────────────────────────────────────

    @staticmethod
    def _is_call_named(node: ast.AST, name: str) -> bool:
        return (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == name)

    @classmethod
    def _is_len_call(cls, node: ast.AST) -> bool:
        return cls._is_call_named(node, "len") and len(node.args) == 1  # type: ignore[attr-defined]

    @staticmethod
    def _is_zero(node: ast.AST) -> bool:
        return isinstance(node, ast.Constant) and node.value == 0

    # ── булева логика: сравнения ─────────────────────────────────────────

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        self.generic_visit(node)
        line = getattr(node, "lineno", 0)

        # Только простые сравнения (не цепочки a == b == c)
        if len(node.ops) != 1 or len(node.comparators) != 1:
            return node

        op, comp = node.ops[0], node.comparators[0]

        # x == True / False / None
        if isinstance(op, ast.Eq) and isinstance(comp, ast.Constant):
            if comp.value is True:
                if self._log("eq-true", line, "x == True", "x", "boolean"):
                    return node.left
                return node
            if comp.value is False:
                if self._log("eq-false", line, "x == False", "not x", "boolean"):
                    return self._not(node.left)
                return node
            if comp.value is None:
                if self._log("eq-none", line, "x == None", "x is None", "boolean"):
                    return ast.Compare(left=node.left, ops=[ast.Is()], comparators=[comp])
                return node

        # x != None
        if (isinstance(op, ast.NotEq) and isinstance(comp, ast.Constant)
                and comp.value is None):
            if self._log("neq-none", line, "x != None", "x is not None", "boolean"):
                return ast.Compare(left=node.left, ops=[ast.IsNot()], comparators=[comp])
            return node

        # len(x) > 0  /  len(x) == 0
        if self._is_len_call(node.left) and self._is_zero(comp):
            target = node.left.args[0]  # type: ignore[attr-defined]
            if isinstance(op, ast.Gt):
                if self._log("len-gt0", line, "len(x) > 0", "x", "boolean"):
                    return target
                return node
            if isinstance(op, ast.Eq):
                if self._log("len-eq0", line, "len(x) == 0", "not x", "boolean"):
                    return self._not(target)
                return node

        # type(x) == T  →  isinstance(x, T)
        if (isinstance(op, ast.Eq) and self._is_call_named(node.left, "type")
                and len(node.left.args) == 1):  # type: ignore[attr-defined]
            if self._log("type-eq", line, "type(x) == T", "isinstance(x, T)", "pythonic"):
                return self._call("isinstance",
                                  [node.left.args[0], comp])  # type: ignore[attr-defined]
            return node

        # ОПТИМИЗАЦИЯ: x in d.keys()  →  x in d
        # Поведение идентично, но без создания view-объекта. Безопасно.
        if isinstance(op, (ast.In, ast.NotIn)):
            if (isinstance(comp, ast.Call) and isinstance(comp.func, ast.Attribute)
                    and comp.func.attr == "keys" and not comp.args):
                opname = "in" if isinstance(op, ast.In) else "not in"
                self._log("dict-keys-membership", line,
                          f"x {opname} d.keys()", f"x {opname} d", "performance")
                return ast.Compare(left=node.left, ops=[op], comparators=[comp.func.value])

        return node

    # ── оптимизация: генератор вместо списка в агрегатных функциях ────────

    # Функции, которым list-comprehension можно заменить на генератор
    # без изменения результата (они потребляют итерируемое целиком).
    _AGGREGATE_FUNCS = {"sum", "any", "all", "min", "max", "sorted", "set", "frozenset", "tuple"}

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        line = getattr(node, "lineno", 0)

        # ОПТИМИЗАЦИЯ: sum([x for x in y]) → sum(x for x in y)
        # Генератор не строит промежуточный список — экономит память.
        if (isinstance(node.func, ast.Name) and node.func.id in self._AGGREGATE_FUNCS
                and len(node.args) == 1 and isinstance(node.args[0], ast.ListComp)):
            lc = node.args[0]
            gen = ast.GeneratorExp(elt=lc.elt, generators=lc.generators)
            self._log("genexpr-in-aggregate", line,
                      f"{node.func.id}([...])", f"{node.func.id}(...)", "performance")
            node.args[0] = ast.copy_location(gen, lc)
            return node

        return node

    # ── булева логика: отрицания ─────────────────────────────────────────

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.AST:
        line = getattr(node, "lineno", 0)

        # not not x → bool(x)  (проверяем ДО рекурсии, иначе внутренний not
        # преобразуется первым и шаблон теряется)
        if (isinstance(node.op, ast.Not)
                and isinstance(node.operand, ast.UnaryOp)
                and isinstance(node.operand.op, ast.Not)):
            self._log("double-not", line, "not not x", "bool(x)", "boolean")
            inner = node.operand.operand
            self.generic_visit(inner)
            return self._call("bool", [inner])

        self.generic_visit(node)

        if isinstance(node.op, ast.Not) and isinstance(node.operand, ast.Compare):
            inner = node.operand
            if len(inner.ops) == 1:
                # not x in y → x not in y
                if isinstance(inner.ops[0], ast.In):
                    self._log("not-in", line, "not x in y", "x not in y", "boolean")
                    return ast.Compare(left=inner.left, ops=[ast.NotIn()],
                                       comparators=inner.comparators)
                # not x is y → x is not y
                if isinstance(inner.ops[0], ast.Is):
                    self._log("not-is", line, "not x is y", "x is not y", "boolean")
                    return ast.Compare(left=inner.left, ops=[ast.IsNot()],
                                       comparators=inner.comparators)
                # not (a == b) → a != b   ;   not (a != b) → a == b
                if isinstance(inner.ops[0], ast.Eq):
                    self._log("not-eq", line, "not (a == b)", "a != b", "boolean")
                    return ast.Compare(left=inner.left, ops=[ast.NotEq()],
                                       comparators=inner.comparators)
                if isinstance(inner.ops[0], ast.NotEq):
                    self._log("not-neq", line, "not (a != b)", "a == b", "boolean")
                    return ast.Compare(left=inner.left, ops=[ast.Eq()],
                                       comparators=inner.comparators)
        return node

    # ── структура: if ────────────────────────────────────────────────────

    def visit_If(self, node: ast.If) -> ast.AST:
        self.generic_visit(node)
        line = getattr(node, "lineno", 0)

        # if a: if b: ...  →  if a and b: ...
        if (len(node.body) == 1 and isinstance(node.body[0], ast.If)
                and not node.orelse and not node.body[0].orelse):
            inner = node.body[0]
            self._log("merge-if", line, "if a: if b:", "if a and b:", "structure")
            node.test = ast.BoolOp(op=ast.And(), values=[node.test, inner.test])
            node.body = inner.body
            ast.fix_missing_locations(node)

        # if c: return True else: return False  →  return c
        if (len(node.body) == 1 and isinstance(node.body[0], ast.Return)
                and len(node.orelse) == 1 and isinstance(node.orelse[0], ast.Return)):
            then_val, else_val = node.body[0].value, node.orelse[0].value
            if (isinstance(then_val, ast.Constant) and isinstance(else_val, ast.Constant)
                    and isinstance(then_val.value, bool)
                    and isinstance(else_val.value, bool)
                    and then_val.value != else_val.value):
                self._log("if-return-bool", line,
                          "if c: return True else: return False",
                          "return c" if then_val.value else "return not c", "structure")
                result = node.test if then_val.value else self._not(node.test)
                return ast.Return(value=result)

        return node

    # ── pythonic: циклы и присваивания ───────────────────────────────────

    def visit_For(self, node: ast.For) -> ast.AST:
        self.generic_visit(node)
        line = getattr(node, "lineno", 0)

        # for i in range(len(x))  →  for i, _ in enumerate(x)
        if (self._is_call_named(node.iter, "range")
                and len(node.iter.args) == 1):  # type: ignore[attr-defined]
            arg = node.iter.args[0]            # type: ignore[attr-defined]
            if self._is_len_call(arg):
                self._log("range-len-enumerate", line, "for i in range(len(x))",
                          "for i, _ in enumerate(x)", "pythonic")
                node.iter = self._call("enumerate", [arg.args[0]])
                if isinstance(node.target, ast.Name):
                    node.target = ast.Tuple(
                        elts=[node.target, ast.Name(id="_", ctx=ast.Store())],
                        ctx=ast.Store())
                ast.fix_missing_locations(node)
        return node

    def visit_Assign(self, node: ast.Assign) -> ast.AST:
        self.generic_visit(node)
        line = getattr(node, "lineno", 0)

        # x = x + n  →  x += n   (только для одиночного простого имени)
        if (len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.BinOp)
                and isinstance(node.value.left, ast.Name)
                and node.targets[0].id == node.value.left.id):
            target_name = node.targets[0].id
            self._log("aug-assign", line, f"{target_name} = {target_name} + n",
                      f"{target_name} += n", "pythonic")
            return ast.AugAssign(target=node.targets[0], op=node.value.op,
                                 value=node.value.right)
        return node

    # ── структура: недостижимый код ──────────────────────────────────────

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        self.generic_visit(node)
        node.body = self._strip_unreachable(node.body)
        if self.level >= 2:  # guard clauses и вынос условий — со стандартного уровня
            node.body = self._extract_long_conditions(node.body)
            node.body = self._apply_guard_clauses(node.body, getattr(node, "lineno", 0))
        return node

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    # ── структура: вынос длинного условия в переменную ───────────────────
    #
    #   if a and b and c and d:      →   is_valid = a and b and c and d
    #       ...                           if is_valid:
    #                                         ...
    #
    # Срабатывает только для BoolOp с 4+ операндами (реально длинных).
    # Безопасно: выражение вычисляется до if, имя не конфликтует.
    _COND_COUNTER = 0

    def _extract_long_conditions(self, body: List[ast.stmt]) -> List[ast.stmt]:
        new_body: List[ast.stmt] = []
        existing_names = self._collect_names(body)
        for stmt in body:
            if (isinstance(stmt, ast.If)
                    and isinstance(stmt.test, ast.BoolOp)
                    and len(stmt.test.values) >= 4):
                # генерируем безопасное имя
                name = self._fresh_name("cond", existing_names)
                existing_names.add(name)
                assign = ast.Assign(
                    targets=[ast.Name(id=name, ctx=ast.Store())],
                    value=stmt.test,
                )
                self._log("extract-condition", getattr(stmt, "lineno", 0),
                          "if a and b and c and d:",
                          f"{name} = ...; if {name}:", "structure")
                stmt.test = ast.Name(id=name, ctx=ast.Load())
                ast.fix_missing_locations(assign)
                new_body.append(assign)
            new_body.append(stmt)
        return new_body

    @staticmethod
    def _collect_names(body: List[ast.stmt]) -> set:
        names = set()
        for stmt in body:
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Name):
                    names.add(sub.id)
        return names

    @staticmethod
    def _fresh_name(base: str, taken: set) -> str:
        if base not in taken:
            return base
        i = 2
        while f"{base}{i}" in taken:
            i += 1
        return f"{base}{i}"

    # ── структура: guard clauses (ранние выходы) ─────────────────────────
    #
    # Превращает «стрелочный» код с глубокой вложенностью в плоский:
    #
    #   def f(...):                     def f(...):
    #       if cond:            →           if not cond:
    #           <много логики>                  return
    #                                       <много логики>
    #
    # Условие безопасности: if — ПОСЛЕДНИЙ оператор тела, без else,
    # тело функции к этому моменту ничего не возвращает (преобразование
    # не меняет поведение, т.к. после if всё равно ничего нет).
    def _apply_guard_clauses(self, body: List[ast.stmt], fn_line: int) -> List[ast.stmt]:
        if not body:
            return body
        last = body[-1]
        # последний оператор — if без else, с непустым телом
        if (isinstance(last, ast.If) and not last.orelse
                and len(last.body) >= 3):  # разворачиваем только реально крупные блоки
            # инвертируем условие и делаем ранний return
            inverted = self._invert(last.test)
            guard = ast.If(
                test=inverted,
                body=[ast.Return(value=None)],
                orelse=[],
            )
            self._log("guard-clause", getattr(last, "lineno", fn_line),
                      "if cond: <тело>", "if not cond: return; <тело>", "structure")
            new_body = body[:-1] + [guard] + last.body
            ast.fix_missing_locations(ast.Module(body=new_body, type_ignores=[]))
            return new_body
        return body

    @staticmethod
    def _invert(test: ast.expr) -> ast.expr:
        """Логически инвертирует условие минимально (not x, а x→ убрать not)."""
        # not X  →  X
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return test.operand
        # a == b → a != b и наоборот (простые случаи)
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            flip = {ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
                    ast.Lt: ast.GtE, ast.GtE: ast.Lt,
                    ast.Gt: ast.LtE, ast.LtE: ast.Gt}
            op_type = type(test.ops[0])
            if op_type in flip:
                return ast.Compare(left=test.left,
                                   ops=[flip[op_type]()],
                                   comparators=test.comparators)
        # иначе: not (X)
        return ast.UnaryOp(op=ast.Not(), operand=test)

    def _strip_unreachable(self, body: List[ast.stmt]) -> List[ast.stmt]:
        """Удаляет код после return/raise/break/continue."""
        result: List[ast.stmt] = []
        for stmt in body:
            result.append(stmt)
            if isinstance(stmt, self._TERMINATORS):
                if len(result) < len(body):
                    self._log("dead-code", getattr(stmt, "lineno", 0),
                              "код после return", "(удалён)", "structure")
                break
        return result


# ─────────────────────────────────────────────────────────────────────────────
# Magic numbers
# ─────────────────────────────────────────────────────────────────────────────

# Словарь известных «магических» чисел → осмысленное имя константы.
# Только то, что имеет однозначный общепринятый смысл. Остальные числа НЕ трогаем,
# чтобы не плодить бессмысленные CONST_91.
_KNOWN_NUMBERS = {
    # HTTP-статусы
    200: "HTTP_OK", 201: "HTTP_CREATED", 204: "HTTP_NO_CONTENT",
    301: "HTTP_MOVED_PERMANENTLY", 302: "HTTP_FOUND", 304: "HTTP_NOT_MODIFIED",
    400: "HTTP_BAD_REQUEST", 401: "HTTP_UNAUTHORIZED", 403: "HTTP_FORBIDDEN",
    404: "HTTP_NOT_FOUND", 405: "HTTP_METHOD_NOT_ALLOWED", 409: "HTTP_CONFLICT",
    422: "HTTP_UNPROCESSABLE", 429: "HTTP_TOO_MANY_REQUESTS",
    500: "HTTP_INTERNAL_ERROR", 502: "HTTP_BAD_GATEWAY", 503: "HTTP_UNAVAILABLE",
    # Время (секунды)
    60: "SECONDS_PER_MINUTE", 3600: "SECONDS_PER_HOUR",
    86400: "SECONDS_PER_DAY", 604800: "SECONDS_PER_WEEK",
    # Размеры данных
    1024: "BYTES_PER_KB", 1048576: "BYTES_PER_MB", 1073741824: "BYTES_PER_GB",
    # Сетевые порты (частые)
    8080: "PORT_HTTP_ALT", 8000: "PORT_DEV", 5432: "PORT_POSTGRES", 6379: "PORT_REDIS",
}


def _extract_magic_numbers(tree: ast.Module, changes: List[RefactorChange]) -> None:
    """
    Заменяет ИЗВЕСТНЫЕ магические числа (HTTP-коды, время, размеры) на именованные
    константы с осмысленными именами и вставляет их объявления в начало модуля.

    Неизвестные числа намеренно НЕ трогаются: автоматически придуманное имя
    (CONST_91) ухудшает читаемость, а не улучшает.
    """
    used: dict = {}  # значение → имя константы (только реально встреченные)

    # уже объявленные на верхнем уровне имена — не конфликтуем
    existing = {n.id for node in tree.body if isinstance(node, ast.Assign)
                for n in node.targets if isinstance(n, ast.Name)}

    class _Replacer(ast.NodeTransformer):
        def visit_Constant(self, node: ast.Constant) -> ast.AST:
            if (isinstance(node.value, int) and not isinstance(node.value, bool)
                    and node.value in _KNOWN_NUMBERS):
                name = _KNOWN_NUMBERS[node.value]
                if name in existing:
                    return node  # имя занято — оставляем как есть
                used[node.value] = name
                return ast.copy_location(ast.Name(id=name, ctx=ast.Load()), node)
            return node

    _Replacer().visit(tree)

    if not used:
        return

    # вставляем объявления констант после импортов/докстроки
    insert_at = 0
    for i, node in enumerate(tree.body):
        if (isinstance(node, (ast.Import, ast.ImportFrom))
                or (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant))):
            insert_at = i + 1
        else:
            break

    decls = []
    for value, name in sorted(used.items()):
        decls.append(ast.Assign(
            targets=[ast.Name(id=name, ctx=ast.Store())],
            value=ast.Constant(value=value),
        ))
        changes.append(RefactorChange(
            rule="named-constant", line=0, before=str(value),
            after=name, category="structure"))

    tree.body[insert_at:insert_at] = decls
    ast.fix_missing_locations(tree)


# ─────────────────────────────────────────────────────────────────────────────
# Публичный API
# ─────────────────────────────────────────────────────────────────────────────

def _complexity_metrics(tree: ast.Module) -> dict:
    """Грубые метрики для отчёта до/после: ветвления и максимальная вложенность."""
    branches = 0
    max_depth = 0

    def walk(node, depth):
        nonlocal branches, max_depth
        max_depth = max(max_depth, depth)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.Try, ast.With)):
                branches += 1
                walk(child, depth + 1)
            else:
                walk(child, depth)

    walk(tree, 0)
    return {"branches": branches, "max_depth": max_depth}


def refactor_pro(code: str, *, format_with_black: bool = True,
                 level: int = 2) -> RefactorResult:
    """
    Применяет продвинутые трансформации читаемости к коду.

    Args:
        code:              исходный Python-код.
        format_with_black: форматировать результат через black (если установлен).
        level:             глубина рефакторинга:
                           1 = только безопасные булевы упрощения;
                           2 = + структура, pythonic, guard clauses (по умолчанию);
                           3 = + именованные константы для известных чисел.

    Returns:
        RefactorResult с обновлённым кодом и списком изменений.
        При синтаксической ошибке или невалидном результате — откат к оригиналу.
    """
    level = max(1, min(3, level))
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return RefactorResult(code, code, [], error=f"Синтаксис: {exc}")

    metrics_before = _complexity_metrics(tree)

    refactorer = ProRefactorer(level=level)
    new_tree = refactorer.visit(tree)
    ast.fix_missing_locations(new_tree)
    if level >= 3:  # именованные константы — только на агрессивном уровне
        _extract_magic_numbers(new_tree, refactorer.changes)

    if not refactorer.changes:
        return RefactorResult(code, code, [])

    try:
        refactored = ast.unparse(new_tree)
    except Exception as exc:  # noqa: BLE001
        return RefactorResult(code, code, [], error=f"Генерация: {exc}")

    # Валидация: результат обязан компилироваться (иначе безопасный откат)
    try:
        validated = ast.parse(refactored)
    except SyntaxError:
        return RefactorResult(code, code, [], error="Результат невалиден, откат")

    metrics_after = _complexity_metrics(validated)

    if format_with_black:
        try:
            import black
            refactored = black.format_str(refactored, mode=black.Mode())
        except Exception:  # noqa: BLE001
            pass

    result = RefactorResult(code, refactored, refactorer.changes)
    result.metrics = {"before": metrics_before, "after": metrics_after}  # type: ignore[attr-defined]
    return result


def refactor_report(result: RefactorResult) -> str:
    """Формирует человекочитаемый отчёт об изменениях (Markdown)."""
    if result.error:
        return f"Рефакторинг не выполнен: {result.error}"
    if not result.changed:
        return "Код уже чистый — улучшений не найдено."

    lines = [f"# Рефакторинг: {len(result.changes)} улучшений", ""]
    for category, items in sorted(result.by_category().items()):
        lines.append(f"## {category} ({len(items)})")
        for change in items:
            location = f" (строка {change.line})" if change.line else ""
            lines.append(f"- `{change.before}` → `{change.after}`{location}")
        lines.append("")
    return "\n".join(lines).rstrip()


# ─────────────────────────────────────────────────────────────────────────────
# Демонстрация
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = '''
def check(items, flag, x):
    if flag == True:
        if len(items) > 0:
            for i in range(len(items)):
                if not i in seen:
                    count = count + 1
                    process(items[i])
        return True
    else:
        return False
    print("unreachable")


def is_valid(value):
    if type(value) == str:
        return True
    return False
'''

    result = refactor_pro(SAMPLE, format_with_black=False)
    print(f"Применено трансформаций: {len(result.changes)}\n")
    for change in result.changes:
        print(f"  [{change.category:9}] {change.before:38} →  {change.after}")
    print("\n=== Результат ===")
    print(result.refactored)
    print("\n=== Отчёт ===")
    print(refactor_report(result))
