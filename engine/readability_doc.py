"""
Повышение читаемости: генерация docstring-заготовок и детальный разбор функций.

Принцип: НЕ выдумывать смысл (это умеет только автор или ИИ), а извлекать
из кода объективную структуру — параметры, возвращаемое значение, исключения,
внешние вызовы — и оформлять как заготовку, которую человек дополнит.
Так читаемость растёт без риска вписать неверный комментарий.
"""
from __future__ import annotations

import ast
from typing import List, Dict, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Детальный разбор одной функции (объективные факты из AST)
# ─────────────────────────────────────────────────────────────────────────────

def describe_function(node: ast.AST, source_lines: List[str]) -> Dict:
    """Возвращает структурный разбор функции: сигнатура, возврат, вызовы, риски."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return {}

    params = _params(node)
    returns = _return_info(node)
    raises = sorted({_exc_name(h) for h in ast.walk(node)
                     if isinstance(h, ast.Raise) and h.exc is not None})
    calls = _external_calls(node)
    has_doc = ast.get_docstring(node) is not None

    # человекочитаемое описание поведения (структурное, без догадок о смысле)
    behavior: List[str] = []
    if params:
        behavior.append("принимает " + ", ".join(p["name"] for p in params))
    else:
        behavior.append("не принимает аргументов")
    if returns["returns_value"]:
        behavior.append("возвращает значение")
    else:
        behavior.append("ничего не возвращает")
    if calls:
        shown = ", ".join(calls[:5])
        behavior.append(f"вызывает {shown}" + ("…" if len(calls) > 5 else ""))
    if raises:
        behavior.append("может бросить " + ", ".join(raises))

    return {
        "name": node.name,
        "line": getattr(node, "lineno", 0),
        "is_async": isinstance(node, ast.AsyncFunctionDef),
        "params": params,
        "returns": returns,
        "raises": raises,
        "calls": calls,
        "has_docstring": has_doc,
        "behavior": "Функция " + ", ".join(behavior) + ".",
    }


def _params(node) -> List[Dict]:
    """Список параметров с аннотациями и значениями по умолчанию."""
    a = node.args
    result: List[Dict] = []
    defaults = [None] * (len(a.args) - len(a.defaults)) + list(a.defaults)
    for arg, default in zip(a.args, defaults):
        if arg.arg in ("self", "cls"):
            continue
        result.append({
            "name": arg.arg,
            "type": _annotation(arg.annotation),
            "default": _literal(default) if default is not None else None,
        })
    if a.vararg:
        result.append({"name": "*" + a.vararg.arg, "type": _annotation(a.vararg.annotation), "default": None})
    if a.kwarg:
        result.append({"name": "**" + a.kwarg.arg, "type": _annotation(a.kwarg.annotation), "default": None})
    return result


def _return_info(node) -> Dict:
    """Есть ли return со значением и аннотация возврата."""
    returns_value = any(
        isinstance(n, ast.Return) and n.value is not None for n in ast.walk(node)
    )
    return {
        "returns_value": returns_value,
        "annotation": _annotation(node.returns),
    }


def _external_calls(node) -> List[str]:
    """Имена вызываемых функций/методов (уникальные, в порядке появления).

    Исключения, которые бросаются через raise, не считаются «вызовами» —
    они попадают в раздел Raises отдельно."""
    raised = {_exc_name(n) for n in ast.walk(node)
              if isinstance(n, ast.Raise) and n.exc is not None}
    seen: List[str] = []
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            name = _call_name(n.func)
            if name and name not in seen and name != node.name and name not in raised:
                seen.append(name)
    return seen


# ─────────────────────────────────────────────────────────────────────────────
# Генерация docstring-заготовки (Google-стиль)
# ─────────────────────────────────────────────────────────────────────────────

def generate_docstring(node: ast.AST, indent: str = "    ") -> Optional[str]:
    """
    Строит заготовку docstring по сигнатуре функции.

    Заполняет объективную структуру (Args/Returns/Raises с типами из аннотаций),
    оставляя описания пустыми с пометкой TODO — их допишет человек.
    Возвращает None, если docstring уже есть.
    """
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    if ast.get_docstring(node) is not None:
        return None  # не трогаем существующие

    info = describe_function(node, [])
    lines: List[str] = ['"""']
    lines.append("TODO: краткое описание назначения функции.")

    real_params = [p for p in info["params"] if not p["name"].startswith("*")]
    if real_params:
        lines.append("")
        lines.append("Args:")
        for p in real_params:
            tp = f" ({p['type']})" if p["type"] else ""
            default = f", по умолчанию {p['default']}" if p["default"] is not None else ""
            lines.append(f"{indent}{p['name']}{tp}: TODO описание{default}.")

    if info["returns"]["returns_value"]:
        lines.append("")
        ann = info["returns"]["annotation"]
        tp = f" ({ann})" if ann else ""
        lines.append("Returns:")
        lines.append(f"{indent}{tp.strip() or 'TODO'}: что именно возвращается.")

    if info["raises"]:
        lines.append("")
        lines.append("Raises:")
        for exc in info["raises"]:
            lines.append(f"{indent}{exc}: при каком условии.")

    lines.append('"""')
    return ("\n" + indent).join(lines)


def add_docstrings(code: str) -> Tuple[str, int]:
    """
    Добавляет docstring-заготовки во все функции без них.

    Возвращает (новый_код, число_добавленных). При ошибке парсинга —
    исходный код без изменений.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return code, 0

    lines = code.split("\n")
    # собираем вставки: (строка_после_def, indent, текст)
    insertions: List[Tuple[int, str]] = []
    added = 0

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if ast.get_docstring(node) is not None:
            continue
        # отступ тела = отступ def + 4
        def_line = lines[node.lineno - 1]
        base_indent = len(def_line) - len(def_line.lstrip())
        body_indent = " " * (base_indent + 4)
        doc = generate_docstring(node, indent=body_indent)
        if doc is None:
            continue
        # строка, после которой вставляем — это строка с двоеточием def.
        # тело функции начинается на node.body[0].lineno
        first_body_line = node.body[0].lineno
        insertions.append((first_body_line, body_indent + doc))
        added += 1

    # вставляем снизу вверх, чтобы не сбить номера строк
    for line_no, text in sorted(insertions, reverse=True):
        lines.insert(line_no - 1, text)

    return "\n".join(lines), added


# ─────────────────────────────────────────────────────────────────────────────
# Вспомогательные
# ─────────────────────────────────────────────────────────────────────────────

def _annotation(node) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:  # noqa: BLE001
        return ""


def _literal(node) -> Optional[str]:
    try:
        return ast.unparse(node)
    except Exception:  # noqa: BLE001
        return None


def _call_name(func) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _exc_name(raise_node) -> str:
    exc = raise_node.exc
    if isinstance(exc, ast.Call):
        return _call_name(exc.func)
    if isinstance(exc, ast.Name):
        return exc.id
    return "Exception"
