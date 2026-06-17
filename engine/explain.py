"""explain.py — пересказ кода: что делает файл, его структура и логика."""
from __future__ import annotations
import ast
from typing import Dict, List


def explain_code(code: str, filename: str = "file") -> dict:
    """Объясняет код: общая логика, функции, классы, зависимости."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return {"error": f"Синтаксическая ошибка: {e.msg} (строка {e.lineno})",
                "summary": "Не удалось разобрать код."}

    imports: List[str] = []
    functions: List[Dict] = []
    classes: List[Dict] = []
    has_main = False
    calls_external = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            imports += [f"{mod}.{a.name}" for a in node.names]
        elif isinstance(node, ast.FunctionDef):
            args = [a.arg for a in node.args.args]
            doc = ast.get_docstring(node)
            functions.append({
                "name": node.name, "args": args, "line": node.lineno,
                "doc": (doc or "").split("\n")[0][:100],
                "is_async": False,
                "returns": _has_return(node),
            })
        elif isinstance(node, ast.AsyncFunctionDef):
            functions.append({"name": node.name, "args": [a.arg for a in node.args.args],
                             "line": node.lineno, "doc": (ast.get_docstring(node) or "").split("\n")[0][:100],
                             "is_async": True, "returns": _has_return(node)})
        elif isinstance(node, ast.ClassDef):
            methods = [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            bases = [_name(b) for b in node.bases]
            classes.append({"name": node.name, "line": node.lineno,
                           "methods": methods, "bases": bases,
                           "doc": (ast.get_docstring(node) or "").split("\n")[0][:100]})

    # точка входа
    if 'if __name__ == "__main__"' in code or "if __name__ == '__main__'" in code:
        has_main = True

    # детект назначения по сигналам
    purpose = _guess_purpose(code, imports, functions, classes)

    # человекочитаемый пересказ
    parts = []
    loc = len([l for l in code.split("\n") if l.strip()])
    parts.append(f"Файл {filename}: ~{loc} строк кода.")
    if purpose:
        parts.append(purpose)
    if classes:
        parts.append(f"Определяет {len(classes)} класс(ов): " +
                     ", ".join(c["name"] for c in classes[:5]) + ".")
    if functions:
        top = ", ".join(f["name"] for f in functions[:6])
        parts.append(f"Содержит {len(functions)} функци(й): {top}" +
                     ("…" if len(functions) > 6 else "") + ".")
    if imports:
        ext = [i.split(".")[0] for i in imports]
        uniq = list(dict.fromkeys(ext))[:8]
        parts.append("Зависит от: " + ", ".join(uniq) + ".")
    if has_main:
        parts.append("Имеет точку входа (запускается напрямую).")

    return {
        "filename": filename,
        "summary": " ".join(parts),
        "purpose": purpose,
        "imports": list(dict.fromkeys(imports))[:20],
        "functions": functions,
        "classes": classes,
        "has_main": has_main,
        "lines": loc,
    }


def _has_return(node) -> bool:
    return any(isinstance(n, ast.Return) and n.value for n in ast.walk(node))


def _name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return "?"


def _guess_purpose(code: str, imports: List[str], funcs: List, classes: List) -> str:
    """Эвристика: к какой категории относится код."""
    low = code.lower()
    imp = " ".join(imports).lower()
    sig = []
    if any(x in imp for x in ("fastapi", "flask", "django", "aiohttp")):
        sig.append("веб-сервер/API")
    if any(x in imp for x in ("torch", "tensorflow", "sklearn", "keras", "numpy")):
        sig.append("ML/научные вычисления")
    if any(x in imp for x in ("sqlalchemy", "psycopg", "sqlite3", "pymongo")):
        sig.append("работа с БД")
    if any(x in imp for x in ("requests", "httpx", "urllib")):
        sig.append("HTTP-клиент")
    if any(x in imp for x in ("argparse", "click", "typer")):
        sig.append("CLI-утилита")
    if any(x in imp for x in ("pytest", "unittest")):
        sig.append("тесты")
    if "ast" in imports or "re" in imports:
        if any("scan" in f["name"].lower() or "analyz" in f["name"].lower() or "check" in f["name"].lower() for f in funcs):
            sig.append("анализ/обработка кода")
    if sig:
        return "Похоже на: " + ", ".join(sig) + "."
    if classes and not funcs:
        return "Определяет структуры данных / модели."
    if funcs and not classes:
        return "Набор функций (процедурный стиль)."
    return ""


if __name__ == "__main__":
    sample = '''import requests
def fetch(url):
    """Получить данные."""
    return requests.get(url).json()
class Client:
    def send(self): pass
if __name__ == "__main__":
    fetch("http://x")
'''
    import json
    print(json.dumps(explain_code(sample, "demo.py"), ensure_ascii=False, indent=2)[:500])
