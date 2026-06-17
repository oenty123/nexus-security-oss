#!/usr/bin/env python3
"""CLI: объяснение кода + добавление docstring-заготовок (для расширения)."""
import sys
import json
import argparse
import ast
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from readability_doc import describe_function, add_docstrings
from explain import explain_code


def main() -> int:
    parser = argparse.ArgumentParser(description="Nexus: объяснение и docstrings")
    parser.add_argument("file", help="файл для разбора")
    parser.add_argument("--docstrings", action="store_true",
                        help="вернуть код с добавленными docstring-заготовками")
    args = parser.parse_args()

    try:
        code = Path(args.file).read_text(encoding="utf-8", errors="ignore")
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": f"чтение: {e}"}, ensure_ascii=False))
        return 1

    if args.docstrings:
        new_code, added = add_docstrings(code)
        print(json.dumps({"refactored": new_code, "added": added,
                          "changed": added > 0}, ensure_ascii=False))
        return 0

    # режим объяснения
    overview = explain_code(code, args.file)
    per_function = []
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                d = describe_function(node, [])
                per_function.append({
                    "name": d["name"], "line": d["line"],
                    "behavior": d["behavior"],
                    "has_docstring": d["has_docstring"],
                })
    except SyntaxError:
        pass

    print(json.dumps({
        "summary": overview.get("summary", ""),
        "purpose": overview.get("purpose", ""),
        "functions": per_function,
        "error": overview.get("error"),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
