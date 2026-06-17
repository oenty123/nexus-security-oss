#!/usr/bin/env python3
"""CLI-обёртка для продвинутого рефакторинга (вызывается VS Code расширением)."""
import sys, json, argparse
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from refactor_pro import refactor_pro

def main():
    parser = argparse.ArgumentParser(description="Nexus refactor")
    parser.add_argument("file", help="файл для рефакторинга")
    parser.add_argument("--level", type=int, default=2, choices=[1, 2, 3],
                        help="глубина: 1=безопасно, 2=стандарт, 3=агрессивно")
    parser.add_argument("--black", action="store_true", help="форматировать black")
    args = parser.parse_args()

    try:
        code = Path(args.file).read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(json.dumps({"error": f"чтение: {e}"}))
        return 1
    result = refactor_pro(code, format_with_black=args.black, level=args.level)
    print(json.dumps(result.to_dict(), ensure_ascii=False))
    return 0

if __name__ == "__main__":
    sys.exit(main())
