#!/usr/bin/env python3
"""
Тесты движка Nexus. Запуск: python3 run_tests.py
Проверяют, что движок ловит известные уязвимости, не даёт ложных
срабатываний на чистом коде, выдерживает граничные случаи и не виснет (ReDoS).
"""
import sys
import time
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from cli import analyze_path  # noqa: E402
import rules_security  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, condition: bool) -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ok  {name}")
    else:
        FAIL += 1
        print(f" FAIL {name}")


def analyze_src(code: str, suffix: str = ".py"):
    with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8") as f:
        f.write(code)
        path = Path(f.name)
    try:
        return analyze_path(path, 2)
    finally:
        path.unlink(missing_ok=True)


def n_findings(result) -> int:
    return len(result.findings) if result and result.findings else 0


def test_detects_vulns():
    print("\n[detection] движок ловит уязвимости")
    check("eval в Python", n_findings(analyze_src("eval(user_input)\n")) > 0)
    check("hardcoded secret", n_findings(analyze_src('api_key = "sk-1234567890abcdef"\n')) > 0)
    check("eval в JS", n_findings(analyze_src("eval(x);\n", ".js")) > 0)
    check("system в Ruby", n_findings(analyze_src('system("ls #{dir}")\n', ".rb")) > 0)
    check("YAML python-tag", n_findings(analyze_src("x: !!python/object/apply:os.system\n", ".yaml")) > 0)


def test_no_false_positives():
    print("\n[precision] нет ложных срабатываний на чистом коде")
    check("чистый Python", n_findings(analyze_src("def add(a, b):\n    return a + b\n")) == 0)
    check("чистый JS", n_findings(analyze_src("function add(a, b) { return a + b; }\n", ".js")) == 0)


def test_edge_cases():
    print("\n[robustness] граничные случаи не валят движок")
    check("пустой файл", analyze_src("") is not None)
    check("только комментарий", analyze_src("# comment\n") is not None)
    check("битый синтаксис", analyze_src("def f(\n  broken !!!\n") is not None)
    check("юникод", analyze_src('x = "пароль"\n') is not None)


def test_no_redos():
    print("\n[ReDoS] ни одно правило не виснет на длинной строке")
    line = "A" * 50000
    slow = []
    for rule in rules_security.ALL_RULES:
        t0 = time.time()
        try:
            rule.pattern.search(line)
        except Exception:  # noqa: BLE001
            pass
        if time.time() - t0 > 0.3:
            slow.append(rule.id)
    check(f"нет медленных правил ({len(slow)} найдено)", not slow)


def test_long_file_fast():
    print("\n[performance] большой файл анализируется быстро")
    t0 = time.time()
    analyze_src('x = "' + "A" * 50000 + '"\n')
    dt = time.time() - t0
    check(f"50k-строка за {dt:.1f}c (<5c)", dt < 5)


def main() -> int:
    print("Nexus engine tests")
    test_detects_vulns()
    test_no_false_positives()
    test_edge_cases()
    test_no_redos()
    test_long_file_fast()
    print(f"\n{'='*40}\nИтого: {PASS} прошло, {FAIL} провалено")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
