#!/usr/bin/env python3
"""
cli.py — командный интерфейс Nexus Security Pro.

Запускает анализ файла и выводит результат в разных форматах.
Используется VS Code, CI/CD, pre-commit хуками и LSP-сервером.

Примеры:
    python cli.py app.py                          # текстовый вывод
    python cli.py app.py --format json            # JSON для расширений
    python cli.py app.py --format vscode          # формат problemMatcher
    python cli.py app.py --format sarif -o r.sarif
    python cli.py src/ --recursive                # вся директория
    python cli.py app.py --fail-on high           # exit 1 при high+
    python cli.py app.py --compliance PCI_DSS     # отчёт соответствия

Коды возврата:
    0 — проблем не найдено (или ниже порога --fail-on)
    1 — найдены проблемы на уровне --fail-on или выше
    2 — ошибка выполнения (файл не найден, синтаксис)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

try:
    from engine import analyze, FullResult
except ImportError:
    # Позволяет запускать cli.py из любой директории
    sys.path.insert(0, str(Path(__file__).parent))
    from engine import analyze, FullResult


SUPPORTED_EXT = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".go", ".java",
    ".rs", ".cs", ".cpp", ".cc", ".c", ".rb", ".php",
    ".kt", ".swift", ".sql", ".sh", ".yaml", ".yml",
    ".html", ".htm", ".css", ".scss",
    ".gradle", ".kts", ".xml",
}

# Файлы сборки распознаются по имени (не только расширению)
BUILD_FILES = {"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ANSI-цвета (отключаются при выводе не в терминал)
class C:
    RED = "\033[91m"
    ORANGE = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls) -> None:
        for attr in ("RED", "ORANGE", "GREEN", "BLUE", "GRAY", "BOLD", "RESET"):
            setattr(cls, attr, "")
        # SEV_COLOR захватил старые значения при импорте — обновляем и его
        for k in SEV_COLOR:
            SEV_COLOR[k] = ""


SEV_COLOR = {
    "critical": C.RED,
    "high": C.ORANGE,
    "medium": C.BLUE,
    "low": C.GRAY,
    "info": C.GRAY,
}


def collect_files(target: Path, recursive: bool) -> List[Path]:
    """Собирает список файлов для анализа."""
    if target.is_file():
        return [target]
    if target.is_dir():
        skip = {"node_modules", ".venv", "venv", ".git", "__pycache__", "dist", "build"}
        files = []
        globber = target.rglob("*") if recursive else target.glob("*")
        for p in globber:
            if p.is_file() and p.suffix.lower() in SUPPORTED_EXT:
                if not any(part in skip for part in p.parts):
                    files.append(p)
        return sorted(files)
    return []


def analyze_path(path: Path, depth: int) -> Optional[FullResult]:
    """Анализирует один файл, возвращает результат или None при ошибке."""
    try:
        code = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"{C.RED}Ошибка чтения {path}: {e}{C.RESET}", file=sys.stderr)
        return None
    result = analyze(code, str(path), depth)
    if result is not None:
        _apply_inline_suppressions(result, code)
    return result


def _apply_inline_suppressions(result: "FullResult", code: str) -> None:
    """
    Убирает находки, подавленные inline-комментариями в коде:
      # nexus:ignore[RULE-ID]  — подавить конкретное правило на строке
      # nosec                  — подавить все находки на строке
    Применяется к findings, antipatterns и проблемам функций.
    """
    try:
        from suppression import get_suppressed_lines, is_suppressed
    except Exception:
        return  # подавление недоступно — не падаем, просто не фильтруем
    suppressed = get_suppressed_lines(code)
    if not suppressed:
        return

    # findings: фильтруем по rule_id
    if getattr(result, "findings", None):
        result.findings = [
            f for f in result.findings
            if not is_suppressed(getattr(f, "line", 0), getattr(f, "rule_id", ""), suppressed)
        ]
    # antipatterns: фильтруем по id
    if getattr(result, "antipatterns", None):
        result.antipatterns = [
            a for a in result.antipatterns
            if not is_suppressed(getattr(a, "line", 0), getattr(a, "id", ""), suppressed)
        ]


# ─────────────────────────────────────────────────────────────────────────────
# Форматы вывода
# ─────────────────────────────────────────────────────────────────────────────

def format_text(results: List[FullResult]) -> str:
    """Человекочитаемый вывод с цветами."""
    out: List[str] = []
    total = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for r in results:
        if not r.findings:
            out.append(f"{C.GREEN}✓{C.RESET} {r.filename} — чисто "
                       f"({C.BOLD}{r.grade}{C.RESET}, {r.score}/100)")
            continue

        out.append(f"\n{C.BOLD}{r.filename}{C.RESET} "
                   f"— {C.BOLD}{r.grade}{C.RESET} ({r.score}/100), "
                   f"{len(r.findings)} проблем:")

        for f in r.findings:
            color = SEV_COLOR.get(f.severity, "")
            total[f.severity] = total.get(f.severity, 0) + 1
            out.append(
                f"  {color}{f.severity.upper():8}{C.RESET} "
                f"{C.GRAY}{r.filename}:{f.line}{C.RESET}  "
                f"{f.title}  {C.GRAY}[{f.cwe}]{C.RESET}"
            )
            if f.fix_after:
                fix_line = f.fix_after.split(chr(10))[0]
                out.append(f"           {C.GREEN}fix:{C.RESET} {fix_line}")

        # Taint flows
        if r.taint_flows:
            out.append(f"  {C.BOLD}Taint flows:{C.RESET}")
            for t in r.taint_flows:
                out.append(f"    {C.RED}→{C.RESET} {t.get('flow_str', '')}")

    # Итог
    out.append("")
    out.append(f"{C.BOLD}Итого:{C.RESET} "
               f"{C.RED}{total['critical']} critical{C.RESET}, "
               f"{C.ORANGE}{total['high']} high{C.RESET}, "
               f"{C.BLUE}{total['medium']} medium{C.RESET}, "
               f"{C.GRAY}{total['low']} low{C.RESET}")
    return "\n".join(out)


def format_vscode(results: List[FullResult]) -> str:
    """
    Формат для VS Code problemMatcher.
    Каждая строка: file:line:col: severity: message [rule]
    """
    lines: List[str] = []
    sev_map = {"critical": "error", "high": "error",
               "medium": "warning", "low": "info", "info": "info"}
    for r in results:
        for f in r.findings:
            vs_sev = sev_map.get(f.severity, "warning")
            col = max(1, f.col)
            lines.append(
                f"{r.filename}:{f.line}:{col}: {vs_sev}: "
                f"{f.title} [{f.cwe}] ({f.severity})"
            )
    return "\n".join(lines)


def format_html(results: List[FullResult]) -> str:
    """Самодостаточный HTML-отчёт по проекту (открывается в браузере, можно отправить команде)."""
    import html as _html

    data = [r.to_dict() for r in results]
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    rows = []
    for r in data:
        for f in r.get("findings", []):
            sev = f.get("severity", "low")
            totals[sev] = totals.get(sev, 0) + 1
            rows.append((sev, r.get("filename", ""), f.get("line", 0),
                         f.get("title", ""), f.get("cwe", ""), f.get("rule_id", "")))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows.sort(key=lambda x: (order.get(x[0], 9), x[1], x[2]))

    total = sum(totals.values())
    color = {"critical": "#d1242f", "high": "#bc4c00", "medium": "#9a6700", "low": "#0969da"}

    cards = "".join(
        f'<div class="card {s}"><div class="n">{totals[s]}</div><div class="l">{s}</div></div>'
        for s in ("critical", "high", "medium", "low")
    )
    body_rows = "".join(
        f'<tr><td><span class="badge" style="background:{color[s]}">{s}</span></td>'
        f'<td class="file">{_html.escape(str(fn))}:{ln}</td>'
        f'<td>{_html.escape(str(title))}</td>'
        f'<td class="mono">{_html.escape(str(cwe))}</td>'
        f'<td class="mono">{_html.escape(str(rid))}</td></tr>'
        for s, fn, ln, title, cwe, rid in rows
    ) or '<tr><td colspan="5" class="clean">✓ Уязвимостей не найдено</td></tr>'

    import datetime
    when = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    return f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><title>Nexus Security — отчёт</title>
<style>
  body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:1000px;margin:0 auto;padding:24px;color:#1f2328;background:#fff}}
  h1{{font-size:1.5em;display:flex;align-items:center;gap:8px}}
  .meta{{color:#656d76;font-size:.9em;margin-bottom:20px}}
  .cards{{display:flex;gap:12px;margin-bottom:24px}}
  .card{{flex:1;padding:16px;border-radius:8px;text-align:center;border:1px solid #d0d7de}}
  .card .n{{font-size:2em;font-weight:700}} .card .l{{font-size:.85em;text-transform:uppercase;color:#656d76}}
  .card.critical .n{{color:#d1242f}} .card.high .n{{color:#bc4c00}} .card.medium .n{{color:#9a6700}} .card.low .n{{color:#0969da}}
  table{{border-collapse:collapse;width:100%;font-size:.9em}}
  th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #d0d7de}}
  th{{font-size:.8em;text-transform:uppercase;color:#656d76}}
  .badge{{color:#fff;padding:2px 8px;border-radius:10px;font-size:.8em;text-transform:uppercase}}
  .file{{font-family:ui-monospace,monospace;white-space:nowrap}} .mono{{font-family:ui-monospace,monospace;color:#656d76}}
  .clean{{text-align:center;color:#1a7f37;padding:24px}}
</style></head><body>
  <h1>🛡️ Nexus Security</h1>
  <div class="meta">Проверено файлов: {len(data)} · Найдено: {total} · {when}</div>
  <div class="cards">{cards}</div>
  <table><thead><tr><th>Уровень</th><th>Файл</th><th>Проблема</th><th>CWE</th><th>Правило</th></tr></thead>
  <tbody>{body_rows}</tbody></table>
  <p class="meta" style="margin-top:24px">Сгенерировано локально. Код не покидал машину.</p>
</body></html>"""


def format_json(results: List[FullResult]) -> str:
    """JSON для расширений и интеграций."""
    return json.dumps(
        [r.to_dict() for r in results],
        ensure_ascii=False,
        indent=2,
    )


def format_sarif(results: List[FullResult]) -> str:
    """SARIF 2.1.0 для GitHub/GitLab."""
    from engine_ast import Finding
    from sarif_exporter import findings_to_sarif
    all_findings: List[Finding] = []
    for r in results:
        all_findings.extend(r.findings)
    return json.dumps(
        findings_to_sarif(all_findings, tool_version="2.0.0"),
        ensure_ascii=False,
        indent=2,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def _apply_project_config(args) -> None:
    """
    Ищет .nexusrc (JSON) в текущей папке и вверх до корня. Применяет значения
    как дефолты — но только те, что пользователь не задал явным флагом.

    Поддерживаемые ключи: depth, all, ignore_rule (список), fail_on.
    Пример .nexusrc:
        {"depth": 3, "all": false, "ignore_rule": ["AP-MAGIC-NUMBER"], "fail_on": "high"}
    """
    import json
    start = Path(getattr(args, "target", ".") or ".").resolve()
    if start.is_file():
        start = start.parent
    for folder in [start, *start.parents]:
        rc = folder / ".nexusrc"
        if rc.is_file():
            try:
                cfg = json.loads(rc.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                return  # битый конфиг — игнорируем молча
            if "depth" in cfg and args.depth == 2:
                args.depth = int(cfg["depth"])
            if cfg.get("all") and not args.all:
                args.all = True
            if cfg.get("ignore_rule"):
                args.ignore_rule = list(args.ignore_rule) + list(cfg["ignore_rule"])
            if cfg.get("fail_on") and args.fail_on == "none":
                args.fail_on = cfg["fail_on"]
            return  # первый найденный конфиг побеждает
        if (folder / ".git").exists():
            break  # дошли до корня репозитория


def _cmd_fix(fix_args: "List[str]") -> int:
    """nexus fix <file> — применяет безопасные рефакторинги (level 1) к Python-файлу."""
    if not fix_args:
        print("Использование: nexus fix <файл.py> [--level 1|2|3]")
        return 2
    path = Path(fix_args[0])
    if not path.is_file():
        print(f"{C.RED}Файл не найден: {path}{C.RESET}")
        return 2
    if path.suffix != ".py":
        print(f"{C.ORANGE}fix работает только с Python-файлами.{C.RESET}")
        return 2
    level = 1
    if "--level" in fix_args:
        try:
            level = int(fix_args[fix_args.index("--level") + 1])
        except (ValueError, IndexError):
            pass
    try:
        from refactor_pro import refactor_pro
    except Exception as e:  # noqa: BLE001
        print(f"{C.RED}Движок рефакторинга недоступен: {e}{C.RESET}")
        return 1

    code = path.read_text(encoding="utf-8", errors="ignore")
    result = refactor_pro(code, format_with_black=False, level=level)
    if result.error:
        print(f"{C.ORANGE}Не удалось: {result.error}{C.RESET}")
        return 1
    if not result.changes:
        print(f"{C.GREEN}✓ Нечего улучшать — код уже чистый.{C.RESET}")
        return 0

    # бэкап и запись
    backup = path.with_suffix(path.suffix + ".bak")
    backup.write_text(code, encoding="utf-8")
    path.write_text(result.refactored, encoding="utf-8")
    print(f"{C.GREEN}✓{C.RESET} Применено {len(result.changes)} улучшений (level {level}).")
    print(f"  Резервная копия: {backup.name}")
    for c in result.changes[:10]:
        print(f"  • {c.before} → {c.after}")
    return 0


def _cmd_init() -> int:
    """Создаёт .nexusrc с разумными дефолтами."""
    import json as _json
    rc = Path(".nexusrc")
    if rc.exists():
        print(f"{C.ORANGE}.nexusrc уже существует — не перезаписываю.{C.RESET}")
        return 0
    config = {
        "depth": 2,
        "all": False,
        "ignore_rule": [],
        "fail_on": "none",
    }
    rc.write_text(_json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{C.GREEN}✓{C.RESET} Создан .nexusrc с настройками по умолчанию.")
    print("  Отредактируйте его: depth (1-3), all (показывать качество),")
    print("  ignore_rule (правила скрыть), fail_on (порог для CI).")
    return 0


def _friendly_summary(results: "List[FullResult]") -> None:
    """Печатает дружелюбный итог: чисто или сколько и каких проблем."""
    t = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in results:
        for f in r.findings:
            t[getattr(f, "severity", "low")] = t.get(getattr(f, "severity", "low"), 0) + 1
    total = sum(t.values())
    if total == 0:
        print(f"\n{C.GREEN}✓ Чисто — уязвимостей не найдено.{C.RESET}")
        return
    parts = []
    if t["critical"]: parts.append(f"{C.RED}{t['critical']} critical{C.RESET}")
    if t["high"]: parts.append(f"{t['high']} high")
    if t["medium"]: parts.append(f"{t['medium']} medium")
    if t["low"]: parts.append(f"{t['low']} low")
    print(f"\n{C.BOLD}Итого: {total} проблем ({', '.join(parts)}){C.RESET}")


def _watch_loop(target: "Path", args) -> int:
    """Следит за изменениями файлов и пересканирует. Ctrl+C для выхода."""
    import time
    print(f"{C.BOLD}Nexus watch{C.RESET} — слежу за {target}. Ctrl+C для выхода.\n")
    mtimes: dict = {}

    def snapshot():
        files = collect_files(target, recursive=True)
        return {str(f): f.stat().st_mtime for f in files if f.exists()}

    try:
        mtimes = snapshot()
        # первый прогон
        _run_once(target, args)
        while True:
            time.sleep(1)
            current = snapshot()
            changed = [f for f, m in current.items() if mtimes.get(f) != m]
            if changed:
                print(f"\n{C.BLUE}↻ Изменён: {', '.join(Path(c).name for c in changed[:3])}{C.RESET}")
                _run_once(target, args)
                mtimes = current
    except KeyboardInterrupt:
        print("\nNexus watch остановлен.")
        return 0


def _run_once(target: "Path", args) -> None:
    """Один прогон анализа для watch-режима (text-вывод)."""
    files = collect_files(target, recursive=True)
    results = [r for f in files if (r := analyze_path(f, args.depth))]
    if not results:
        return
    if not (args.all and not args.security_only):
        for r in results:
            if hasattr(r, "antipatterns"):
                r.antipatterns = []
    print(format_text(results))
    _friendly_summary(results)


def main(argv: Optional[List[str]] = None) -> int:
    raw = argv if argv is not None else sys.argv[1:]
    # Спецкоманда: nexus init — создаёт .nexusrc интерактивно
    if raw and raw[0] == "init":
        return _cmd_init()
    if raw and raw[0] == "fix":
        return _cmd_fix(raw[1:])
    # Запуск без аргументов — дружелюбная справка вместо argparse-ошибки
    if not raw:
        print(f"""{C.BOLD}🛡️  Nexus Security{C.RESET} — локальный анализатор безопасности кода

{C.BOLD}Использование:{C.RESET}
  nexus .                      проверить текущий проект
  nexus file.py                проверить один файл
  nexus . --all                + проблемы качества кода
  nexus . -f html -o report.html   отчёт для команды
  nexus --watch .              следить и пересканировать
  nexus init                   создать конфиг .nexusrc
  nexus fix file.py            применить безопасные исправления

{C.GRAY}Полная справка: nexus --help{C.RESET}""")
        return 0

    parser = argparse.ArgumentParser(
        prog="nexus",
        description="Nexus Security Pro — SAST анализатор кода",
    )
    parser.add_argument("target", help="файл или директория для анализа")
    parser.add_argument("-f", "--format", default="text",
                        choices=["text", "json", "vscode", "sarif", "html"],
                        help="формат вывода (default: text)")
    parser.add_argument("-o", "--output", help="записать результат в файл")
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="рекурсивный обход директории")
    parser.add_argument("-d", "--depth", type=int, default=2, choices=[1, 2, 3],
                        help="глубина: 1=быстро, 2=стандарт, 3=параноик")
    parser.add_argument("--fail-on", default="none",
                        choices=["none", "critical", "high", "medium", "low"],
                        help="exit 1 если найдены проблемы этого уровня или выше")
    parser.add_argument("--compliance", default=None,
                        choices=["PCI_DSS", "HIPAA", "SOC2", "GDPR", "OWASP"],
                        help="добавить отчёт о соответствии стандарту")
    parser.add_argument("--no-color", action="store_true", help="отключить цвета")
    parser.add_argument("--quiet", action="store_true",
                        help="только проблемы, без сводки")
    parser.add_argument("--all", action="store_true",
                        help="показывать и проблемы качества кода (сложность, магические числа)")
    parser.add_argument("--security-only", action="store_true",
                        help="только уязвимости безопасности (по умолчанию)")
    parser.add_argument("--ignore-rule", action="append", default=[], metavar="RULE_ID",
                        help="скрыть все находки правила (можно несколько раз)")
    parser.add_argument("--version", action="version", version="Nexus Security 1.0.0")
    parser.add_argument("--watch", action="store_true",
                        help="следить за файлами и пересканировать при изменении")
    args = parser.parse_args(argv)

    # Конфиг проекта .nexusrc (JSON) в корне или рядом с целью — задаёт дефолты.
    # Флаги командной строки имеют приоритет над конфигом.
    _apply_project_config(args)

    # Цвета отключаются для не-терминала или по флагу
    if args.no_color or not sys.stdout.isatty() or args.format != "text":
        C.disable()

    target = Path(args.target)
    if not target.exists():
        print(f"Ошибка: {target} не существует", file=sys.stderr)
        return 2

    # Watch-режим: следим и пересканируем
    if args.watch:
        return _watch_loop(target, args)

    # Директория сканируется рекурсивно по умолчанию (удобство)
    recursive = args.recursive or target.is_dir()
    files = collect_files(target, recursive)
    if not files:
        print(f"Не найдено поддерживаемых файлов в {target}", file=sys.stderr)
        return 2

    results: List[FullResult] = []
    for f in files:
        r = analyze_path(f, args.depth)
        if r:
            results.append(r)

    if not results:
        return 2

    # По умолчанию показываем только безопасность. --all включает качество кода.
    show_quality = args.all and not args.security_only
    ignored = set(args.ignore_rule)
    for r in results:
        if ignored and getattr(r, "findings", None):
            r.findings = [f for f in r.findings
                          if getattr(f, "rule_id", "") not in ignored]
        if not show_quality:
            if hasattr(r, "antipatterns"):
                r.antipatterns = []
            if hasattr(r, "functions"):
                for fn in r.functions:
                    if hasattr(fn, "issues"):
                        fn.issues = []
        elif ignored:
            if getattr(r, "antipatterns", None):
                r.antipatterns = [
                    a for a in r.antipatterns
                    if (a.get("id") if isinstance(a, dict) else getattr(a, "id", "")) not in ignored
                ]

    # Форматирование
    formatters = {
        "text": format_text,
        "json": format_json,
        "vscode": format_vscode,
        "sarif": format_sarif,
        "html": format_html,
    }
    output = formatters[args.format](results)

    # Compliance (только text/json)
    if args.compliance and args.format in ("text", "json"):
        from compliance import compliance_summary
        all_findings = [f.to_dict() for r in results for f in r.findings]
        summary = compliance_summary(all_findings, args.compliance)
        if args.format == "text":
            status = "СООТВЕТСТВУЕТ" if summary["compliant"] else "НЕ СООТВЕТСТВУЕТ"
            output += (f"\n\n{C.BOLD}Compliance {args.compliance}:{C.RESET} "
                       f"{summary['compliance_percentage']}% — {status} "
                       f"({summary['passed']}/{summary['total_controls']} контролей)")

    # Вывод
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        if not args.quiet:
            print(f"Результат записан в {args.output}", file=sys.stderr)
    else:
        print(output)
        # дружелюбный итог для интерактивного text-режима
        if args.format == "text" and not args.quiet:
            _friendly_summary(results)

    # Код возврата по --fail-on
    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        for r in results:
            for f in r.findings:
                if SEVERITY_ORDER.get(f.severity, 9) <= threshold:
                    return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
