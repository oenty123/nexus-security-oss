"""
suppression.py — подавление false positives.

Три механизма (как в bandit/semgrep):
  1. Inline-комментарии: # nosec, # noqa: nexus, # nexus:ignore[RULE-ID]
  2. Baseline-файл: игнорировать уже известные находки (для легаси)
  3. Конфиг .nexusignore: исключить файлы/правила глобально

Без этого команда тонет в шуме на первом скане легаси-кода.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set


# Паттерны inline-подавления
_SUPPRESS_ALL = re.compile(r"#\s*(nosec|noqa:\s*nexus|nexus:\s*ignore)\b", re.I)
_SUPPRESS_RULE = re.compile(r"#\s*nexus:\s*ignore\[([A-Z0-9_,-]+)\]", re.I)


def get_suppressed_lines(code: str) -> Dict[int, Optional[Set[str]]]:
    """
    Возвращает {line_number: rule_ids | None}.
    None означает «подавить все правила на этой строке».
    set означает «подавить только указанные правила».
    """
    suppressed: Dict[int, Optional[Set[str]]] = {}
    for i, line in enumerate(code.splitlines(), 1):
        rule_match = _SUPPRESS_RULE.search(line)
        if rule_match:
            rules = {r.strip() for r in rule_match.group(1).split(",")}
            suppressed[i] = rules
        elif _SUPPRESS_ALL.search(line):
            suppressed[i] = None  # все правила
    return suppressed


def is_suppressed(line: int, rule_id: str,
                  suppressed: Dict[int, Optional[Set[str]]]) -> bool:
    """Проверяет, подавлена ли находка на данной строке."""
    if line not in suppressed:
        return False
    rules = suppressed[line]
    if rules is None:
        return True  # подавлены все
    return rule_id in rules


# ─────────────────────────────────────────────────────────────────────────────
# Baseline — игнорировать известные находки
# ─────────────────────────────────────────────────────────────────────────────

def finding_fingerprint(finding: dict) -> str:
    """
    Стабильный отпечаток находки для baseline.
    Не зависит от номера строки (код сдвигается), зависит от
    правила + файла + содержимого строки.
    """
    key = f"{finding.get('rule_id')}:{finding.get('file')}:{finding.get('snippet', '').strip()}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def create_baseline(findings: List[dict], path: str = ".nexus-baseline.json") -> int:
    """Сохраняет текущие находки как baseline. Возвращает число записей."""
    fingerprints = sorted({finding_fingerprint(f) for f in findings})
    data = {
        "version": "1.0",
        "fingerprints": fingerprints,
        "count": len(fingerprints),
    }
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return len(fingerprints)


def load_baseline(path: str = ".nexus-baseline.json") -> Set[str]:
    """Загружает baseline-отпечатки. Пустой set если файла нет."""
    p = Path(path)
    if not p.exists():
        return set()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return set(data.get("fingerprints", []))
    except (json.JSONDecodeError, KeyError):
        return set()


def filter_baseline(findings: List[dict], baseline: Set[str]) -> List[dict]:
    """Убирает находки, присутствующие в baseline (показывает только новые)."""
    return [f for f in findings if finding_fingerprint(f) not in baseline]


# ─────────────────────────────────────────────────────────────────────────────
# .nexusignore — глобальные исключения
# ─────────────────────────────────────────────────────────────────────────────

class IgnoreConfig:
    """Парсит .nexusignore: файлы и правила для глобального исключения."""

    def __init__(self) -> None:
        self.ignored_paths: List[str] = []
        self.ignored_rules: Set[str] = set()

    @classmethod
    def load(cls, path: str = ".nexusignore") -> "IgnoreConfig":
        cfg = cls()
        p = Path(path)
        if not p.exists():
            return cfg
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("rule:"):
                cfg.ignored_rules.add(line[5:].strip())
            else:
                cfg.ignored_paths.append(line)
        return cfg

    def is_path_ignored(self, filepath: str) -> bool:
        import fnmatch
        return any(fnmatch.fnmatch(filepath, pat) for pat in self.ignored_paths)

    def is_rule_ignored(self, rule_id: str) -> bool:
        return rule_id in self.ignored_rules


# ─────────────────────────────────────────────────────────────────────────────
# Главная функция фильтрации
# ─────────────────────────────────────────────────────────────────────────────

def apply_suppressions(
    findings: List[dict],
    code: str,
    baseline_path: Optional[str] = None,
    ignore_config: Optional[IgnoreConfig] = None,
) -> tuple[List[dict], int]:
    """
    Применяет все механизмы подавления.
    Возвращает (отфильтрованные_находки, число_подавленных).
    """
    suppressed_lines = get_suppressed_lines(code)
    baseline = load_baseline(baseline_path) if baseline_path else set()
    cfg = ignore_config or IgnoreConfig()

    result: List[dict] = []
    suppressed_count = 0

    for f in findings:
        rule_id = f.get("rule_id", "")
        line = f.get("line", 0)

        # 1. Inline
        if is_suppressed(line, rule_id, suppressed_lines):
            suppressed_count += 1
            continue
        # 2. Глобальное правило
        if cfg.is_rule_ignored(rule_id):
            suppressed_count += 1
            continue
        # 3. Baseline
        if baseline and finding_fingerprint(f) in baseline:
            suppressed_count += 1
            continue

        result.append(f)

    return result, suppressed_count


if __name__ == "__main__":
    code = '''
password = "hardcoded123"  # nexus:ignore[AUTH-SECRET-001]
api_key = "secret456"  # nosec
normal_secret = "exposed789"
'''
    findings = [
        {"rule_id": "AUTH-SECRET-001", "file": "t.py", "line": 2, "snippet": "password"},
        {"rule_id": "AUTH-SECRET-001", "file": "t.py", "line": 3, "snippet": "api_key"},
        {"rule_id": "AUTH-SECRET-001", "file": "t.py", "line": 4, "snippet": "normal_secret"},
    ]
    filtered, count = apply_suppressions(findings, code)
    print(f"Исходно: {len(findings)}, подавлено: {count}, осталось: {len(filtered)}")
    for f in filtered:
        print(f"  Строка {f['line']}: {f['rule_id']}")
    assert len(filtered) == 1, "Должна остаться 1 находка (normal_secret)"
    assert filtered[0]["line"] == 4
    print("✓ Подавление работает")
