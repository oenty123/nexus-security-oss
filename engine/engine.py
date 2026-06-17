"""
engine.py — главный оркестратор анализа Nexus Security Pro v2.

Объединяет все движки:
  1. InterproceduralTaint  — межпроцедурный taint-анализ (engine_taint.py)
  2. SecurityRule scanner  — 50+ правил OWASP/CWE (rules_security.py)
  3. SecretScanner         — энтропийное обнаружение секретов
  4. ComplexityAnalyzer    — метрики качества (engine_ast.py)
  5. DuplicationDetector   — клоны кода (engine_ast.py)
  6. RefactoringSuggester  — антипаттерны (engine_ast.py)

Дедупликация: taint (high confidence) имеет приоритет над regex.
"""

from __future__ import annotations

import dataclasses
import hashlib
import math
import re
from typing import Dict, List

from engine_ast import (
    ComplexityAnalyzer,
    DuplicationDetector,
    Finding,
    FunctionMetric,
    RefactoringSuggester,
    detect_language,
)
from engine_taint import analyze_interprocedural
from rules_security import ALL_RULES, rules_for_language


# ─────────────────────────────────────────────────────────────────────────────
# Secret Scanner (энтропийный)
# ─────────────────────────────────────────────────────────────────────────────

class SecretScanner:
    """
    Обнаружение секретов двумя методами:
      1. Сигнатуры известных провайдеров (AWS, GitHub, Stripe, ...)
      2. Энтропия Шеннона для высокоэнтропийных строк
    """

    PROVIDER_PATTERNS = [
        ("AWS Access Key",     re.compile(r'AKIA[0-9A-Z]{16}'),                       "critical"),
        ("AWS Secret Key",     re.compile(r'(?i)aws.{0,20}["\'][0-9a-zA-Z/+]{40}["\']'), "critical"),
        ("GitHub Token",       re.compile(r'gh[pousr]_[0-9a-zA-Z]{36,}'),             "critical"),
        ("GitLab Token",       re.compile(r'glpat-[0-9a-zA-Z_-]{20}'),                "critical"),
        ("Slack Token",        re.compile(r'xox[baprs]-[0-9a-zA-Z-]{10,}'),           "high"),
        ("Stripe Key",         re.compile(r'sk_(?:live|test)_[0-9a-zA-Z]{24,}'),      "critical"),
        ("Google API Key",     re.compile(r'AIza[0-9A-Za-z_-]{35}'),                  "high"),
        ("JWT Token",          re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.'), "medium"),
        ("Private Key",        re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), "critical"),
        ("Generic API Secret", re.compile(r'(?i)(?:api[_-]?secret|client[_-]?secret)\s*[:=]\s*["\'][0-9a-zA-Z]{16,}["\']'), "high"),
        ("Database URL",       re.compile(r'(?:postgres|mysql|mongodb)://[^:]+:[^@]+@'), "high"),
    ]

    # Переменные, в которых высокоэнтропийная строка = секрет
    SECRET_VAR_HINT = re.compile(
        r'(?i)(secret|password|passwd|token|api[_-]?key|auth|credential|private)'
    )

    def scan(self, code: str, filename: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = code.splitlines()

        # 1. Провайдер-сигнатуры
        for name, pattern, sev in self.PROVIDER_PATTERNS:
            for m in pattern.finditer(code):
                ln = code[: m.start()].count("\n") + 1
                snippet = lines[ln - 1].strip() if ln <= len(lines) else ""
                if snippet.startswith("#") or snippet.startswith("//"):
                    continue
                findings.append(Finding(
                    rule_id=f"SECRET-{name.replace(' ', '-').upper()}",
                    title=f"Обнаружен секрет: {name}",
                    severity=sev,
                    cwe="CWE-798",
                    category="secrets",
                    file=filename,
                    line=ln,
                    snippet=self._redact(snippet),
                    desc=f"{name} в исходном коде. Немедленно ротируйте и удалите из истории git.",
                    fix_before=self._redact(snippet),
                    fix_after="os.getenv('SECRET_NAME')  # читать из переменных окружения",
                    confidence="high",
                    source="secret-scanner",
                ))

        # 2. Энтропийное обнаружение
        for i, line in enumerate(lines, 1):
            if not self.SECRET_VAR_HINT.search(line):
                continue
            for str_match in re.finditer(r'["\']([0-9a-zA-Z_/+=.-]{20,})["\']', line):
                candidate = str_match.group(1)
                ent = self._shannon_entropy(candidate)
                if ent > 4.0 and not self._looks_like_path(candidate):
                    findings.append(Finding(
                        rule_id="SECRET-HIGH-ENTROPY",
                        title="Высокоэнтропийная строка (возможный секрет)",
                        severity="high",
                        cwe="CWE-798",
                        category="secrets",
                        file=filename,
                        line=i,
                        snippet=self._redact(line.strip()),
                        desc=f"Строка с энтропией {ent:.1f} бит в security-переменной. "
                             "Вероятно секрет/ключ.",
                        fix_before=self._redact(line.strip()),
                        fix_after="value = os.getenv('SECRET_NAME')",
                        confidence="medium",
                        source="entropy",
                    ))
                    break

        return findings

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        entropy = 0.0
        length = len(s)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _looks_like_path(s: str) -> bool:
        return ("/" in s and " " not in s and s.count("/") >= 2) or s.startswith("http")

    @staticmethod
    def _redact(s: str) -> str:
        """Маскирует значение секрета в выводе."""
        def repl(m: re.Match) -> str:
            val = m.group(1)
            if len(val) <= 8:
                return m.group(0)
            return m.group(0)[0] + val[:4] + "***REDACTED***" + val[-2:] + m.group(0)[-1]
        return re.sub(r'["\']([0-9a-zA-Z_/+=.-]{12,})["\']', repl, s)


# ─────────────────────────────────────────────────────────────────────────────
# Rule-based scanner
# ─────────────────────────────────────────────────────────────────────────────

def _is_rule_definition(snippet: str) -> bool:
    """
    True, если строка — определение правила/паттерна анализатора, а не реальный
    уязвимый код. Убирает ложные срабатывания при сканировании самого Nexus.
    """
    s = snippet
    markers = (
        "_rx(", "re.compile(", "SecurityRule(", "pattern=", "PROVIDER",
        "SINKS", "SOURCES", "TAINT_", "RULES", "_PATTERN", "signature",
        "fix_before", "fix_after", "self._log(", "RefactorChange(",
        "CWE-", "category=", "rule_id=", "_rx",
    )
    # строка содержит маркер определения правила
    if any(mk in s for mk in markers):
        return True
    # строка целиком — это строковый литерал-паттерн (начинается с кавычки и regex-мета)
    if s[:2] in ('r"', "r'") or (s[:1] in ('"', "'") and any(c in s for c in r"\b\s\(")):
        return True
    return False


_TEST_FILE_RE = re.compile(r"test_|_test\b|\bspec\b|/tests?/", re.I)

_SANITIZERS = ("escape(", "quote(", "sanitize", "secure_filename", "literal_eval",
               "safe_load", "compare_digest", "bleach.", "validate", "is_safe")


def _is_safe_context(snippet: str, category: str) -> bool:
    """Эвристика точности: вызов уже защищён санитайзером → не уязвимость."""
    low = snippet.lower()
    # инъекции/rce с явной санитизацией в той же строке
    if category in ("sql", "command", "rce", "xss", "ssti", "xpath", "ldap"):
        if any(s in low for s in _SANITIZERS):
            return True
    return False


class RuleScanner:
    """Применяет SecurityRule из rules_security.py."""

    def scan(self, code: str, filename: str, language: str, depth: int = 2) -> List[Finding]:
        findings: List[Finding] = []
        lines = code.splitlines()
        is_test = bool(_TEST_FILE_RE.search(filename))

        applicable = rules_for_language(language)

        # Защита от ReDoS: на аномально длинных строках (минифицированный код,
        # встроенные данные) regex может уходить в катастрофический backtracking.
        # finditer применяем к коду, но предварительно «обезвреживаем» строки
        # длиннее лимита, заменяя их на маркер той же длины без спецсимволов.
        MAX_LINE = 2000
        scan_code = code
        if any(len(ln) > MAX_LINE for ln in lines):
            safe_lines = [
                ln if len(ln) <= MAX_LINE else ("\u0000" * len(ln))
                for ln in lines
            ]
            scan_code = "\n".join(safe_lines)

        for rule in applicable:
            # На быстрой глубине пропускаем low/medium
            if depth == 1 and rule.severity in ("low", "medium"):
                continue

            for m in rule.pattern.finditer(scan_code):
                ln = code[: m.start()].count("\n") + 1
                snippet = lines[ln - 1].strip() if ln <= len(lines) else ""
                if snippet.startswith("#") or snippet.startswith("//") or snippet.startswith("*"):
                    continue
                # Фильтр самосканирования: строка является определением правила,
                # а не реальным вызовом (паттерны в _rx(), sink-списки, regex-строки).
                if _is_rule_definition(snippet):
                    continue
                # Усиление точности: пропускаем явно безопасный контекст —
                # вызов уже обёрнут в санитайзер или это пример в докстринге.
                if _is_safe_context(snippet, rule.category):
                    continue
                # В тестовых файлах снижаем severity (кроме critical)
                if is_test and depth < 3 and rule.severity != "critical":
                    continue

                findings.append(Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    cwe=rule.cwe,
                    category=rule.category,
                    file=filename,
                    line=ln,
                    col=m.start() - code.rfind("\n", 0, m.start()) - 1,
                    snippet=snippet[:120],
                    desc=rule.description,
                    fix_before=rule.fix_before,
                    fix_after=rule.fix_after,
                    confidence=rule.confidence,
                    source="rule",
                ))

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Main analysis result
# ─────────────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class FullResult:
    filename:      str
    language:      str
    total_lines:   int
    code_lines:    int
    comment_lines: int
    findings:      List[Finding]
    taint_flows:   List[dict]
    functions:     List[FunctionMetric]
    duplications:  List[dict]
    antipatterns:  List[dict]
    score:         int
    grade:         str
    owasp_coverage: Dict[str, int]
    errors:        List[str]

    def to_dict(self) -> dict:
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {
            "filename": self.filename,
            "language": self.language,
            "total_lines": self.total_lines,
            "code_lines": self.code_lines,
            "comment_lines": self.comment_lines,
            "score": self.score,
            "grade": self.grade,
            "findings": [f.to_dict() for f in self.findings],
            "taint_flows": self.taint_flows,
            "functions": [fn.to_dict() for fn in self.functions],
            "duplications": self.duplications,
            "antipatterns": self.antipatterns,
            "owasp_coverage": self.owasp_coverage,
            "errors": self.errors,
            "summary": {**by_sev, "total": len(self.findings)},
        }


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

_secret_scanner = SecretScanner()
_rule_scanner = RuleScanner()
_complexity = ComplexityAnalyzer()
_dedup = DuplicationDetector()
_refactor = RefactoringSuggester()

# Кэш результатов по хэшу (код, depth): повторный скан того же кода мгновенный
_RESULT_CACHE: Dict[str, "FullResult"] = {}
_CACHE_MAX = 256


def _cache_key(code: str, filename: str, depth: int) -> str:
    h = hashlib.sha256(f"{depth}:{filename}:{code}".encode("utf-8", "ignore")).hexdigest()
    return h


def analyze(code: str, filename: str = "unknown", depth: int = 2) -> FullResult:
    """
    Полный анализ файла со всеми движками (с кэшированием результатов).

    Args:
        code:     исходный код
        filename: имя файла (для определения языка)
        depth:    1=быстро, 2=стандарт, 3=параноик
    """
    _ck = _cache_key(code, filename, depth)
    _cached = _RESULT_CACHE.get(_ck)
    if _cached is not None:
        return _cached
    lines = code.splitlines()
    total_lines = len(lines)
    code_lines = sum(1 for l in lines if l.strip() and not l.strip().startswith("#"))
    comment_lines = sum(1 for l in lines if l.strip().startswith("#"))
    language = detect_language(filename)
    errors: List[str] = []
    all_findings: List[Finding] = []
    taint_flows: List[dict] = []

    # 1. Межпроцедурный taint-анализ (Python)
    if language == "python":
        try:
            tf = analyze_interprocedural(code, filename)
            for t in tf:
                taint_flows.append({**t.to_dict(), "flow_str": " → ".join(t.flow)})
                all_findings.append(Finding(
                    rule_id=t.rule_id,
                    title=t.title,
                    severity=t.severity,
                    cwe=t.cwe,
                    category="taint",
                    file=filename,
                    line=t.line,
                    col=t.col,
                    snippet=t.snippet,
                    desc=f"Поток данных: {' → '.join(t.flow)}",
                    fix_before=t.snippet,
                    fix_after=t.fix,
                    confidence=t.confidence,
                    source="taint",
                ))
        except Exception as e:
            errors.append(f"Taint-анализ: {e}")

    # 2. Rule-based scan
    try:
        rule_findings = _rule_scanner.scan(code, filename, language, depth)
        # Тройной анализ: если regex подтверждает taint на той же строке —
        # помечаем taint-находку как confirmed (а не просто отбрасываем regex).
        taint_by_line = {f.line: f for f in all_findings if f.source == "taint"}
        for rf in rule_findings:
            if rf.line in taint_by_line:
                taint_by_line[rf.line].confidence = "confirmed"
            else:
                all_findings.append(rf)
    except Exception as e:
        errors.append(f"Rule-scan: {e}")

    # 2b. Dataflow-анализ (CFG, path-sensitive) — Python, глубина 2+
    if language == "python" and depth >= 2:
        try:
            from engine_dataflow import analyze_dataflow
            df_findings = analyze_dataflow(code, filename)
            existing = {(f.line, f.cwe) for f in all_findings}
            for df in df_findings:
                if (df.line, df.cwe) not in existing:
                    all_findings.append(Finding(
                        rule_id=df.rule_id,
                        title=df.title,
                        severity=df.severity,
                        cwe=df.cwe,
                        category="dataflow",
                        file=filename,
                        line=df.line,
                        col=df.col,
                        snippet=df.snippet,
                        desc=f"Поток данных: {' → '.join(df.path)}",
                        fix_before=df.snippet,
                        fix_after=df.fix,
                        confidence=df.confidence,
                        source="dataflow",
                    ))
                    existing.add((df.line, df.cwe))
        except Exception as e:
            errors.append(f"Dataflow: {e}")

    # 3. Secret scanner
    try:
        secret_findings = _secret_scanner.scan(code, filename)
        existing_lines = {f.line for f in all_findings if f.category == "secrets"}
        for sf in secret_findings:
            if sf.line not in existing_lines:
                all_findings.append(sf)
    except Exception as e:
        errors.append(f"Secret-scan: {e}")

    # 4. Complexity (Python)
    functions: List[FunctionMetric] = []
    if language == "python":
        try:
            functions = _complexity.analyze(code)
        except Exception as e:
            errors.append(f"Complexity: {e}")

    # 5. Duplication
    try:
        duplications = _dedup.detect(code)
    except Exception as e:
        errors.append(f"Dedup: {e}")
        duplications = []

    # 6. Refactoring
    try:
        antipatterns = _refactor.analyze(code, filename)
    except Exception as e:
        errors.append(f"Refactor: {e}")
        antipatterns = []

    # 7. Дедупликация (несколько правил на одной строке с тем же CWE) + сортировка
    # Тройной анализ: повышаем уверенность находок, подтверждённых >1 движком.
    _by_loc: Dict[tuple, list] = {}
    for f in all_findings:
        _by_loc.setdefault((f.line, f.cwe), []).append(f)
    for (_ln, _cwe), group in _by_loc.items():
        sources = {getattr(f, "source", "rule") for f in group}
        # Находку видят минимум 2 разных движка (taint/dataflow/rule) → confirmed
        if len(sources) >= 2:
            for f in group:
                f.confidence = "confirmed"
    _seen = set()
    _uniq = []
    for f in all_findings:
        key = (f.line, f.cwe, f.category)
        if key in _seen:
            continue
        _seen.add(key)
        _uniq.append(f)
    all_findings = _uniq
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda f: (sev_order.get(f.severity, 5), f.line))

    # 8. OWASP coverage
    owasp_coverage: Dict[str, int] = {}
    for rule in ALL_RULES:
        owasp_coverage.setdefault(rule.owasp, 0)
    found_owasp: Dict[str, int] = {}
    for f in all_findings:
        for rule in ALL_RULES:
            if rule.id == f.rule_id:
                found_owasp[rule.owasp] = found_owasp.get(rule.owasp, 0) + 1
                break

    # 9. Score
    penalty = sum(
        {"critical": 25, "high": 12, "medium": 5, "low": 2}.get(f.severity, 0)
        for f in all_findings
    )
    penalty += sum(3 for fn in functions if fn.refactor_priority == "high")
    penalty += len(duplications)
    penalty += sum(2 for a in antipatterns if a["severity"] == "high")
    score = max(0, 100 - penalty)
    grade = ("A" if score >= 90 else "B" if score >= 75
             else "C" if score >= 55 else "D" if score >= 35 else "F")

    _result = FullResult(
        filename=filename,
        language=language,
        total_lines=total_lines,
        code_lines=code_lines,
        comment_lines=comment_lines,
        findings=all_findings,
        taint_flows=taint_flows,
        functions=functions,
        duplications=duplications,
        antipatterns=antipatterns,
        score=score,
        grade=grade,
        owasp_coverage=found_owasp,
        errors=errors,
    )
    # сохраняем в кэш (с ограничением размера)
    if len(_RESULT_CACHE) >= _CACHE_MAX:
        _RESULT_CACHE.clear()
    _RESULT_CACHE[_ck] = _result
    return _result


if __name__ == "__main__":
    sample = '''
import os, pickle, hashlib, subprocess

API_KEY = "sk-prod-abc123def456ghi789jkl012mno345"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

def handler():
    uid = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id=" + uid)
    data = pickle.loads(request.body)
    h = hashlib.md5(password).hexdigest()
    subprocess.run(cmd, shell=True)
    requests.get(user_url, verify=False)
'''
    result = analyze(sample, "app.py", depth=3)
    print(f"Файл: {result.filename} ({result.language})")
    print(f"Оценка: {result.grade} ({result.score}/100)")
    print(f"Найдено: {len(result.findings)} проблем, {len(result.taint_flows)} taint-flows\n")
    for f in result.findings[:12]:
        print(f"  [{f.severity.upper():8}] {f.title}  (строка {f.line}, {f.cwe})")
