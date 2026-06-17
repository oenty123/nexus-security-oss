"""
compliance.py — маппинг уязвимостей на стандарты соответствия.

Поддерживаемые стандарты:
  - OWASP Top 10 2021
  - PCI DSS v4.0
  - HIPAA Security Rule
  - SOC 2 Type II (Trust Services Criteria)
  - GDPR (технические меры, Article 32)
  - NIST SSDF (Secure Software Development Framework)

Генерирует compliance-отчёт: PASS/FAIL по каждому требованию.
Это ключевая фича для enterprise-продаж: CISO покупают её за $50-100K/год.
"""

from __future__ import annotations

import dataclasses
from typing import Dict, List


@dataclasses.dataclass
class ComplianceRequirement:
    standard:    str
    control_id:  str
    title:       str
    description: str
    cwe_list:    List[str]        # CWE, нарушающие это требование
    severity:    str              # required | recommended


@dataclasses.dataclass
class ComplianceResult:
    standard:        str
    control_id:      str
    title:           str
    status:          str          # pass | fail | not_applicable
    violations:      List[dict]    # findings, нарушающие требование
    recommendation:  str


# ═════════════════════════════════════════════════════════════════════════════
# PCI DSS v4.0 — для обработки платёжных карт
# ═════════════════════════════════════════════════════════════════════════════

PCI_DSS = [
    ComplianceRequirement(
        "PCI DSS v4.0", "6.2.4",
        "Защита от инъекционных атак",
        "Программное обеспечение защищено от инъекционных атак (SQL, command, LDAP).",
        ["CWE-89", "CWE-78", "CWE-90", "CWE-643", "CWE-94"], "required",
    ),
    ComplianceRequirement(
        "PCI DSS v4.0", "6.2.4.1",
        "Защита от XSS и CSRF",
        "Защита от межсайтового скриптинга и подделки запросов.",
        ["CWE-79", "CWE-352"], "required",
    ),
    ComplianceRequirement(
        "PCI DSS v4.0", "3.5.1",
        "Криптографическая защита PAN",
        "Номера карт защищены стойкой криптографией. Запрещены MD5, SHA-1, слабые ключи.",
        ["CWE-327", "CWE-326", "CWE-321"], "required",
    ),
    ComplianceRequirement(
        "PCI DSS v4.0", "8.3.2",
        "Защита учётных данных",
        "Пароли и ключи не хранятся в открытом виде. Запрещён хардкод секретов.",
        ["CWE-798", "CWE-256", "CWE-321"], "required",
    ),
    ComplianceRequirement(
        "PCI DSS v4.0", "4.2.1",
        "Шифрование передачи данных (TLS)",
        "Данные передаются по стойкому TLS. SSL verify не отключается.",
        ["CWE-295", "CWE-326"], "required",
    ),
    ComplianceRequirement(
        "PCI DSS v4.0", "6.3.1",
        "Безопасная обработка ошибок",
        "Ошибки не раскрывают чувствительную информацию (stack trace, конфиги).",
        ["CWE-209", "CWE-489"], "required",
    ),
]


# ═════════════════════════════════════════════════════════════════════════════
# HIPAA Security Rule — для медицинских данных (PHI)
# ═════════════════════════════════════════════════════════════════════════════

HIPAA = [
    ComplianceRequirement(
        "HIPAA", "164.312(a)(2)(iv)",
        "Шифрование и дешифрование PHI",
        "Защищённая медицинская информация шифруется стойкими алгоритмами.",
        ["CWE-327", "CWE-326", "CWE-321"], "required",
    ),
    ComplianceRequirement(
        "HIPAA", "164.312(b)",
        "Контроль аудита",
        "Действия логируются. Логи защищены от инъекций и не содержат PHI/секретов.",
        ["CWE-117", "CWE-532"], "required",
    ),
    ComplianceRequirement(
        "HIPAA", "164.312(c)(1)",
        "Целостность данных",
        "PHI защищена от несанкционированного изменения. Безопасная десериализация.",
        ["CWE-502", "CWE-345"], "required",
    ),
    ComplianceRequirement(
        "HIPAA", "164.312(d)",
        "Аутентификация лиц или сущностей",
        "Доступ только аутентифицированным субъектам. Стойкая аутентификация.",
        ["CWE-287", "CWE-798", "CWE-347"], "required",
    ),
    ComplianceRequirement(
        "HIPAA", "164.312(e)(1)",
        "Безопасность передачи",
        "PHI передаётся по защищённым каналам. Защита от SSRF и MITM.",
        ["CWE-295", "CWE-918"], "required",
    ),
]


# ═════════════════════════════════════════════════════════════════════════════
# SOC 2 Type II — Trust Services Criteria
# ═════════════════════════════════════════════════════════════════════════════

SOC2 = [
    ComplianceRequirement(
        "SOC 2", "CC6.1",
        "Логический доступ — защита от несанкционированного доступа",
        "Реализованы средства защиты от несанкционированного доступа: access control, IDOR-защита.",
        ["CWE-22", "CWE-601", "CWE-915", "CWE-269"], "required",
    ),
    ComplianceRequirement(
        "SOC 2", "CC6.6",
        "Защита от внешних угроз",
        "Система защищена от инъекций, SSRF и других внешних атак.",
        ["CWE-89", "CWE-78", "CWE-918", "CWE-94"], "required",
    ),
    ComplianceRequirement(
        "SOC 2", "CC6.7",
        "Защита передаваемых данных",
        "Данные при передаче зашифрованы. TLS не ослабляется.",
        ["CWE-295", "CWE-326"], "required",
    ),
    ComplianceRequirement(
        "SOC 2", "CC6.8",
        "Защита от вредоносного ПО и небезопасного кода",
        "Защита от выполнения произвольного кода (RCE, десериализация).",
        ["CWE-95", "CWE-502", "CWE-78"], "required",
    ),
    ComplianceRequirement(
        "SOC 2", "CC7.1",
        "Обнаружение уязвимостей",
        "Уязвимости конфигурации выявляются. Нет хардкод-секретов, DEBUG=True.",
        ["CWE-798", "CWE-489", "CWE-942"], "recommended",
    ),
]


# ═════════════════════════════════════════════════════════════════════════════
# GDPR Article 32 — технические меры защиты
# ═════════════════════════════════════════════════════════════════════════════

GDPR = [
    ComplianceRequirement(
        "GDPR", "Art.32(1)(a)",
        "Псевдонимизация и шифрование персональных данных",
        "Персональные данные шифруются стойкими алгоритмами.",
        ["CWE-327", "CWE-326", "CWE-321"], "required",
    ),
    ComplianceRequirement(
        "GDPR", "Art.32(1)(b)",
        "Конфиденциальность и целостность систем",
        "Защита от инъекций, RCE и несанкционированного доступа к данным.",
        ["CWE-89", "CWE-95", "CWE-502", "CWE-22"], "required",
    ),
    ComplianceRequirement(
        "GDPR", "Art.32(2)",
        "Защита от случайного раскрытия",
        "Данные не раскрываются через ошибки, логи или небезопасную конфигурацию.",
        ["CWE-209", "CWE-532", "CWE-200"], "required",
    ),
]


# ═════════════════════════════════════════════════════════════════════════════
# OWASP Top 10 2021
# ═════════════════════════════════════════════════════════════════════════════

OWASP_TOP10 = [
    ComplianceRequirement(
        "OWASP Top 10 2021", "A01",
        "Broken Access Control",
        "Защита от обхода контроля доступа: IDOR, path traversal, privilege escalation.",
        ["CWE-22", "CWE-601", "CWE-915", "CWE-269"], "required",
    ),
    ComplianceRequirement(
        "OWASP Top 10 2021", "A02",
        "Cryptographic Failures",
        "Стойкая криптография. Нет MD5/SHA-1, слабого PRNG, хардкод-ключей.",
        ["CWE-327", "CWE-338", "CWE-321", "CWE-208"], "required",
    ),
    ComplianceRequirement(
        "OWASP Top 10 2021", "A03",
        "Injection",
        "Защита от SQL, command, LDAP, XPath, SSTI инъекций.",
        ["CWE-89", "CWE-78", "CWE-90", "CWE-643", "CWE-94", "CWE-943"], "required",
    ),
    ComplianceRequirement(
        "OWASP Top 10 2021", "A05",
        "Security Misconfiguration",
        "Безопасная конфигурация: нет DEBUG=True, CORS *, XXE.",
        ["CWE-489", "CWE-942", "CWE-611", "CWE-209"], "required",
    ),
    ComplianceRequirement(
        "OWASP Top 10 2021", "A07",
        "Identification and Authentication Failures",
        "Стойкая аутентификация: нет JWT none, слабых секретов, открытых паролей.",
        ["CWE-345", "CWE-347", "CWE-798", "CWE-256", "CWE-330"], "required",
    ),
    ComplianceRequirement(
        "OWASP Top 10 2021", "A08",
        "Software and Data Integrity Failures",
        "Безопасная десериализация. Нет pickle/yaml.load недоверенных данных.",
        ["CWE-502"], "required",
    ),
    ComplianceRequirement(
        "OWASP Top 10 2021", "A10",
        "Server-Side Request Forgery (SSRF)",
        "Защита от SSRF: валидация URL, whitelist доменов.",
        ["CWE-918"], "required",
    ),
]


STANDARDS: Dict[str, List[ComplianceRequirement]] = {
    "PCI_DSS":  PCI_DSS,
    "HIPAA":    HIPAA,
    "SOC2":     SOC2,
    "GDPR":     GDPR,
    "OWASP":    OWASP_TOP10,
}


def evaluate_compliance(
    findings: List[dict],
    standard: str,
) -> List[ComplianceResult]:
    """
    Оценивает соответствие findings заданному стандарту.

    Args:
        findings: список findings (dict с полем 'cwe')
        standard: ключ из STANDARDS (PCI_DSS, HIPAA, SOC2, GDPR, OWASP)

    Returns:
        список ComplianceResult — PASS/FAIL по каждому требованию
    """
    requirements = STANDARDS.get(standard.upper())
    if not requirements:
        raise ValueError(f"Неизвестный стандарт: {standard}. Доступны: {list(STANDARDS)}")

    # Индексируем findings по CWE
    cwe_to_findings: Dict[str, List[dict]] = {}
    for f in findings:
        cwe = f.get("cwe", "")
        cwe_to_findings.setdefault(cwe, []).append(f)

    results: List[ComplianceResult] = []
    for req in requirements:
        violations: List[dict] = []
        for cwe in req.cwe_list:
            violations.extend(cwe_to_findings.get(cwe, []))

        if violations:
            status = "fail"
            rec = (
                f"Обнаружено {len(violations)} нарушений. "
                f"Устраните уязвимости {', '.join(set(req.cwe_list))} "
                f"для соответствия {req.standard} {req.control_id}."
            )
        else:
            status = "pass"
            rec = "Требование выполнено."

        results.append(ComplianceResult(
            standard=req.standard,
            control_id=req.control_id,
            title=req.title,
            status=status,
            violations=violations,
            recommendation=rec,
        ))

    return results


def compliance_summary(findings: List[dict], standard: str) -> dict:
    """Сводка по соответствию стандарту."""
    results = evaluate_compliance(findings, standard)
    passed = sum(1 for r in results if r.status == "pass")
    failed = sum(1 for r in results if r.status == "fail")
    total = len(results)
    compliance_pct = round(passed / total * 100, 1) if total else 100.0

    return {
        "standard": standard,
        "total_controls": total,
        "passed": passed,
        "failed": failed,
        "compliance_percentage": compliance_pct,
        "compliant": failed == 0,
        "controls": [
            {
                "control_id": r.control_id,
                "title": r.title,
                "status": r.status,
                "violations_count": len(r.violations),
                "recommendation": r.recommendation,
            }
            for r in results
        ],
    }


def all_standards_summary(findings: List[dict]) -> dict:
    """Сводка по всем стандартам сразу — для enterprise-дашборда."""
    return {
        std: compliance_summary(findings, std)
        for std in STANDARDS
    }


if __name__ == "__main__":
    sample_findings = [
        {"cwe": "CWE-89",  "title": "SQL Injection", "severity": "critical"},
        {"cwe": "CWE-798", "title": "Hardcoded Secret", "severity": "critical"},
        {"cwe": "CWE-327", "title": "MD5 Hash", "severity": "high"},
    ]
    for std in STANDARDS:
        s = compliance_summary(sample_findings, std)
        status = "✅ COMPLIANT" if s["compliant"] else f"❌ {s['failed']} FAILED"
        print(f"{std:10} {s['compliance_percentage']:5.1f}%  {status}")
