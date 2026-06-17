"""
sarif_exporter.py — экспорт результатов в формат SARIF 2.1.0.

SARIF (Static Analysis Results Interchange Format) — стандарт отрасли.
Принимается: GitHub Advanced Security, GitLab SAST, Azure DevOps,
             Visual Studio Code, JetBrains IDE, SonarQube, Jira.

Без SARIF-интеграции невозможно пройти enterprise RFP.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from engine_ast import Finding


SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
    "/master/Schemata/sarif-schema-2.1.0.json"
)

_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "none",
}

_SEVERITY_TO_SCORE = {
    "critical": "9.8",
    "high":     "7.5",
    "medium":   "5.0",
    "low":      "2.0",
    "info":     "0.0",
}


def findings_to_sarif(
    findings: List[Finding],
    tool_version: str = "2.0.0",
    repo_uri: Optional[str] = None,
    scan_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Конвертирует список Finding в структуру SARIF 2.1.0.

    Args:
        findings:     список уязвимостей
        tool_version: версия Nexus Security Pro
        repo_uri:     URI репозитория (для GitHub Actions)
        scan_id:      идентификатор скана (для корреляции)

    Returns:
        dict, который сериализуется в JSON → .sarif файл
    """
    rules: Dict[str, Dict] = {}
    results: List[Dict] = []

    for f in findings:
        rule_id = f.rule_id

        # ── Определение правила ──────────────────────────────────────────
        if rule_id not in rules:
            cwe_num = f.cwe.replace("CWE-", "")
            rules[rule_id] = {
                "id": rule_id,
                "name": _pascal_case(f.title),
                "shortDescription": {"text": f.title},
                "fullDescription":  {"text": f.desc or f.title},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
                "help": {
                    "text":     _build_help_text(f),
                    "markdown": _build_help_markdown(f),
                },
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_LEVEL.get(f.severity, "warning"),
                },
                "properties": {
                    "tags": ["security", f.category],
                    "precision": f.confidence,
                    "problem.severity": f.severity,
                    "security-severity": _SEVERITY_TO_SCORE.get(f.severity, "5.0"),
                },
            }

        # ── Результат ────────────────────────────────────────────────────
        uri = f.file.replace("\\", "/")
        result: Dict[str, Any] = {
            "ruleId":  rule_id,
            "level":   _SEVERITY_TO_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.desc or f.title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri":       uri,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine":   f.line,
                        "startColumn": f.col + 1 if f.col else 1,
                    },
                },
                "logicalLocations": [{"kind": "module"}],
            }],
            "fingerprints": {
                "nexusLocationHash/v1": f.fingerprint(),
            },
            "properties": {
                "cwe":        f.cwe,
                "severity":   f.severity,
                "confidence": f.confidence,
                "source":     f.source,
            },
        }

        # Добавить fix если есть
        if f.fix_before and f.fix_after:
            result["fixes"] = [{
                "description": {"text": "Nexus auto-fix suggestion"},
                "artifactChanges": [{
                    "artifactLocation": {"uri": uri},
                    "replacements": [{
                        "deletedRegion": {
                            "startLine": f.line,
                            "startColumn": 1,
                        },
                        "insertedContent": {"text": f.fix_after + "\n"},
                    }],
                }],
            }]

        # Добавить код вокруг уязвимости
        if f.snippet:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": f.snippet
            }

        results.append(result)

    # ── Сборка SARIF-документа ────────────────────────────────────────────
    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name":           "Nexus Security Pro",
                "version":        tool_version,
                "semanticVersion": tool_version,
                "informationUri": "https://github.com/oenty123/nexus-security",
                "organization":   "Nexus Security",
                "downloadUri":    "https://github.com/oenty123/nexus-security/download",
                "rules":          list(rules.values()),
                "supportedTaxonomies": [{
                    "name":    "CWE",
                    "version": "4.13",
                    "guid":    "FFC64C90-42B6-44CE-8BEB-F6B7DAE649E5",
                }],
            }
        },
        "results":  results,
        "invocations": [{
            "executionSuccessful": True,
            "endTimeUtc": datetime.now(timezone.utc).isoformat(),
            "toolExecutionNotifications": [],
        }],
        "columnKind": "utf16CodeUnits",
        "properties": {
            "nexus:scanId":  scan_id or "",
            "nexus:version": tool_version,
        },
    }

    if repo_uri:
        run["versionControlProvenance"] = [{
            "repositoryUri": repo_uri,
            "revisionId":    "",
            "branch":        "",
        }]

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }


def write_sarif(
    findings: List[Finding],
    output_path: str,
    tool_version: str = "2.0.0",
    repo_uri: Optional[str] = None,
) -> None:
    """Записывает SARIF-файл на диск."""
    sarif = findings_to_sarif(findings, tool_version, repo_uri)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2, ensure_ascii=False)


# ── Вспомогательные функции ───────────────────────────────────────────────────

def _pascal_case(title: str) -> str:
    """'sql injection via f-string' → 'SqlInjectionViaFString'"""
    return "".join(w.capitalize() for w in title.replace("-", " ").split()[:4])


def _build_help_text(f: Finding) -> str:
    parts = [f.title, ""]
    if f.desc:
        parts += [f.desc, ""]
    parts.append(f"CWE: {f.cwe}")
    parts.append(f"Severity: {f.severity.upper()}")
    if f.fix_before:
        parts += ["", "Before:", f"  {f.fix_before}"]
    if f.fix_after:
        parts += ["After:", f"  {f.fix_after}"]
    return "\n".join(parts)


def _build_help_markdown(f: Finding) -> str:
    md = f"## {f.title}\n\n"
    if f.desc:
        md += f"{f.desc}\n\n"
    md += f"**CWE:** [{f.cwe}](https://cwe.mitre.org/data/definitions/{f.cwe.replace('CWE-', '')}.html)  \n"
    md += f"**Severity:** `{f.severity.upper()}`  \n"
    md += f"**Confidence:** `{f.confidence}`\n\n"
    if f.fix_before and f.fix_after:
        md += "### Fix\n\n"
        md += f"**Before:**\n```python\n{f.fix_before}\n```\n\n"
        md += f"**After:**\n```python\n{f.fix_after}\n```\n"
    return md
