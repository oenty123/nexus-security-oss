package com.nexus.security

import com.google.gson.Gson
import com.google.gson.annotations.SerializedName

/** Одна находка анализатора (уязвимость, антипаттерн или проблема сложности). */
data class Finding(
    val line: Int,
    val severity: String,
    val title: String,
    val cwe: String = "",
    val kind: String = "Безопасность",
    val rule: String = ""
)

/** Внутренние структуры JSON-ответа cli.py. */
private data class CliFinding(
    val line: Int = 1,
    val severity: String = "low",
    val title: String = "",
    val cwe: String = "",
    @SerializedName("rule_id") val ruleId: String = ""
)

private data class CliAntipattern(
    val line: Int = 1,
    val severity: String = "low",
    val title: String = "",
    val id: String = ""
)

private data class CliFunction(
    val name: String = "",
    val line: Int = 1,
    val issues: List<String> = emptyList()
)

private data class CliResult(
    val filename: String = "",
    val score: Int = 100,
    val grade: String = "—",
    val findings: List<CliFinding> = emptyList(),
    val antipatterns: List<CliAntipattern> = emptyList(),
    val functions: List<CliFunction> = emptyList()
)

/** Итог анализа одного файла. */
data class AnalysisResult(
    val score: Int,
    val grade: String,
    val findings: List<Finding>
)

object NexusParser {
    private val gson = Gson()

    /**
     * Разбирает JSON-массив, который печатает `cli.py <file> --format json`.
     * Собирает находки из всех трёх источников: findings, antipatterns, functions.
     */
    fun parse(json: String): AnalysisResult {
        val results = gson.fromJson(json, Array<CliResult>::class.java)
        if (results.isNullOrEmpty()) {
            return AnalysisResult(100, "—", emptyList())
        }
        val r = results[0]
        val all = mutableListOf<Finding>()

        for (f in r.findings) {
            all.add(Finding(f.line, f.severity, f.title, f.cwe, "Безопасность",
                f.cwe.ifEmpty { f.ruleId }))
        }
        for (a in r.antipatterns) {
            all.add(Finding(a.line, a.severity, a.title, "", "Качество", a.id))
        }
        for (fn in r.functions) {
            if (fn.issues.isNotEmpty()) {
                all.add(Finding(fn.line, "low",
                    "Функция «${fn.name}»: ${fn.issues.first()}", "", "Сложность", "COMPLEXITY"))
            }
        }

        val order = mapOf("critical" to 0, "high" to 1, "medium" to 2, "low" to 3, "info" to 4)
        all.sortWith(compareBy({ order[it.severity] ?: 9 }, { it.line }))
        return AnalysisResult(r.score, r.grade, all)
    }
}
