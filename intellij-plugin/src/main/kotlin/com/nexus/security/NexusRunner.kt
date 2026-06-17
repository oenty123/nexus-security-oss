package com.nexus.security

import com.intellij.openapi.diagnostic.Logger
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Запускает анализатор Nexus (cli.py) через локальный Python и возвращает результат.
 * Анализ выполняется на машине пользователя — код никуда не отправляется.
 */
object NexusRunner {
    private val log = Logger.getInstance(NexusRunner::class.java)

    sealed class RunResult {
        data class Ok(val analysis: AnalysisResult) : RunResult()
        data class Error(val message: String) : RunResult()
    }

    /**
     * Находит cli.py: либо явно заданный в настройках путь, либо ищет
     * в корне проекта и типовых вложенных папках.
     */
    private fun resolveCli(projectBasePath: String?): File? {
        val settings = NexusSettings.getInstance()
        if (settings.cliPath.isNotBlank()) {
            val f = File(settings.cliPath)
            if (f.isFile) return f
        }
        if (projectBasePath == null) return null
        val candidates = listOf(
            "cli.py",
            "nexus_core/cli.py",
            "nexus_enterprise/cli.py",
            "nexus-enterprise/nexus_enterprise/cli.py",
            "nexus-core/nexus_core/cli.py"
        )
        for (rel in candidates) {
            val f = File(projectBasePath, rel)
            if (f.isFile) return f
        }
        return null
    }

    fun analyze(filePath: String, projectBasePath: String?): RunResult {
        val settings = NexusSettings.getInstance()
        val cli = resolveCli(projectBasePath)
            ?: return RunResult.Error(
                "cli.py не найден. Укажите путь в Settings → Tools → Nexus Security."
            )

        return try {
            // redirectErrorStream(true): stderr сливается в stdout — нет риска
            // взаимной блокировки буферов (классический deadlock ProcessBuilder).
            val process = ProcessBuilder(
                settings.pythonPath,
                cli.absolutePath,
                filePath,
                "--format", "json",
                "--depth", settings.depth.toString()
            ).redirectErrorStream(true).start()

            // Читаем вывод в отдельном потоке, чтобы буфер не переполнился,
            // пока основной поток ждёт завершения процесса.
            val outputBuffer = StringBuilder()
            val reader = Thread {
                process.inputStream.bufferedReader().forEachLine { outputBuffer.appendLine(it) }
            }
            reader.start()

            val finished = process.waitFor(30, TimeUnit.SECONDS)
            if (!finished) {
                process.destroyForcibly()
                reader.join(1000)
                return RunResult.Error("Анализ превысил лимит времени (30 c).")
            }
            reader.join(2000)
            val output = outputBuffer.toString().trim()

            // cli.py печатает JSON в stdout; при ошибке — текст/трейс.
            // JSON начинается с '[' — отделяем валидный вывод от диагностики.
            val jsonStart = output.indexOf('[')
            if (jsonStart < 0) {
                val hint = when {
                    output.contains("No such file") || output.contains("not found") ->
                        "Python или cli.py не найден. Проверьте пути в настройках."
                    output.contains("Traceback") ->
                        "Ошибка в анализаторе: " + output.takeLast(200)
                    else -> output.take(300)
                }
                return RunResult.Error("Анализатор не вернул данных. $hint")
            }
            RunResult.Ok(NexusParser.parse(output.substring(jsonStart)))
        } catch (e: Exception) {
            log.warn("Nexus analyze failed", e)
            val msg = e.message ?: "неизвестная ошибка"
            if (msg.contains("No such file") || msg.contains("error=2")) {
                RunResult.Error("Python (${settings.pythonPath}) не найден. Укажите путь в настройках.")
            } else {
                RunResult.Error("Ошибка запуска анализатора: $msg")
            }
        }
    }
}
