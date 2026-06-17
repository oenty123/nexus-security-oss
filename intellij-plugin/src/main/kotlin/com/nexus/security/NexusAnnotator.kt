package com.nexus.security

import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.ExternalAnnotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiFile

/**
 * Подсвечивает находки Nexus прямо в коде (волнистые линии), как inspections.
 *
 * ExternalAnnotator работает в три фазы:
 *   1. collectInformation — собрать данные из файла (в EDT, быстро);
 *   2. doAnnotate — тяжёлая работа в фоне (запуск анализатора);
 *   3. apply — нанести подсветку (в EDT).
 */
class NexusAnnotator : ExternalAnnotator<NexusAnnotator.Info, AnalysisResult>() {

    data class Info(val filePath: String, val basePath: String?, val text: String)

    override fun collectInformation(file: PsiFile, editor: Editor, hasErrors: Boolean): Info? {
        val vFile = file.virtualFile ?: return null
        // Анализируем только сохранённые файлы на диске
        if (!vFile.isInLocalFileSystem) return null
        return Info(vFile.path, file.project.basePath, editor.document.text)
    }

    override fun doAnnotate(info: Info?): AnalysisResult? {
        if (info == null) return null
        return when (val r = NexusRunner.analyze(info.filePath, info.basePath)) {
            is NexusRunner.RunResult.Ok -> r.analysis
            is NexusRunner.RunResult.Error -> null  // ошибки показывает ручной запуск, не аннотатор
        }
    }

    override fun apply(file: PsiFile, result: AnalysisResult?, holder: AnnotationHolder) {
        if (result == null) return
        val document = file.viewProvider.document ?: return
        val lineCount = document.lineCount

        for (f in result.findings) {
            val lineIdx = (f.line - 1).coerceIn(0, (lineCount - 1).coerceAtLeast(0))
            if (lineIdx >= lineCount) continue

            val start = document.getLineStartOffset(lineIdx)
            val end = document.getLineEndOffset(lineIdx)
            // диапазон строки без хвостовых пробелов; пустую строку пропускаем
            val text = document.getText(TextRange(start, end))
            val trimmedLen = text.trimEnd().length
            if (trimmedLen == 0) continue
            val range = TextRange(start, start + trimmedLen)

            val severity = when (f.severity) {
                "critical", "high" -> HighlightSeverity.ERROR
                "medium" -> HighlightSeverity.WARNING
                else -> HighlightSeverity.WEAK_WARNING
            }
            val message = buildString {
                append(f.title)
                if (f.rule.isNotEmpty()) append("  [").append(f.rule).append("]")
            }
            holder.newAnnotation(severity, message)
                .range(range)
                .create()
        }
    }
}
