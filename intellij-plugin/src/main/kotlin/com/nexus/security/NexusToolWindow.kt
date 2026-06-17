package com.nexus.security

import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.content.ContentFactory
import com.intellij.ui.table.JBTable
import java.awt.BorderLayout
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.ListSelectionModel
import javax.swing.table.DefaultTableModel
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent

/**
 * Нижняя панель «Nexus Security» со списком находок.
 * Двойной клик по строке открывает файл на нужной строке.
 */
class NexusToolWindowFactory : ToolWindowFactory {

    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = NexusResultPanel(project)
        panels[project] = panel
        val content = ContentFactory.getInstance().createContent(panel, "", false)
        toolWindow.contentManager.addContent(content)
        // Очищаем ссылку на панель при закрытии проекта (без утечки памяти)
        com.intellij.openapi.util.Disposer.register(project) { unregister(project) }
    }

    companion object {
        private val panels = mutableMapOf<Project, NexusResultPanel>()

        fun updateContent(project: Project, fileName: String, analysis: AnalysisResult) {
            if (project.isDisposed) { panels.remove(project); return }
            panels[project]?.update(fileName, analysis)
        }

        fun unregister(project: Project) {
            panels.remove(project)
        }
    }
}

class NexusResultPanel(private val project: Project) : JPanel(BorderLayout()) {

    private val header = JLabel("Запустите анализ: Ctrl+Alt+N или ПКМ → «Анализировать через Nexus»")
    private val columns = arrayOf("Уровень", "Проблема", "Тип", "Правило", "Строка")
    private val model = object : DefaultTableModel(columns, 0) {
        override fun isCellEditable(row: Int, col: Int) = false
    }
    private val table = JBTable(model)
    private var currentFile: String? = null
    private var lines = listOf<Int>()

    init {
        table.selectionMode = ListSelectionModel.SINGLE_SELECTION
        table.columnModel.getColumn(0).maxWidth = 90
        table.columnModel.getColumn(2).maxWidth = 110
        table.columnModel.getColumn(4).maxWidth = 70

        table.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2) navigateToSelected()
            }
        })

        add(header, BorderLayout.NORTH)
        add(JBScrollPane(table), BorderLayout.CENTER)
    }

    fun update(fileName: String, analysis: AnalysisResult) {
        currentFile = fileName
        header.text = "  $fileName — оценка ${analysis.score}/100 (${analysis.grade}), " +
            "найдено ${analysis.findings.size}"
        model.rowCount = 0
        lines = analysis.findings.map { it.line }
        for (f in analysis.findings) {
            model.addRow(arrayOf(f.severity, f.title, f.kind, f.rule, f.line.toString()))
        }
    }

    private fun navigateToSelected() {
        val row = table.selectedRow
        if (row < 0 || row >= lines.size) return
        val line = lines[row]
        val editor = FileEditorManager.getInstance(project).selectedTextEditor ?: return
        val file = com.intellij.openapi.fileEditor.FileDocumentManager
            .getInstance().getFile(editor.document) ?: return
        val targetLine = (line - 1).coerceAtLeast(0)
        OpenFileDescriptor(project, file, targetLine, 0).navigate(true)
    }
}
