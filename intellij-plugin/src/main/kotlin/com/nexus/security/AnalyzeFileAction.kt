package com.nexus.security

import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.wm.ToolWindowManager

/**
 * Действие «Анализировать через Nexus» — запускается из меню, контекстного
 * меню редактора или по Ctrl+Alt+N. Гоняет анализатор в фоне и показывает
 * результаты в Tool Window «Nexus Security».
 */
class AnalyzeFileAction : AnAction() {

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val file = e.getData(CommonDataKeys.VIRTUAL_FILE)
        if (file == null || file.isDirectory) {
            Messages.showInfoMessage(project, "Откройте файл для анализа.", "Nexus Security")
            return
        }
        val filePath = file.path
        val fileName = file.name
        val basePath = project.basePath

        ProgressManager.getInstance().run(
            object : Task.Backgroundable(project, "Анализ Nexus Security", true) {
                override fun run(indicator: ProgressIndicator) {
                    indicator.isIndeterminate = true
                    // project и fileName захвачены заранее — AnActionEvent
                    // нельзя использовать после завершения действия.
                    when (val result = NexusRunner.analyze(filePath, basePath)) {
                        is NexusRunner.RunResult.Ok -> {
                            ApplicationManager.getApplication().invokeLater {
                                if (!project.isDisposed) {
                                    showResults(project, fileName, result.analysis)
                                }
                            }
                        }
                        is NexusRunner.RunResult.Error -> {
                            ApplicationManager.getApplication().invokeLater {
                                if (!project.isDisposed) {
                                    Messages.showWarningDialog(project, result.message, "Nexus Security")
                                }
                            }
                        }
                    }
                }
            }
        )
    }

    private fun showResults(project: com.intellij.openapi.project.Project, fileName: String, analysis: AnalysisResult) {
        val toolWindow = ToolWindowManager.getInstance(project).getToolWindow("Nexus Security")
        toolWindow?.show()
        NexusToolWindowFactory.updateContent(project, fileName, analysis)
    }
}
