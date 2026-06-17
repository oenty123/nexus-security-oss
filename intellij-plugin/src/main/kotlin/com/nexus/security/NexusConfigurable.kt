package com.nexus.security

import com.intellij.openapi.options.Configurable
import com.intellij.openapi.ui.TextFieldWithBrowseButton
import com.intellij.openapi.fileChooser.FileChooserDescriptorFactory
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBTextField
import com.intellij.util.ui.FormBuilder
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JPanel

/**
 * Страница настроек: Settings → Tools → Nexus Security.
 * Путь к Python, путь к cli.py, глубина анализа.
 */
class NexusConfigurable : Configurable {

    private val pythonField = JBTextField()
    private val cliField = TextFieldWithBrowseButton()
    private val depthCombo = JComboBox(arrayOf("1 — быстро", "2 — стандарт", "3 — параноик"))
    private var panel: JPanel? = null

    override fun getDisplayName(): String = "Nexus Security"

    override fun createComponent(): JComponent {
        cliField.addBrowseFolderListener(
            "Путь к cli.py",
            "Выберите файл cli.py анализатора Nexus",
            null,
            FileChooserDescriptorFactory.createSingleFileDescriptor()
        )

        panel = FormBuilder.createFormBuilder()
            .addLabeledComponent(JBLabel("Интерпретатор Python:"), pythonField, 1, false)
            .addComponent(JBLabel("<html><small>На Linux обычно python3</small></html>"))
            .addLabeledComponent(JBLabel("Путь к cli.py:"), cliField, 1, false)
            .addComponent(JBLabel("<html><small>Пусто — искать в корне проекта автоматически</small></html>"))
            .addLabeledComponent(JBLabel("Глубина анализа:"), depthCombo, 1, false)
            .addComponentFillVertically(JPanel(), 0)
            .panel
        reset()
        return panel!!
    }

    override fun isModified(): Boolean {
        val s = NexusSettings.getInstance()
        return pythonField.text != s.pythonPath ||
            cliField.text != s.cliPath ||
            (depthCombo.selectedIndex + 1) != s.depth
    }

    override fun apply() {
        val s = NexusSettings.getInstance()
        s.pythonPath = pythonField.text.trim().ifEmpty { "python3" }
        s.cliPath = cliField.text.trim()
        s.depth = depthCombo.selectedIndex + 1
    }

    override fun reset() {
        val s = NexusSettings.getInstance()
        pythonField.text = s.pythonPath
        cliField.text = s.cliPath
        depthCombo.selectedIndex = (s.depth - 1).coerceIn(0, 2)
    }

    override fun disposeUIResources() {
        panel = null
    }
}
