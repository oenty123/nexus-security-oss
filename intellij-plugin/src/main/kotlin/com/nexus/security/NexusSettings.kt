package com.nexus.security

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage

/**
 * Постоянные настройки плагина: путь к интерпретатору Python и к cli.py
 * анализатора Nexus. Хранятся на уровне приложения (общие для всех проектов).
 */
@State(
    name = "NexusSecuritySettings",
    storages = [Storage("nexus-security.xml")]
)
class NexusSettings : PersistentStateComponent<NexusSettings.State> {

    class State {
        @JvmField var pythonPath: String = "python3"
        @JvmField var cliPath: String = ""
        @JvmField var depth: Int = 2
    }

    private var state = State()

    override fun getState(): State = state
    override fun loadState(newState: State) { state = newState }

    var pythonPath: String
        get() = state.pythonPath
        set(value) { state.pythonPath = value }

    var cliPath: String
        get() = state.cliPath
        set(value) { state.cliPath = value }

    var depth: Int
        get() = state.depth
        set(value) { state.depth = value }

    companion object {
        fun getInstance(): NexusSettings =
            ApplicationManager.getApplication().getService(NexusSettings::class.java)
    }
}
