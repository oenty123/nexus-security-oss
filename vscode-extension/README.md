# Nexus Security Pro — VS Code Extension

Анализ кода в реальном времени: подсветка уязвимостей **прямо при наборе**.
SQL-инъекции, RCE, секреты, SSRF и 50+ проверок — волнистые подчёркивания в коде.

## Возможности

- **Real-time анализ** — уязвимости подсвечиваются при наборе (debounce 800мс)
- **Problems-панель** — все находки списком (Ctrl+Shift+M)
- **Quick Fix** — лампочка предлагает исправление из движка Nexus
- **Hover** — описание уязвимости + ссылка на CWE
- **Workspace scan** — анализ всего проекта одной командой

## Установка (для разработки)

```bash
cd vscode-extension
npm install          # установка зависимостей
npm run compile      # компиляция TypeScript → out/

# Запуск в режиме отладки:
# Откройте папку в VS Code, нажмите F5 — откроется окно с расширением
```

## Сборка .vsix для распространения

```bash
npm install -g @vscode/vsce
vsce package         # создаст nexus-security-pro-2.0.0.vsix

# Установка из файла:
code --install-extension nexus-security-pro-2.0.0.vsix
```

## Публикация в Marketplace

```bash
vsce login <publisher>     # требует Personal Access Token от Azure DevOps
vsce publish               # публикует в VS Code Marketplace
```

## Настройки (settings.json)

| Параметр | По умолчанию | Описание |
|----------|-------------|----------|
| `nexus.pythonPath` | `python` | Путь к Python |
| `nexus.cliPath` | (авто) | Путь к cli.py |
| `nexus.runOnSave` | `true` | Анализ при сохранении |
| `nexus.runOnType` | `true` | Анализ при наборе |
| `nexus.debounceMs` | `800` | Задержка при наборе |
| `nexus.depth` | `2` | Глубина (1-3) |
| `nexus.minSeverity` | `low` | Минимальный уровень |

## Требования

- VS Code 1.75+
- Python 3.11+ с установленным движком Nexus (`pip install -r requirements.txt`)
- `cli.py` в корне workspace (или укажите `nexus.cliPath`)

## Команды (Ctrl+Shift+P)

- **Nexus: Scan Current File**
- **Nexus: Scan Entire Workspace**
- **Nexus: Clear All Warnings**
