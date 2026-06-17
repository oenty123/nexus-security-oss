# Nexus Security — плагин для IntelliJ IDEA

SAST-анализатор кода для IntelliJ IDEA (и других IDE на платформе IntelliJ:
PyCharm, WebStorm, Android Studio). Находит уязвимости безопасности в коде на
Python, JavaScript, TypeScript, Java, Kotlin, PHP, Go и других языках.

Плагин — это «обёртка»: он вызывает тот же анализатор Nexus (`cli.py`), что и
расширение для VS Code. Анализ выполняется локально, код никуда не отправляется.

---

## Требования

Перед установкой убедитесь, что есть:

1. **JDK 17** — для сборки плагина (`java -version` должно показать 17+).
2. **Python 3** — на машине, где будет работать плагин (он вызывает `cli.py`).
   Проверка: `python3 --version`.
3. **Файлы анализатора Nexus** — папка с `cli.py` и движком (`rules_security.py`,
   `engine_ast.py` и т.д.). Это те же файлы, что вы используете в VS Code-версии.
4. **Интернет** — нужен один раз при первой сборке (Gradle скачает зависимости
   и IntelliJ SDK, ~1–2 ГБ).

---

## Сборка плагина

В терминале, в папке `nexus-intellij`:

### Linux / macOS
```bash
cd nexus-intellij
chmod +x gradlew
./gradlew buildPlugin
```

### Windows
```bat
cd nexus-intellij
gradlew.bat buildPlugin
```

> Если файла `gradlew` нет (он не приложен), сгенерируйте его командой
> `gradle wrapper` (нужен установленный Gradle), либо откройте папку в IntelliJ
> IDEA — она предложит импортировать Gradle-проект и создаст wrapper сама.

Сборка займёт несколько минут (первый раз — дольше из-за скачивания SDK).
Готовый плагин появится здесь:

```
build/distributions/nexus-security-intellij-1.0.0.zip
```

---

## Установка в IntelliJ IDEA

1. Откройте IntelliJ IDEA.
2. **File → Settings** (на macOS: **IntelliJ IDEA → Preferences**).
3. Раздел **Plugins**.
4. Нажмите ⚙️ (шестерёнка вверху) → **Install Plugin from Disk…**
5. Выберите собранный файл
   `build/distributions/nexus-security-intellij-1.0.0.zip`
6. Нажмите **OK** и перезапустите IDE, когда предложит.

---

## Настройка

После установки и перезапуска:

1. **File → Settings → Tools → Nexus Security**.
2. Заполните:
   - **Интерпретатор Python** — обычно `python3` (Linux/macOS) или `python` (Windows).
   - **Путь к cli.py** — нажмите кнопку обзора и укажите файл `cli.py` анализатора
     Nexus. Если оставить пустым — плагин поищет его в корне открытого проекта
     автоматически.
   - **Глубина анализа** — 2 (стандарт) по умолчанию.
3. **OK**.

---

## Использование

1. Откройте любой файл с кодом (`.py`, `.js`, `.ts`, `.java`, `.php`, …).
2. Запустите анализ одним из способов:
   - горячая клавиша **Ctrl+Alt+N**;
   - правый клик в редакторе → **«Анализировать через Nexus»**;
   - меню **Tools → «Анализировать через Nexus»**.
3. Внизу откроется панель **Nexus Security** со списком находок:
   уровень, описание, тип, правило, строка.
4. **Двойной клик** по находке — переход к нужной строке в коде.

---

## Возможные проблемы

**«cli.py не найден»**
Укажите точный путь к `cli.py` в настройках (Tools → Nexus Security), либо
откройте в IDE папку проекта, где он лежит.

**«Python не найден»**
Проверьте, что Python 3 установлен (`python3 --version`). Впишите правильную
команду в поле «Интерпретатор Python» (на Windows часто `python`, не `python3`).

**Сборка падает с ошибкой сети**
Gradle не смог скачать SDK/зависимости. Проверьте интернет и повторите
`./gradlew buildPlugin`. За корпоративным прокси может потребоваться настройка
прокси для Gradle.

**Плагин не виден после установки**
Убедитесь, что перезапустили IDE. Проверьте Settings → Plugins → вкладка
Installed — там должен быть «Nexus Security» (включён).

---

## Что плагин умеет и чего пока нет

**Умеет:**
- анализ текущего файла (Ctrl+Alt+N);
- **подсветка находок прямо в коде** — волнистые линии под уязвимостями,
  с описанием при наведении (как встроенные inspections);
- список находок в панели с переходом к строке по двойному клику;
- настройка пути к Python/cli.py и глубины;
- поддержка всех языков движка: Python, JavaScript, TypeScript, Java, Kotlin,
  PHP, Go, Rust, C/C++, C#, Swift, Ruby, HTML, CSS, SQL, Shell и др.;
- **анализ файлов сборки** — `pom.xml` (Maven), `build.gradle` / `.kts` (Gradle):
  http-репозитории, динамические версии, секреты в build-файлах.

**Пока нет** (в отличие от VS Code-версии): автофиксов и журнала по всему
проекту. Подсветка и анализ работают.

> Примечание про подсветку: аннотатор зарегистрирован для всех языков
> (`language=""` в plugin.xml). Если в вашей версии IDE подсветка не появляется,
> используйте ручной запуск (Ctrl+Alt+N) — он работает всегда.

---

## Архитектура (для разработчиков)

```
nexus-intellij/
├── build.gradle.kts              сборка (Gradle + Kotlin + IntelliJ plugin)
├── settings.gradle.kts
└── src/main/
    ├── kotlin/com/nexus/security/
    │   ├── NexusSettings.kt        хранение настроек
    │   ├── NexusParser.kt          разбор JSON-вывода cli.py
    │   ├── NexusRunner.kt          запуск Python + cli.py
    │   ├── AnalyzeFileAction.kt    действие «Анализировать»
    │   ├── NexusToolWindow.kt      панель результатов
    │   └── NexusConfigurable.kt    страница настроек
    └── resources/META-INF/
        └── plugin.xml              манифест плагина
```

Лицензия: MIT
