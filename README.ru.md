<div align="center">

# 🛡️ Nexus Security

**Быстрый локальный SAST-анализатор для 23+ языков. Ваш код не покидает машину.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Languages](https://img.shields.io/badge/языков-23%2B-blue.svg)]()
[![No cloud](https://img.shields.io/badge/приватность-100%25%20локально-brightgreen.svg)]()

[English version](README.md)

</div>

---

## Зачем Nexus?

Большинство сканеров безопасности (Snyk, SonarCloud) загружают ваш код на свои серверы. **Nexus работает полностью на вашей машине** — ничего никуда не отправляется. Это подходит финтеху, медицине, госсектору и любой команде, которой нельзя выгружать код наружу.

- 🔒 **100% локально** — без облака, телеметрии, аккаунта, работает офлайн
- ⚡ **Быстро** — regex + AST, без тяжёлого ML
- 🌍 **23+ языка** — Python, JS/TS, Java, Kotlin, Go, Rust, PHP, C/C++, C#, Ruby, Swift, HTML, CSS и др.
- 🧩 **Интеграция с IDE** — расширение для VS Code и плагин для IntelliJ IDEA
- 🧠 **Не только безопасность** — метрики сложности, безопасный рефакторинг, объяснение кода, генерация docstring (Python)

## Что находит

SQL-инъекции, XSS, command injection, SSTI, хардкод-секреты, слабую криптографию, небезопасную десериализацию, path traversal, XXE, SSRF и десятки других — с привязкой к **CWE** и **OWASP Top 10**.

```
$ python3 cli.py app.py --format json
→ язык: python | оценка: D | находок: 4
  [critical] SSTI — render_template_string с вводом (строка 12)
  [critical] Command Injection — shell=True (строка 18)
  [high]     Хардкод секрета / API-ключа (строка 3)
  [low]      requests без timeout (строка 25)
```

## Быстрый старт

```bash
git clone https://github.com/<you>/nexus-security.git
cd nexus-security/engine
python3 cli.py путь/к/файлу.py
```

Нужен Python 3.8+. Ядро работает без зависимостей.

## Плагины для IDE

- **VS Code** — установите `.vsix`: подсветка находок, быстрые исправления, отчёты
- **IntelliJ IDEA / WebStorm** — плагин на Kotlin, сборка `./gradlew buildPlugin`

Полная настройка — в [`docs/INSTALL.md`](docs/INSTALL.md).

## Покрытие языков

| Уровень | Языки |
|---------|-------|
| **Отличный** | Python, JavaScript, TypeScript |
| **Хороший** | Java, Kotlin, PHP, HTML, Go, C#, Ruby, Rust, C/C++, Swift |
| **Базовый** | CSS, SQL, Shell, YAML, Scala, Lua, R, Dart |

Глубже всего анализируется Python (безопасность + сложность + taint + рефакторинг). Остальные языки получают правила безопасности на паттернах. Мы честны об этом — см. [детали покрытия](docs/COVERAGE.md).

## Планы

- [ ] Встроенный Python (установка без настройки)
- [ ] Интеграция с CI (GitHub Actions, GitLab CI)
- [ ] HTML-отчёты по всему проекту
- [ ] Больше языков с глубоким анализом

## Участие

Правила легко добавлять — см. [CONTRIBUTING.md](CONTRIBUTING.md). Особенно приветствуются правила для новых языков и сообщения о ложных срабатываниях.

## Лицензия

**AGPL-3.0** — свободно использовать, изучать, изменять и распространять; сетевые сервисы обязаны открывать исходный код. Для закрытого/коммерческого использования доступна отдельная лицензия — см. [COMMERCIAL.md](COMMERCIAL.md).
