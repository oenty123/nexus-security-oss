<div align="center">

# 🛡️ Nexus Security

**A fast, fully-local SAST analyzer for 23+ languages. Your code never leaves your machine.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Languages](https://img.shields.io/badge/languages-23%2B-blue.svg)]()
[![No cloud](https://img.shields.io/badge/privacy-100%25%20local-brightgreen.svg)]()
[![CI](https://github.com/<you>/nexus-security/actions/workflows/nexus.yml/badge.svg)]()

[Русская версия](README.ru.md)

<!-- TODO: запишите короткую демо-гифку (5-10 сек): открыли файл → подсветка
     уязвимости → навели курсор → подсказка → исправили. Положите в docs/demo.gif
     и раскомментируйте строку ниже. Это сильнее всего влияет на число звёзд. -->
<!-- ![demo](docs/demo.gif) -->

</div>

---

## Why Nexus?

Most security scanners (Snyk, SonarCloud) upload your code to their servers. **Nexus runs entirely on your machine** — nothing is ever sent anywhere. That makes it a fit for fintech, healthcare, defense, and any team that legally can't ship code to a third party.

- 🔒 **100% local** — no cloud, no telemetry, no account, works offline
- ⚡ **Fast** — regex + AST, not a heavyweight ML pipeline
- 🌍 **23+ languages** — Python, JS/TS, Java, Kotlin, Go, Rust, PHP, C/C++, C#, Ruby, Swift, HTML, CSS, and more
- 🧩 **Editor integration** — VS Code extension and IntelliJ IDEA plugin
- 🧠 **More than security** — complexity metrics, safe refactoring, code explanation, docstring generation (Python)

## What it finds

SQL injection, XSS, command injection, SSTI, hardcoded secrets, weak crypto, insecure deserialization, path traversal, XXE, SSRF, and dozens more — mapped to **CWE** and **OWASP Top 10**.

```
$ python3 cli.py app.py --format json
→ language: python | grade: D | findings: 4
  [critical] SSTI — render_template_string with user input (line 12)
  [critical] Command Injection — shell=True (line 18)
  [high]     Hardcoded secret / API key (line 3)
  [low]      requests without timeout (line 25)
```

## Quick start

```bash
git clone https://github.com/<you>/nexus-security.git
cd nexus-security
python3 install.py          # finds Python, verifies the engine, prints your paths
```

The installer auto-detects everything. Then point your editor plugin at the printed paths (or it finds them automatically). Requires Python 3.8+. No dependencies for the core engine.

Prefer manual? Just run the engine directly:
```bash
python3 engine/cli.py path/to/your/file.py
```

## Editor plugins

- **VS Code** — install the `.vsix`, get inline highlighting, quick-fixes, scan reports
- **IntelliJ IDEA / WebStorm** — Kotlin plugin, build with `./gradlew buildPlugin`

See [`docs/INSTALL.md`](docs/INSTALL.md) for setup and [`docs/USAGE.md`](docs/USAGE.md) for how to use the editor extension.

## Language coverage

| Tier | Languages |
|------|-----------|
| **Excellent** | Python, JavaScript, TypeScript |
| **Good** | Java, Kotlin, PHP, HTML, Go, C#, Ruby, Rust, C/C++, Swift |
| **Baseline** | CSS, SQL, Shell, YAML, Scala, Lua, R, Dart |

Python gets the deepest analysis (security + complexity + taint + refactoring). Other languages get pattern-based security rules. We're honest about this — see [coverage details](docs/COVERAGE.md).

## Roadmap

- [ ] Bundled Python (zero-setup install)
- [ ] CI integration (GitHub Actions, GitLab CI)
- [ ] Project-wide HTML reports
- [ ] More deep-analysis languages

## Contributing

Rules are simple to add — see [CONTRIBUTING.md](CONTRIBUTING.md). New language rules and false-positive reports are especially welcome.

## License

**AGPL-3.0** — free to use, study, modify and share; network services must publish their source. For closed-source/commercial use, a separate license is available — see [COMMERCIAL.md](COMMERCIAL.md).
