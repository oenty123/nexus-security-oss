# Language coverage

Nexus is honest about depth. **Python** gets full analysis. Other languages get
pattern-based security rules — solid for catching real issues, but without the
AST-level metrics, taint analysis, and refactoring that Python enjoys.

## Rule counts

| Language | Rules | Tier | Deep analysis* |
|----------|------:|------|:--------------:|
| Python | 133 | Excellent | ✅ |
| JavaScript | 50 | Excellent | — |
| TypeScript | 40 | Excellent | — |
| Java | 36 | Good | — |
| PHP | 30 | Good | — |
| Kotlin | 26 | Good | — |
| HTML | 25 | Good | — |
| Go | 24 | Good | — |
| C# | 24 | Good | — |
| C / C++ | 24 | Good | — |
| Rust | 24 | Good | — |
| Ruby | 23 | Good | — |
| Swift | 23 | Good | — |
| CSS / SCSS | 21 | Moderate | — |
| Shell | 21 | Moderate | — |
| YAML | 21 | Baseline | — |
| SQL | 20 | Baseline | — |
| Scala / Lua / R / Dart | 20 | Baseline | — |

\* **Deep analysis** = cyclomatic/cognitive complexity, taint/dataflow tracking,
and automated safe refactoring. Currently Python-only.

Also supported as **build files**: `pom.xml` (Maven), `build.gradle[.kts]` (Gradle)
— checks for http repositories, dynamic versions, and hardcoded secrets.

## What the rules detect

Across all languages: SQL injection, XSS, command injection, code injection
(eval/SSTI), hardcoded secrets, weak cryptography, insecure deserialization,
path traversal, XXE, SSRF, insecure TLS, and language-specific pitfalls
(buffer overflows in C, `Marshal.load` in Ruby, `InsecureSkipVerify` in Go, etc.).

Every finding maps to a **CWE** and an **OWASP Top 10 (2021)** category.

## Limitations

- Non-Python rules are regex-based: they catch patterns, not data flow. A
  tainted value passed through several functions may be missed.
- Coverage depth varies. Baseline-tier languages catch the most common issues
  (secrets, code execution, injection) but not the long tail.
- For a serious audit of a specific language, pair Nexus with a specialized tool
  (e.g. `gosec` for Go, `cargo-audit` for Rust).

Want deeper coverage for a language you use? See [CONTRIBUTING.md](../CONTRIBUTING.md)
— adding rules is straightforward.
