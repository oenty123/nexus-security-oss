# Installation

## Requirements

- **Python 3.8+** (the engine runs on it)
- For editor plugins: **VS Code 1.75+** or **IntelliJ IDEA / WebStorm** with JDK 17

## 1. Get the engine

```bash
git clone https://github.com/<you>/nexus-security.git
cd nexus-security
python3 install.py
```

`install.py` finds Python, verifies the engine, and prints the paths your editor needs. On Windows you can double-click `install.bat`; on Linux/macOS run `./install.sh`.

Run the engine directly any time:

```bash
python3 engine/cli.py path/to/file.py            # human-readable
python3 engine/cli.py path/to/file.py -f json    # machine-readable
python3 engine/cli.py path/to/dir -r             # whole directory
```

Flags: `-f/--format {text,json,vscode,sarif}`, `-d/--depth {1,2,3}`, `-r/--recursive`.

## 2. VS Code extension

1. Download `nexus-security-pro-*.vsix`.
2. VS Code → Extensions → `…` menu → **Install from VSIX…**
3. Reload. The extension auto-detects Python and the engine. Highlighting works on save.

Open a folder (not a single file) and trust it if VS Code asks (Workspace Trust).

## 3. IntelliJ IDEA / WebStorm plugin

```bash
cd intellij-plugin
./gradlew buildPlugin        # Windows: gradlew.bat buildPlugin
```

Then: Settings → Plugins → gear icon → **Install Plugin from Disk** → pick
`build/distributions/nexus-security-intellij-*.zip`. Set the Python and `cli.py`
paths in Settings → Tools → Nexus Security (or leave blank to auto-find).

First build downloads the IntelliJ SDK (~1–2 GB), so it needs internet once.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| "Python not found" | Install Python 3.8+, or set the path in plugin settings |
| "cli.py not found" | Open the project folder containing `engine/`, or set the path manually |
| No highlighting (VS Code) | Trust the workspace; check **Output → Nexus Security** |
| Slow on huge files | Long lines are auto-skipped (ReDoS guard); this is expected |

## Project config (.nexusrc)

Drop a `.nexusrc` (JSON) in your project root to set defaults — no need to pass
flags every time:

```json
{
  "depth": 3,
  "all": false,
  "ignore_rule": ["AP-MAGIC-NUMBER", "AP-PRINT-IN-CODE"],
  "fail_on": "high"
}
```

CLI flags always override the config. Keys: `depth` (1-3), `all` (show quality
issues), `ignore_rule` (list of rule IDs to hide), `fail_on` (exit code threshold).

## Commands

After `python3 install.py`, the `nexus` command works from anywhere:

```bash
nexus .                      # scan current project (security only)
nexus . --all                # include code-quality issues
nexus file.py                # scan one file
nexus . -f html -o report.html   # shareable HTML report
nexus --watch .              # re-scan on every save
nexus init                   # create a .nexusrc config
nexus fix file.py            # apply safe refactorings (makes a .bak backup)
nexus --version
```

`nexus fix` only applies level-1 (always-safe) transformations by default and
always writes a `.bak` backup first. Use `--level 2` or `3` for more.

## Standalone binary (no Python for end users)

To let users run Nexus **without installing Python**, build a binary with PyInstaller:

```bash
cd engine
pip install pyinstaller
pyinstaller nexus.spec
# → dist/nexus (or dist/nexus.exe on Windows)
```

The binary is platform-specific — build once per OS (Windows / macOS / Linux).
Ship the single `dist/nexus` file; end users need nothing else.

## Running tests

```bash
python3 engine/run_tests.py
```

Checks detection, false positives, edge cases, and ReDoS safety. CI runs this on
every push.

## Automated binary builds (GitHub Actions)

The `.github/workflows/build.yml` workflow builds binaries for Linux, macOS, and
Windows automatically. Two ways to trigger:

1. **Create a release tag** — binaries are built and attached to the GitHub release:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
2. **Manual run** — Actions tab → "Build binaries" → Run workflow. Download the
   binaries from the run's Artifacts section.

Each binary is self-contained — users run it without installing Python.
