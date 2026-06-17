#!/usr/bin/env python3
"""
Nexus Security — авто-установщик.

Запустите:  python3 install.py   (или python install.py)

Что делает:
  1. Проверяет версию Python (нужен 3.8+).
  2. Находит движок (cli.py) и проверяет, что он работает.
  3. Печатает готовые значения для настроек VS Code / IntelliJ
     (путь к Python и к cli.py) — копируете их в настройки плагина.
  4. Опционально создаёт файл nexus-config.json с этими путями.

Не требует прав администратора, ничего не качает, работает офлайн.
"""
import sys
import os
import json
import subprocess
from pathlib import Path


GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"; BOLD = "\033[1m"; RESET = "\033[0m"
if os.name == "nt" or not sys.stdout.isatty():
    GREEN = RED = YELLOW = BOLD = RESET = ""


def ok(msg): print(f"{GREEN}✓{RESET} {msg}")
def warn(msg): print(f"{YELLOW}!{RESET} {msg}")
def err(msg): print(f"{RED}✗{RESET} {msg}")


def check_python() -> bool:
    v = sys.version_info
    if v < (3, 8):
        err(f"Python {v.major}.{v.minor} слишком старый. Нужен 3.8+.")
        return False
    ok(f"Python {v.major}.{v.minor}.{v.micro} — подходит")
    return True


def find_cli() -> Path | None:
    """Ищет cli.py рядом с установщиком и в типовых подпапках."""
    here = Path(__file__).resolve().parent
    candidates = [
        here / "cli.py",
        here / "engine" / "cli.py",
        here / "nexus-engine" / "cli.py",
        here / "nexus_enterprise" / "cli.py",
    ]
    for c in candidates:
        if c.is_file():
            return c
    # рекурсивный поиск на 2 уровня вглубь
    for sub in here.rglob("cli.py"):
        if "test" not in str(sub).lower():
            return sub
    return None


def test_engine(cli: Path, python: str) -> bool:
    """Прогоняет движок на временном файле, проверяет, что он отвечает."""
    sample = cli.parent / "_nexus_selftest.py"
    try:
        sample.write_text('password = "test12345secret"\neval(x)\n', encoding="utf-8")
        result = subprocess.run(
            [python, str(cli), str(sample), "--format", "json"],
            capture_output=True, text=True, timeout=30,
        )
        sample.unlink(missing_ok=True)
        if result.returncode == 0 and result.stdout.strip().startswith("["):
            data = json.loads(result.stdout)
            n = len(data[0].get("findings", [])) if data else 0
            ok(f"Движок работает — нашёл {n} проблем в тесте")
            return True
        err(f"Движок вернул ошибку: {result.stderr[:200] or result.stdout[:200]}")
        return False
    except subprocess.TimeoutExpired:
        err("Движок не ответил за 30 секунд.")
        return False
    except Exception as e:  # noqa: BLE001
        err(f"Не удалось запустить движок: {e}")
        return False
    finally:
        try:
            sample.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass


def main() -> int:
    print(f"\n{BOLD}🛡️  Nexus Security — установка{RESET}\n")

    if not check_python():
        print("\nУстановите Python 3.8+ с https://python.org и повторите.")
        return 1

    cli = find_cli()
    if cli is None:
        err("Не найден cli.py. Запустите install.py из папки с движком.")
        return 1
    ok(f"Движок найден: {cli}")

    python = sys.executable  # тот же интерпретатор, что запустил установщик
    if not test_engine(cli, python):
        return 1

    # готовые значения для настроек плагинов
    print(f"\n{BOLD}Готово! Впишите это в настройки плагина:{RESET}\n")
    print(f"  Python (pythonPath):  {BOLD}{python}{RESET}")
    print(f"  Путь к cli.py:        {BOLD}{cli}{RESET}\n")

    # сохраняем конфиг рядом
    config = {"pythonPath": python, "cliPath": str(cli)}
    config_path = cli.parent / "nexus-config.json"
    try:
        config_path.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
        ok(f"Конфиг сохранён: {config_path}")
    except Exception as e:  # noqa: BLE001
        warn(f"Не удалось сохранить конфиг ({e}) — впишите пути вручную.")

    print(f"\n{BOLD}Дальше:{RESET}")
    print("  VS Code:  Settings → Nexus Security → вставьте пути выше")
    print("  IntelliJ: Settings → Tools → Nexus Security → вставьте пути выше\n")

    _install_global_command(cli, python)
    return 0


def _install_global_command(cli, python: str) -> None:
    """Создаёт глобальную команду `nexus`, доступную из любой папки."""
    import stat
    try:
        # выбираем папку в PATH, доступную для записи без sudo
        home = Path.home()
        candidates = [home / ".local" / "bin", home / "bin"]
        target_dir = next((d for d in candidates if str(d) in os.environ.get("PATH", "")), None)

        if os.name == "nt":
            # Windows: создаём nexus.bat в папке Scripts пользователя
            scripts = Path(sys.prefix) / "Scripts"
            if scripts.is_dir():
                bat = scripts / "nexus.bat"
                bat.write_text(f'@echo off\n"{python}" "{cli}" %*\n', encoding="utf-8")
                ok(f"Команда nexus создана: {bat}")
                return
        else:
            if target_dir is None:
                target_dir = home / ".local" / "bin"
            target_dir.mkdir(parents=True, exist_ok=True)
            launcher = target_dir / "nexus"
            launcher.write_text(f'#!/usr/bin/env bash\nexec "{python}" "{cli}" "$@"\n', encoding="utf-8")
            launcher.chmod(launcher.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
            if str(target_dir) in os.environ.get("PATH", ""):
                ok(f"Команда `nexus` создана — работает из любой папки")
            else:
                warn(f"Команда создана в {target_dir}, но её нет в PATH.")
                print(f"     Добавьте в ~/.bashrc:  export PATH=\"{target_dir}:$PATH\"")
            return
    except Exception as e:  # noqa: BLE001
        warn(f"Не удалось создать глобальную команду ({e}). Запускайте через python3 cli.py.")


def _unused():
    return 0


if __name__ == "__main__":
    sys.exit(main())
