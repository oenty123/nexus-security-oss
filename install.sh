#!/usr/bin/env bash
# Nexus Security — установка (Linux/macOS). Запуск: ./install.sh
if command -v python3 >/dev/null 2>&1; then python3 install.py
elif command -v python >/dev/null 2>&1; then python install.py
else echo "Python 3 не найден. Установите с https://python.org"; exit 1; fi
