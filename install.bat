@echo off
REM Nexus Security - установка (Windows). Запуск: двойной клик
where python >nul 2>nul && (python install.py & pause & exit /b)
where py >nul 2>nul && (py install.py & pause & exit /b)
echo Python 3 ne nayden. Ustanovite s https://python.org
pause
