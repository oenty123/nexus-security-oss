# PyInstaller spec — сборка автономного бинарника `nexus` без зависимости от Python.
#
# Зачем: чтобы конечный пользователь мог запускать Nexus, НЕ устанавливая Python.
# Бинарник платформо-зависим — соберите отдельно под каждую ОС (Windows/macOS/Linux).
#
# Установка PyInstaller:   pip install pyinstaller
# Сборка:                  pyinstaller nexus.spec
# Результат:               dist/nexus  (или dist/nexus.exe на Windows)
#
# Затем этот один файл можно раздавать — Python пользователю не нужен.

block_cipher = None

a = Analysis(
    ['cli.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    # модули движка, которые подтягиваются динамически — указываем явно
    hiddenimports=[
        'engine', 'engine_ast', 'engine_taint', 'engine_dataflow',
        'rules_security', 'compliance', 'sarif_exporter', 'suppression',
        'refactor_pro', 'readability_doc', 'explain',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz, a.scripts, a.binaries, a.zipfiles, a.datas,
    name='nexus',
    debug=False,
    strip=False,
    upx=True,        # сжатие (если установлен upx)
    console=True,    # CLI-приложение
)
