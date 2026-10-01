@echo off
rem 双击启动 ipk_repack_gui.py（优先用无控制台的 pythonw，失败则退回 python）
cd /d "%~dp0"
where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw -X utf8 "%~dp0ipk_repack_gui.py"
) else (
    python -X utf8 "%~dp0ipk_repack_gui.py"
)
