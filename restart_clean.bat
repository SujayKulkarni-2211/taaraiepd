@echo off
echo ========================================
echo   TAARA - Clean Restart
echo ========================================
echo.
echo Stopping all Streamlit processes...
taskkill /F /IM streamlit.exe /T 2>nul
timeout /t 2 /nobreak >nul

echo Cleaning up...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq *streamlit*" /T 2>nul
timeout /t 2 /nobreak >nul

echo.
echo All processes stopped.
echo.
echo Starting Taara...
echo.

call venv\Scripts\activate.bat
streamlit run main.py

pause
