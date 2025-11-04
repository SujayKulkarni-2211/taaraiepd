@echo off
echo ========================================
echo    TAARA - DevSecOps Control Plane
echo ========================================
echo.
echo Starting Taara application...
echo.

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Run Streamlit
streamlit run main.py

pause
