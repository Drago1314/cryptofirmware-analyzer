@echo off
title CryptoFirmware Analyzer - Auto Setup
color 0A
cls

echo.
echo  ============================================
echo   CryptoFirmware Analyzer - Auto Setup
echo  ============================================
echo.

:: ── Check Python ─────────────────────────────
echo [1/4] Checking Python...
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    color 0C
    echo.
    echo  ERROR: Python not found!
    echo  Please install Python from https://python.org
    echo  Make sure to check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)
python --version
echo  Python found!
echo.

:: ── Install dependencies ─────────────────────
echo [2/4] Installing dependencies (this may take a minute)...
echo.
python -m pip install --upgrade pip -q
python -m pip install streamlit scikit-learn plotly pycryptodome joblib numpy pandas -q

IF %ERRORLEVEL% NEQ 0 (
    color 0C
    echo.
    echo  ERROR: Failed to install dependencies.
    echo  Check your internet connection and try again.
    echo.
    pause
    exit /b 1
)
echo  All dependencies installed!
echo.

:: ── Generate test binary ─────────────────────
echo [3/4] Generating test firmware binary...
python generate_test_binary.py

IF %ERRORLEVEL% NEQ 0 (
    echo  Warning: Could not generate test binary. App will still work.
) ELSE (
    echo  test_firmware.elf created successfully!
)
echo.

:: ── Launch app ───────────────────────────────
echo [4/4] Launching CryptoFirmware Analyzer...
echo.
echo  ============================================
echo   App running at: http://localhost:8501
echo   Opening browser automatically...
echo   Press Ctrl+C in this window to stop.
echo  ============================================
echo.

:: Open browser after 3 seconds (fixed: runs in background properly)
start "" /b cmd /c "timeout /t 3 /nobreak >nul & start http://localhost:8501"

:: Run streamlit
python -m streamlit run app.py --server.port 8501 --browser.gatherUsageStats false

pause
