@echo off
REM ═══════════════════════════════════════════════════════════════════
REM  PatientIDS GUI — One-Shot Build Script for Windows
REM  Run this in the folder containing ids_gui.py and ids_gui.spec
REM ═══════════════════════════════════════════════════════════════════

echo.
echo  ╔══════════════════════════════════════════════╗
echo  ║   Patient IDS GUI — Windows EXE Builder      ║
echo  ╚══════════════════════════════════════════════╝
echo.

REM ── Step 1: Install all required packages ────────────────────────────
echo [1/3] Installing Python dependencies...
pip install ^
    paho-mqtt ^
    joblib ^
    scikit-learn ^
    numpy ^
    pandas ^
    psutil ^
    reportlab ^
    pyinstaller

if %errorlevel% neq 0 (
    echo ERROR: pip install failed. Make sure Python is in your PATH.
    pause
    exit /b 1
)

echo.
echo [2/3] Cleaning previous build artefacts...
if exist "build"  rmdir /s /q "build"
if exist "dist"   rmdir /s /q "dist"
if exist "PatientIDS.exe" del /f "PatientIDS.exe"

echo.
echo [3/3] Building standalone EXE with PyInstaller...
pyinstaller ids_gui.spec

if %errorlevel% neq 0 (
    echo.
    echo ERROR: PyInstaller build failed. Check output above.
    pause
    exit /b 1
)

REM ── Copy EXE to current directory for convenience ────────────────────
copy /y "dist\PatientIDS.exe" "PatientIDS.exe" >nul 2>&1

echo.
echo  ════════════════════════════════════════════════
echo   BUILD SUCCESSFUL
echo   EXE location: dist\PatientIDS.exe
echo                 PatientIDS.exe  (copy in this folder)
echo  ════════════════════════════════════════════════
echo.
echo  Before running PatientIDS.exe, make sure:
echo    1. Your MQTT broker is running on the Windows VM
echo    2. You have run train_isolation_forest.py to generate:
echo         patient_ids_model.pkl
echo         patient_ids_scaler.pkl
echo         patient_ids_meta.json
echo    3. The model paths in Settings match your actual file locations
echo.
pause
