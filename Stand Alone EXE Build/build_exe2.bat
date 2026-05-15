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

REM ── Step 1: Verify Python is reachable ───────────────────────────────
echo [1/4] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: 'python' not found. Add Python to PATH and retry.
    echo        Usually found at:
    echo        C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python3xx\
    pause
    exit /b 1
)

REM Show exactly which python and Scripts folder are in use
for /f "tokens=*" %%i in ('python -c "import sys; print(sys.executable)"') do set PYTHON_EXE=%%i
for /f "tokens=*" %%i in ('python -c "import sys,os; print(os.path.join(os.path.dirname(sys.executable),'Scripts'))"') do set SCRIPTS_DIR=%%i
echo     Python  : %PYTHON_EXE%
echo     Scripts : %SCRIPTS_DIR%

REM ── Step 2: Install / upgrade all required packages ──────────────────
echo.
echo [2/4] Installing Python dependencies...
python -m pip install --upgrade pip --quiet
python -m pip install paho-mqtt joblib scikit-learn numpy pandas psutil reportlab pyinstaller

if %errorlevel% neq 0 (
    echo ERROR: pip install failed. Check your internet connection.
    pause
    exit /b 1
)

REM ── Step 3: Clean previous artefacts ─────────────────────────────────
echo.
echo [3/4] Cleaning previous build artefacts...
if exist "build"        rmdir /s /q "build"
if exist "dist"         rmdir /s /q "dist"
if exist "PatientIDS.exe" del /f /q "PatientIDS.exe"

REM ── Step 4: Build EXE via python -m PyInstaller ──────────────────────
REM   Using "python -m PyInstaller" bypasses the PATH issue entirely —
REM   it always uses the PyInstaller from the same Python that pip installed it.
echo.
echo [4/4] Building standalone EXE (this takes 1-3 minutes)...
python -m PyInstaller ids_gui.spec

if %errorlevel% neq 0 (
    echo.
    echo ════════════════════════════════════════════════
    echo  BUILD FAILED
    echo ════════════════════════════════════════════════
    echo  Common fixes:
    echo    1. Run this .bat as Administrator
    echo    2. Temporarily disable antivirus (it blocks PyInstaller)
    echo    3. Make sure ids_gui.py and ids_gui.spec are in THIS folder
    echo    4. Try:  python -m PyInstaller --clean ids_gui.spec
    pause
    exit /b 1
)

REM ── Copy EXE to current folder for easy access ───────────────────────
copy /y "dist\PatientIDS.exe" "PatientIDS.exe" >nul 2>&1

echo.
echo  ════════════════════════════════════════════════
echo   BUILD SUCCESSFUL
echo   EXE location : dist\PatientIDS.exe
echo   Quick copy   : PatientIDS.exe  (this folder)
echo  ════════════════════════════════════════════════
echo.
echo  Before running PatientIDS.exe, make sure:
echo    1. MQTT broker is running on your Windows VM
echo    2. train_isolation_forest.py has been run to generate:
echo         patient_ids_model.pkl
echo         patient_ids_scaler.pkl
echo         patient_ids_meta.json
echo    3. Open Settings in the GUI and confirm all file paths
echo.
pause