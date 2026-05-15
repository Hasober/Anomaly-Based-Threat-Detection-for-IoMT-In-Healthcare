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

for /f "tokens=*" %%i in ('python -c "import sys; print(sys.executable)"') do set PYTHON_EXE=%%i
echo     Python : %PYTHON_EXE%

REM ── Step 2: Install ALL required packages including scipy ─────────────
echo.
echo [2/4] Installing Python dependencies (including scipy)...
python -m pip install --upgrade pip --quiet
python -m pip install ^
    scipy ^
    paho-mqtt ^
    joblib ^
    scikit-learn ^
    numpy ^
    pandas ^
    psutil ^
    reportlab ^
    pyinstaller

if %errorlevel% neq 0 (
    echo ERROR: pip install failed. Check your internet connection.
    pause
    exit /b 1
)

REM Confirm scipy installed correctly
python -c "import scipy; print('    scipy version:', scipy.__version__)"
if %errorlevel% neq 0 (
    echo ERROR: scipy failed to import after install. Try: python -m pip install scipy --force-reinstall
    pause
    exit /b 1
)

REM ── Step 3: Clean previous artefacts ─────────────────────────────────
echo.
echo [3/4] Cleaning previous build artefacts...
if exist "build"          rmdir /s /q "build"
if exist "dist"           rmdir /s /q "dist"
if exist "PatientIDS.exe" del /f /q "PatientIDS.exe"

REM ── Step 4: Build EXE ────────────────────────────────────────────────
echo.
echo [4/4] Building standalone EXE (this takes 1-3 minutes)...
python -m PyInstaller --clean ids_gui.spec

if %errorlevel% neq 0 (
    echo.
    echo ════════════════════════════════════════════════
    echo  BUILD FAILED — Troubleshooting steps:
    echo ════════════════════════════════════════════════
    echo  1. Run this .bat as Administrator
    echo  2. Disable antivirus temporarily (it blocks PyInstaller)
    echo  3. Check ids_gui.py and ids_gui.spec are in THIS folder
    echo  4. Manually run: python -m PyInstaller --clean ids_gui.spec
    pause
    exit /b 1
)

copy /y "dist\PatientIDS.exe" "PatientIDS.exe" >nul 2>&1

echo.
echo  ════════════════════════════════════════════════
echo   BUILD SUCCESSFUL
echo   EXE location : dist\PatientIDS.exe
echo   Quick copy   : PatientIDS.exe  (this folder)
echo  ════════════════════════════════════════════════
echo.
echo  Before running PatientIDS.exe:
echo    1. MQTT broker must be running on your Windows VM
echo    2. Run train_isolation_forest.py to generate the 3 model files
echo    3. Open Settings in the GUI to confirm file paths
echo.
pause
