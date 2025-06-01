@echo off
REM Academic Legislative Monitor - Windows Setup Script
REM This batch file sets up and runs the R Shiny application on Windows

echo.
echo ==================================================
echo    MONITOR LEGISLATIVO ACADEMICO                 
echo    Windows Setup and Run Script                  
echo ==================================================
echo.

REM Check if R is installed
where R >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: R is not installed or not in PATH
    echo.
    echo Please install R from: https://cloud.r-project.org/
    echo After installation, add R to your system PATH
    echo.
    pause
    exit /b 1
)

REM Check if Rscript is available
where Rscript >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: Rscript is not found in PATH
    echo.
    echo Please ensure R is properly installed and added to PATH
    echo.
    pause
    exit /b 1
)

echo [OK] R is installed and available
echo.

REM Run the setup script
echo Starting R Shiny setup...
echo This may take several minutes on first run...
echo.

Rscript setup_and_run.R

REM Check if the script ran successfully
if %errorlevel% neq 0 (
    echo.
    echo ERROR: Setup script failed
    echo Please check the error messages above
    echo.
    pause
    exit /b 1
)

echo.
echo Application closed successfully
echo.
pause