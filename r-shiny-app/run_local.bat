@echo off
echo ===================================================
echo    ACADEMIC LEGISLATIVE MONITOR - LOCAL TEST
echo ===================================================
echo.

REM Check if R is installed
where R >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: R is not installed or not in PATH
    echo Please install R from https://cran.r-project.org/
    pause
    exit /b 1
)

echo Starting local test server...
echo.
echo The application will open in your browser at:
echo http://localhost:3838
echo.
echo Login credentials:
echo   Admin:      admin / admin123
echo   Researcher: researcher / research123
echo   Student:    student / student123
echo.
echo Press Ctrl+C to stop the server
echo.

REM Run the local test script
Rscript run_local.R

pause