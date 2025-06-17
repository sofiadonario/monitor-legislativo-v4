@echo off
echo ===================================================
echo    ACADEMIC LEGISLATIVE MONITOR - DEPLOYMENT
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

echo Starting deployment script...
echo.

REM Run the deployment script
Rscript deploy.R

pause