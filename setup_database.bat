@echo off
REM Database Setup Script for Monitor Legislativo v4 (Windows)
REM This script helps configure AsyncPG and SQLAlchemy for Supabase integration

echo ==================================================
echo Monitor Legislativo v4 - Database Setup Assistant
echo ==================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from python.org
    pause
    exit /b 1
)

echo Python found: 
python --version
echo.

REM Check if pip is installed
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: pip is not installed
    echo Please ensure pip is installed with Python
    pause
    exit /b 1
)

echo pip found
echo.

REM Check if .env file exists
if not exist .env (
    echo WARNING: No .env file found.
    echo Creating .env from .env.example...
    
    if exist .env.example (
        copy .env.example .env
        echo Created .env file
        echo.
        echo IMPORTANT: Edit .env file with your database credentials!
        echo Required: DATABASE_URL, SUPABASE_URL, SUPABASE_ANON_KEY
        echo.
        pause
    ) else (
        echo ERROR: No .env.example file found
        pause
        exit /b 1
    )
) else (
    echo .env file found
)

echo.
echo Installing required dependencies...
echo.

REM Install dependencies
pip install sqlalchemy[asyncio]==2.0.23 asyncpg==0.29.0 python-dotenv==1.0.0

if %errorlevel% equ 0 (
    echo.
    echo Dependencies installed successfully!
) else (
    echo.
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo Testing database connection...
echo.

REM Run connection test
python test_database.py

if %errorlevel% equ 0 (
    echo.
    echo Database connection successful!
    
    echo.
    set /p INIT="Would you like to initialize the database schema? (y/n): "
    
    if /i "%INIT%"=="y" (
        echo.
        echo Initializing database...
        python initialize_database.py
    )
) else (
    echo.
    echo ERROR: Database connection failed
    echo.
    echo Please check:
    echo 1. Your .env file has correct DATABASE_URL
    echo 2. Your Supabase project is active
    echo 3. Network connection to Supabase
    pause
    exit /b 1
)

echo.
echo ==================================================
echo Setup complete!
echo ==================================================
echo.
echo Next steps:
echo 1. Start the backend: python main_app\main.py
echo 2. Start the frontend: npm run dev
echo 3. Check health: http://localhost:8000/api/lexml/health
echo.
echo For Railway deployment:
echo 1. Set environment variables in Railway dashboard
echo 2. Push code: git push origin main
echo 3. Monitor logs for database initialization
echo.
pause