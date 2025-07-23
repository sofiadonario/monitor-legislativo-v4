@echo off
REM Script para executar o separador de localidades no Windows
REM Autor: Assistente Manus
REM Data: 22/07/2025

echo ========================================
echo SEPARADOR DE LOCALIDADES - DATASET LEXML
echo ========================================
echo.

REM Verifica se Python está instalado
python --version >nul 2>&1
if errorlevel 1 (
    echo ERRO: Python não encontrado!
    echo Por favor, instale Python 3.7+ e adicione ao PATH
    pause
    exit /b 1
)

REM Verifica se pandas está instalado
python -c "import pandas" >nul 2>&1
if errorlevel 1 (
    echo Instalando pandas...
    pip install pandas
    if errorlevel 1 (
        echo ERRO: Falha ao instalar pandas
        pause
        exit /b 1
    )
)

echo Executando separador de localidades...
echo.

REM Executa o script Python
python separar_localidades.py

echo.
echo Processamento concluído!
echo Verifique os arquivos *_localidades_separadas.csv gerados
echo.
pause

