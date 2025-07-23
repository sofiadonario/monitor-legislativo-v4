#!/bin/bash
# Script para executar o separador de localidades no Linux/WSL
# Autor: Assistente Manus
# Data: 22/07/2025

echo "========================================"
echo "SEPARADOR DE LOCALIDADES - DATASET LEXML"
echo "========================================"
echo

# Verifica se Python está instalado
if ! command -v python3 &> /dev/null; then
    echo "ERRO: Python3 não encontrado!"
    echo "Por favor, instale Python 3.7+ usando:"
    echo "  Ubuntu/Debian: sudo apt update && sudo apt install python3 python3-pip"
    echo "  CentOS/RHEL: sudo yum install python3 python3-pip"
    exit 1
fi

# Verifica se pandas está instalado
python3 -c "import pandas" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Instalando pandas..."
    pip3 install pandas
    if [ $? -ne 0 ]; then
        echo "ERRO: Falha ao instalar pandas"
        echo "Tente: sudo pip3 install pandas"
        exit 1
    fi
fi

echo "Executando separador de localidades..."
echo

# Executa o script Python
python3 separar_localidades.py

echo
echo "Processamento concluído!"
echo "Verifique os arquivos *_localidades_separadas.csv gerados"
echo

