#!/usr/bin/env python3
"""
Teste manual do separador de localidades
"""

import pandas as pd
import sys
sys.path.append('.')
from separar_localidades import parse_localidade

# Testes manuais
testes = [
    "Brasil, SP, São Paulo",
    "Brasil, São Paulo, SP", 
    "SP, São Paulo",
    "São Paulo, SP",
    "Brasil",
    "São Paulo",
    "RJ, Rio de Janeiro",
    "Federal",
    "Estadual",
    "Municipal",
    "",
    "Brasília, DF",
    "DF, Brasília"
]

print("=== TESTE MANUAL DO SEPARADOR DE LOCALIDADES ===\n")

for teste in testes:
    resultado = parse_localidade(teste)
    print(f"Entrada: '{teste}'")
    print(f"  País: '{resultado['pais']}'")
    print(f"  Estado: '{resultado['estado']}'")
    print(f"  Município: '{resultado['municipio']}'")
    print()

# Teste com dados reais do CSV
print("=== TESTE COM DADOS REAIS ===\n")

# Cria um pequeno dataset de teste
dados_teste = {
    'titulo': ['Teste 1', 'Teste 2', 'Teste 3'],
    'localidade': ['Federal', 'SP, São Paulo', 'Brasil, RJ, Rio de Janeiro']
}

df_teste = pd.DataFrame(dados_teste)
print("Dataset de teste:")
print(df_teste)
print()

# Aplica a função
localidades_parsed = df_teste['localidade'].apply(parse_localidade)

# Cria novas colunas
df_teste['pais'] = [loc['pais'] for loc in localidades_parsed]
df_teste['estado'] = [loc['estado'] for loc in localidades_parsed]
df_teste['municipio'] = [loc['municipio'] for loc in localidades_parsed]

print("Resultado após separação:")
print(df_teste[['localidade', 'pais', 'estado', 'municipio']])

