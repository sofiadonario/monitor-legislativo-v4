# DATASET LEXML INDIVIDUAL COM LOCALIZAÇÃO

## 📋 DESCRIÇÃO

Este ZIP contém todos os arquivos individuais do dataset LexML com informações de localização extraídas (país, estado, município).

## 📦 CONTEÚDO DO ZIP

**21 arquivos CSV** organizados por **categoria** e **modal de transporte**:

### 📊 POR CATEGORIA:

#### 🔵 DOUTRINA (4 arquivos):
- `lexml_doutrina_geral_20250722_102507_com_localizacao.csv` (10.124 registros)
- `lexml_doutrina_rodoviário_20250722_102507_com_localizacao.csv` (1.846 registros)
- `lexml_doutrina_marítimo_20250722_102507_com_localizacao.csv` (602 registros)
- `lexml_doutrina_aéreo_20250722_102507_com_localizacao.csv` (238 registros)

#### 🔴 JURISPRUDÊNCIA (4 arquivos):
- `lexml_jurisprudência_geral_20250722_102507_com_localizacao.csv` (26.981 registros)
- `lexml_jurisprudência_rodoviário_20250722_102507_com_localizacao.csv` (25.794 registros)
- `lexml_jurisprudência_marítimo_20250722_102507_com_localizacao.csv` (810 registros)
- `lexml_jurisprudência_aéreo_20250722_102507_com_localizacao.csv` (1.032 registros)

#### 🟢 LEGISLAÇÃO (4 arquivos):
- `lexml_legislação_geral_20250722_102507_com_localizacao.csv` (37.218 registros)
- `lexml_legislação_rodoviário_20250722_102507_com_localizacao.csv` (11.706 registros)
- `lexml_legislação_marítimo_20250722_102507_com_localizacao.csv` (1.618 registros)
- `lexml_legislação_aéreo_20250722_102507_com_localizacao.csv` (544 registros)

#### 🟡 OUTROS (4 arquivos):
- `lexml_outros_geral_20250722_102507_com_localizacao.csv` (7.097 registros)
- `lexml_outros_rodoviário_20250722_102507_com_localizacao.csv` (5.981 registros)
- `lexml_outros_marítimo_20250722_102507_com_localizacao.csv` (526 registros)
- `lexml_outros_aéreo_20250722_102507_com_localizacao.csv` (246 registros)

#### 🟣 PROPOSIÇÕES (4 arquivos):
- `lexml_proposições_geral_20250722_102507_com_localizacao.csv` (877 registros)
- `lexml_proposições_rodoviário_20250722_102507_com_localizacao.csv` (747 registros)
- `lexml_proposições_marítimo_20250722_102507_com_localizacao.csv` (13 registros)
- `lexml_proposições_aéreo_20250722_102507_com_localizacao.csv` (14 registros)

#### 📊 DATASET PRINCIPAL:
- `lexml_dataset_limpo_classificado_20250722_102507_com_localizacao.csv` (134.014 registros)

## 🎯 NOVAS COLUNAS ADICIONADAS

Todos os arquivos contêm as seguintes colunas adicionais:

- **`pais`** - País identificado (ex: "Brasil")
- **`estado`** - Estado/UF ou "Federal" (ex: "SP", "Federal", "DF")
- **`municipio`** - Município identificado (ex: "Brasília")
- **`fontes_localizacao`** - Fontes utilizadas na extração (debug)

## 📈 ESTATÍSTICAS GERAIS

### Por País:
- 🇧🇷 **Brasil:** 97.5% dos registros

### Por Estado (Top 10):
- 🏛️ **Federal:** 70.7%
- 🏙️ **São Paulo (SP):** 6.1%
- ⛰️ **Minas Gerais (MG):** 5.0%
- 🏛️ **Distrito Federal (DF):** 2.2%
- 🌊 **Santa Catarina (SC):** 0.4%

### Por Modal:
- 🔵 **Geral:** 61.4%
- 🟢 **Rodoviário:** 34.4%
- 🔴 **Marítimo:** 2.7%
- 🟡 **Aéreo:** 1.5%

## 🔍 FONTES DE LOCALIZAÇÃO

As informações de localização foram extraídas de:

1. **URN (Uniform Resource Name)** - 62.7%
2. **Jurisdição** - 20.0%
3. **Assuntos/Classificação** - 17.3%

## 💻 COMO USAR

### Abrir arquivos individuais:
```python
import pandas as pd

# Exemplo: Carregar jurisprudência rodoviária
df = pd.read_csv('lexml_jurisprudência_rodoviário_20250722_102507_com_localizacao.csv')

# Filtrar por estado
df_sp = df[df['estado'] == 'SP']

# Filtrar por país
df_brasil = df[df['pais'] == 'Brasil']
```

### Análise por localização:
```python
# Contar registros por estado
print(df['estado'].value_counts())

# Contar registros por país
print(df['pais'].value_counts())

# Verificar fontes de localização
print(df['fontes_localizacao'].value_counts())
```

## 📊 QUALIDADE DOS DADOS

✅ **97.5%** dos registros têm país identificado
✅ **84.9%** dos registros têm estado/jurisdição identificada
✅ **Múltiplas fontes** utilizadas para máxima cobertura
✅ **Dados limpos** e normalizados
✅ **Sem duplicatas** entre arquivos

## 🎯 ADEQUAÇÃO AO PROJETO

Os dados foram filtrados e classificados especificamente para o projeto de pesquisa:
- **"Governança das Políticas Públicas de transporte: infraestrutura, tecnologia e eletrificação"**
- Foco em **descarbonização** e **sustentabilidade**
- Cobertura de **todos os modais** de transporte
- Período: **1829-2025** (196 anos de dados)

## 📝 OBSERVAÇÕES

- **Encoding:** UTF-8 (compatível com acentos)
- **Separador:** Vírgula (,)
- **Formato de data:** YYYY-MM-DD
- **Valores vazios:** Representados como strings vazias ou "nan"

## 🔧 REQUISITOS TÉCNICOS

- **Python 3.7+** com pandas
- **Excel 2016+** ou LibreOffice Calc
- **Memória:** 4GB+ recomendado para arquivos grandes
- **Espaço:** 400MB descomprimido

## 📞 SUPORTE

Dataset criado especificamente para análise de políticas públicas de transporte no Brasil.

**Características únicas:**
- ✅ Localização extraída de múltiplas fontes
- ✅ Classificação por modal de transporte
- ✅ Foco em sustentabilidade e descarbonização
- ✅ Dados históricos de quase 200 anos

**Versão:** 3.0
**Data:** 23/07/2025
**Total de registros:** 134.014 únicos

