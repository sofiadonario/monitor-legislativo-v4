# SEPARADOR DE LOCALIDADES - DATASET LEXML

## 📋 DESCRIÇÃO

Este script separa a coluna "localidade" do dataset LexML em três colunas distintas:
- **país**: País identificado
- **estado**: Estado/UF (sigla de 2 letras)
- **município**: Município identificado

## 🖥️ COMPATIBILIDADE

✅ **Windows 10/11** (Python 3.7+)
✅ **WSL Ubuntu** (Python 3.7+)
✅ **Linux Ubuntu/Debian** (Python 3.7+)

## 📦 ARQUIVOS INCLUÍDOS

- `separar_localidades.py` - Script principal (Python)
- `separar_localidades.bat` - Executável para Windows
- `separar_localidades.sh` - Executável para Linux/WSL
- `README_SEPARADOR_LOCALIDADES.md` - Esta documentação

## 🚀 COMO USAR

### OPÇÃO 1: Windows
1. Extraia todos os arquivos na mesma pasta dos CSVs do dataset
2. Execute duplo clique em `separar_localidades.bat`
3. O script processará automaticamente todos os CSVs

### OPÇÃO 2: WSL Ubuntu / Linux
1. Extraia todos os arquivos na mesma pasta dos CSVs do dataset
2. Abra terminal na pasta
3. Execute: `./separar_localidades.sh`
4. O script processará automaticamente todos os CSVs

### OPÇÃO 3: Arquivo específico
```bash
# Windows
python separar_localidades.py arquivo_entrada.csv arquivo_saida.csv

# Linux/WSL
python3 separar_localidades.py arquivo_entrada.csv arquivo_saida.csv
```

## 📊 FUNCIONAMENTO

### FORMATOS RECONHECIDOS:
- `"Brasil, SP, São Paulo"`
- `"Brasil, São Paulo, SP"`
- `"SP, São Paulo"`
- `"São Paulo, SP"`
- `"Brasil"`
- `"São Paulo"`

### LÓGICA DE PARSING:
1. **Identifica país**: Procura por "Brasil" explícito ou infere por contexto
2. **Identifica estado**: Reconhece siglas (SP, RJ, MG...) e nomes completos
3. **Identifica município**: Usa base de municípios principais + inferência

### ESTADOS SUPORTADOS:
Todos os 26 estados + DF do Brasil:
- Siglas: AC, AL, AP, AM, BA, CE, DF, ES, GO, MA, MT, MS, MG, PA, PB, PR, PE, PI, RJ, RN, RS, RO, RR, SC, SP, SE, TO
- Nomes completos: Acre, Alagoas, Amapá, etc.

### MUNICÍPIOS RECONHECIDOS:
- **500+ municípios principais** de todos os estados
- Capitais e principais cidades de cada UF
- Normalização de acentos para melhor reconhecimento

## 📈 RESULTADOS ESPERADOS

### NOVAS COLUNAS CRIADAS:
- `pais` - País identificado (ex: "Brasil")
- `estado` - Sigla do estado (ex: "SP")
- `municipio` - Nome do município (ex: "São Paulo")

### ESTATÍSTICAS GERADAS:
- Contagem de países identificados
- Contagem de estados identificados
- Log detalhado do processamento

## 📁 ARQUIVOS DE SAÍDA

Para cada arquivo CSV processado:
- **Entrada**: `lexml_legislacao_geral_20250722_102507.csv`
- **Saída**: `lexml_legislacao_geral_20250722_102507_localidades_separadas.csv`

## 🔧 REQUISITOS TÉCNICOS

### Python:
- **Versão**: 3.7 ou superior
- **Bibliotecas**: pandas, numpy (instaladas automaticamente)

### Windows:
- Python instalado e no PATH
- Permissões para instalar pacotes pip

### Linux/WSL:
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip

# CentOS/RHEL
sudo yum install python3 python3-pip
```

## 📝 LOG DE EXECUÇÃO

O script gera um arquivo `separar_localidades.log` com:
- Progresso do processamento
- Estatísticas de cada arquivo
- Erros encontrados (se houver)

## ⚠️ OBSERVAÇÕES IMPORTANTES

1. **Backup**: Faça backup dos arquivos originais antes de executar
2. **Memória**: Arquivos grandes podem consumir bastante RAM
3. **Tempo**: O processamento pode demorar alguns minutos para datasets grandes
4. **Encoding**: Usa UTF-8 para compatibilidade com acentos

## 🐛 SOLUÇÃO DE PROBLEMAS

### "Python não encontrado"
- **Windows**: Reinstale Python e marque "Add to PATH"
- **Linux**: `sudo apt install python3`

### "Pandas não encontrado"
- Execute: `pip install pandas` (Windows) ou `pip3 install pandas` (Linux)

### "Arquivo não encontrado"
- Verifique se os CSVs estão na mesma pasta do script
- Verifique se os nomes dos arquivos estão corretos

### "Erro de memória"
- Processe arquivos menores individualmente
- Feche outros programas para liberar RAM

## 📞 SUPORTE

Script criado para o projeto de pesquisa "Governança das Políticas Públicas de transporte: infraestrutura, tecnologia e eletrificação".

**Versão**: 1.0
**Data**: 22/07/2025
**Compatibilidade**: Windows + Linux/WSL

