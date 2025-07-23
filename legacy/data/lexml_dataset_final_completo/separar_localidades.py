#!/usr/bin/env python3
"""
Script para separar a coluna "localidade" em "país", "estado" e "município"
Compatível com Windows e WSL Ubuntu

Autor: Assistente Manus
Data: 22/07/2025
Versão: 1.0
"""

import pandas as pd
import numpy as np
import re
import os
import sys
from datetime import datetime
import logging

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('separar_localidades.log'),
        logging.StreamHandler()
    ]
)

def detect_platform():
    """Detecta a plataforma (Windows ou Linux/WSL)"""
    if os.name == 'nt':
        return 'Windows'
    else:
        return 'Linux/WSL'

def normalize_text(text):
    """Normaliza texto removendo acentos e caracteres especiais"""
    if pd.isna(text) or text == '':
        return ''
    
    text = str(text).strip()
    
    # Mapeamento de caracteres acentuados
    replacements = {
        'á': 'a', 'à': 'a', 'ã': 'a', 'â': 'a', 'ä': 'a',
        'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e',
        'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i',
        'ó': 'o', 'ò': 'o', 'õ': 'o', 'ô': 'o', 'ö': 'o',
        'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u',
        'ç': 'c', 'ñ': 'n',
        'Á': 'A', 'À': 'A', 'Ã': 'A', 'Â': 'A', 'Ä': 'A',
        'É': 'E', 'È': 'E', 'Ê': 'E', 'Ë': 'E',
        'Í': 'I', 'Ì': 'I', 'Î': 'I', 'Ï': 'I',
        'Ó': 'O', 'Ò': 'O', 'Õ': 'O', 'Ô': 'O', 'Ö': 'O',
        'Ú': 'U', 'Ù': 'U', 'Û': 'U', 'Ü': 'U',
        'Ç': 'C', 'Ñ': 'N'
    }
    
    for old, new in replacements.items():
        text = text.replace(old, new)
    
    return text

def load_brazilian_locations():
    """Carrega dicionário de estados e municípios brasileiros"""
    
    # Estados brasileiros (sigla e nome completo)
    estados_brasil = {
        'AC': 'Acre', 'AL': 'Alagoas', 'AP': 'Amapá', 'AM': 'Amazonas',
        'BA': 'Bahia', 'CE': 'Ceará', 'DF': 'Distrito Federal', 'ES': 'Espírito Santo',
        'GO': 'Goiás', 'MA': 'Maranhão', 'MT': 'Mato Grosso', 'MS': 'Mato Grosso do Sul',
        'MG': 'Minas Gerais', 'PA': 'Pará', 'PB': 'Paraíba', 'PR': 'Paraná',
        'PE': 'Pernambuco', 'PI': 'Piauí', 'RJ': 'Rio de Janeiro', 'RN': 'Rio Grande do Norte',
        'RS': 'Rio Grande do Sul', 'RO': 'Rondônia', 'RR': 'Roraima', 'SC': 'Santa Catarina',
        'SP': 'São Paulo', 'SE': 'Sergipe', 'TO': 'Tocantins'
    }
    
    # Principais municípios por estado (amostra representativa)
    municipios_principais = {
        'SP': ['São Paulo', 'Guarulhos', 'Campinas', 'São Bernardo do Campo', 'Santo André', 
               'Osasco', 'Ribeirão Preto', 'Sorocaba', 'Santos', 'São José dos Campos'],
        'RJ': ['Rio de Janeiro', 'São Gonçalo', 'Duque de Caxias', 'Nova Iguaçu', 'Niterói',
               'Belford Roxo', 'São João de Meriti', 'Campos dos Goytacazes', 'Petrópolis'],
        'MG': ['Belo Horizonte', 'Uberlândia', 'Contagem', 'Juiz de Fora', 'Betim',
               'Montes Claros', 'Ribeirão das Neves', 'Uberaba', 'Governador Valadares'],
        'BA': ['Salvador', 'Feira de Santana', 'Vitória da Conquista', 'Camaçari', 'Juazeiro',
               'Petrolina', 'Lauro de Freitas', 'Itabuna', 'Jequié'],
        'PR': ['Curitiba', 'Londrina', 'Maringá', 'Ponta Grossa', 'Cascavel',
               'São José dos Pinhais', 'Foz do Iguaçu', 'Colombo', 'Guarapuava'],
        'RS': ['Porto Alegre', 'Caxias do Sul', 'Pelotas', 'Canoas', 'Santa Maria',
               'Gravataí', 'Viamão', 'Novo Hamburgo', 'São Leopoldo'],
        'PE': ['Recife', 'Jaboatão dos Guararapes', 'Olinda', 'Caruaru', 'Petrolina',
               'Paulista', 'Cabo de Santo Agostinho', 'Camaragibe', 'Garanhuns'],
        'CE': ['Fortaleza', 'Caucaia', 'Juazeiro do Norte', 'Maracanaú', 'Sobral',
               'Crato', 'Itapipoca', 'Maranguape', 'Iguatu'],
        'PA': ['Belém', 'Ananindeua', 'Santarém', 'Marabá', 'Parauapebas',
               'Castanhal', 'Abaetetuba', 'Cametá', 'Bragança'],
        'SC': ['Florianópolis', 'Joinville', 'Blumenau', 'São José', 'Criciúma',
               'Chapecó', 'Itajaí', 'Lages', 'Palhoça'],
        'GO': ['Goiânia', 'Aparecida de Goiânia', 'Anápolis', 'Rio Verde', 'Luziânia',
               'Águas Lindas de Goiás', 'Valparaíso de Goiás', 'Trindade', 'Formosa'],
        'MA': ['São Luís', 'Imperatriz', 'São José de Ribamar', 'Timon', 'Caxias',
               'Codó', 'Paço do Lumiar', 'Açailândia', 'Bacabal'],
        'PB': ['João Pessoa', 'Campina Grande', 'Santa Rita', 'Patos', 'Bayeux',
               'Sousa', 'Cajazeiras', 'Cabedelo', 'Guarabira'],
        'ES': ['Vila Velha', 'Serra', 'Cariacica', 'Vitória', 'Cachoeiro de Itapemirim',
               'Linhares', 'São Mateus', 'Colatina', 'Guarapari'],
        'AM': ['Manaus', 'Parintins', 'Itacoatiara', 'Manacapuru', 'Coari',
               'Tefé', 'Tabatinga', 'Maués', 'Humaitá'],
        'MT': ['Cuiabá', 'Várzea Grande', 'Rondonópolis', 'Sinop', 'Tangará da Serra',
               'Cáceres', 'Sorriso', 'Lucas do Rio Verde', 'Barra do Garças'],
        'DF': ['Brasília', 'Taguatinga', 'Ceilândia', 'Samambaia', 'Planaltina',
               'Águas Claras', 'Guará', 'Sobradinho', 'Gama'],
        'MS': ['Campo Grande', 'Dourados', 'Três Lagoas', 'Corumbá', 'Ponta Porã',
               'Naviraí', 'Nova Andradina', 'Sidrolândia', 'Maracaju'],
        'RO': ['Porto Velho', 'Ji-Paraná', 'Ariquemes', 'Vilhena', 'Cacoal',
               'Rolim de Moura', 'Guajará-Mirim', 'Jaru', 'Ouro Preto do Oeste'],
        'AC': ['Rio Branco', 'Cruzeiro do Sul', 'Sena Madureira', 'Tarauacá', 'Feijó',
               'Brasileia', 'Plácido de Castro', 'Xapuri', 'Epitaciolândia'],
        'AL': ['Maceió', 'Arapiraca', 'Palmeira dos Índios', 'Rio Largo', 'Penedo',
               'União dos Palmares', 'São Miguel dos Campos', 'Coruripe', 'Delmiro Gouveia'],
        'AP': ['Macapá', 'Santana', 'Laranjal do Jari', 'Oiapoque', 'Mazagão',
               'Porto Grande', 'Tartarugalzinho', 'Vitória do Jari', 'Ferreira Gomes'],
        'PI': ['Teresina', 'Parnaíba', 'Picos', 'Piripiri', 'Floriano',
               'Campo Maior', 'Barras', 'União', 'Altos'],
        'RN': ['Natal', 'Mossoró', 'Parnamirim', 'São Gonçalo do Amarante', 'Macaíba',
               'Ceará-Mirim', 'Caicó', 'Assu', 'Currais Novos'],
        'RR': ['Boa Vista', 'Rorainópolis', 'Caracaraí', 'Alto Alegre', 'Mucajaí',
               'Cantá', 'Normandia', 'Bonfim', 'Pacaraima'],
        'SE': ['Aracaju', 'Nossa Senhora do Socorro', 'Lagarto', 'Itabaiana', 'São Cristóvão',
               'Estância', 'Tobias Barreto', 'Simão Dias', 'Propriá'],
        'TO': ['Palmas', 'Araguaína', 'Gurupi', 'Porto Nacional', 'Paraíso do Tocantins',
               'Colinas do Tocantins', 'Guaraí', 'Tocantinópolis', 'Miracema do Tocantins']
    }
    
    return estados_brasil, municipios_principais

def parse_localidade(localidade_text):
    """
    Analisa o texto da localidade e extrai país, estado e município
    
    Formatos esperados:
    - "Brasil, SP, São Paulo"
    - "Brasil, São Paulo, SP"
    - "SP, São Paulo"
    - "São Paulo, SP"
    - "Brasil"
    - "São Paulo"
    """
    
    if pd.isna(localidade_text) or localidade_text == '':
        return {'pais': '', 'estado': '', 'municipio': ''}
    
    localidade_text = str(localidade_text).strip()
    
    # Carrega dados brasileiros
    estados_brasil, municipios_principais = load_brazilian_locations()
    
    # Normaliza texto para comparação
    localidade_norm = normalize_text(localidade_text.lower())
    
    # Inicializa resultado
    resultado = {'pais': '', 'estado': '', 'municipio': ''}
    
    # Divide por vírgulas
    partes = [parte.strip() for parte in localidade_text.split(',')]
    
    # Se tem "Brasil" explícito
    if any('brasil' in normalize_text(parte.lower()) for parte in partes):
        resultado['pais'] = 'Brasil'
        # Remove "Brasil" das partes
        partes = [parte for parte in partes if 'brasil' not in normalize_text(parte.lower())]
    
    # Se não tem país explícito, mas tem indicadores brasileiros, assume Brasil
    elif any(parte.strip().upper() in estados_brasil.keys() for parte in partes):
        resultado['pais'] = 'Brasil'
    elif any(parte.strip() in estados_brasil.values() for parte in partes):
        resultado['pais'] = 'Brasil'
    
    # Processa partes restantes
    for parte in partes:
        parte_clean = parte.strip()
        parte_upper = parte_clean.upper()
        
        # Verifica se é sigla de estado
        if parte_upper in estados_brasil.keys():
            resultado['estado'] = parte_upper
        
        # Verifica se é nome completo de estado
        elif parte_clean in estados_brasil.values():
            # Encontra a sigla correspondente
            for sigla, nome in estados_brasil.items():
                if nome == parte_clean:
                    resultado['estado'] = sigla
                    break
        
        # Verifica se é município conhecido
        else:
            parte_norm = normalize_text(parte_clean.lower())
            for estado, municipios in municipios_principais.items():
                for municipio in municipios:
                    if normalize_text(municipio.lower()) == parte_norm:
                        resultado['municipio'] = municipio
                        if not resultado['estado']:
                            resultado['estado'] = estado
                        if not resultado['pais']:
                            resultado['pais'] = 'Brasil'
                        break
                if resultado['municipio']:
                    break
            
            # Se não encontrou como município conhecido, mas não é estado, assume como município
            if not resultado['municipio'] and parte_clean not in estados_brasil.values() and parte_upper not in estados_brasil.keys():
                resultado['municipio'] = parte_clean
    
    # Se tem estado brasileiro mas não tem país, assume Brasil
    if resultado['estado'] and not resultado['pais']:
        resultado['pais'] = 'Brasil'
    
    # Se tem município mas não tem estado, tenta inferir
    if resultado['municipio'] and not resultado['estado']:
        municipio_norm = normalize_text(resultado['municipio'].lower())
        for estado, municipios in municipios_principais.items():
            for municipio in municipios:
                if normalize_text(municipio.lower()) == municipio_norm:
                    resultado['estado'] = estado
                    resultado['pais'] = 'Brasil'
                    break
            if resultado['estado']:
                break
    
    return resultado

def process_csv_file(input_file, output_file=None):
    """Processa um arquivo CSV separando as localidades"""
    
    logging.info(f"Processando arquivo: {input_file}")
    
    try:
        # Carrega o CSV
        df = pd.read_csv(input_file, encoding='utf-8')
        logging.info(f"Arquivo carregado: {len(df)} registros")
        
        # Verifica se existe coluna 'localidade'
        if 'localidade' not in df.columns:
            logging.warning("Coluna 'localidade' não encontrada. Colunas disponíveis:")
            logging.warning(f"{list(df.columns)}")
            return False
        
        # Aplica a função de parsing
        logging.info("Separando localidades...")
        localidades_parsed = df['localidade'].apply(parse_localidade)
        
        # Cria novas colunas
        df['pais'] = [loc['pais'] for loc in localidades_parsed]
        df['estado'] = [loc['estado'] for loc in localidades_parsed]
        df['municipio'] = [loc['municipio'] for loc in localidades_parsed]
        
        # Estatísticas
        paises_count = df['pais'].value_counts()
        estados_count = df['estado'].value_counts()
        
        logging.info("Estatísticas de separação:")
        logging.info(f"  Países identificados: {len(paises_count)}")
        for pais, count in paises_count.head(10).items():
            if pais:
                logging.info(f"    {pais}: {count} registros")
        
        logging.info(f"  Estados identificados: {len(estados_count)}")
        for estado, count in estados_count.head(10).items():
            if estado:
                logging.info(f"    {estado}: {count} registros")
        
        # Define arquivo de saída
        if not output_file:
            base_name = os.path.splitext(input_file)[0]
            output_file = f"{base_name}_localidades_separadas.csv"
        
        # Salva resultado
        df.to_csv(output_file, index=False, encoding='utf-8')
        logging.info(f"Arquivo salvo: {output_file}")
        
        return True
        
    except Exception as e:
        logging.error(f"Erro ao processar arquivo: {e}")
        return False

def process_all_csv_files(directory="."):
    """Processa todos os arquivos CSV do dataset"""
    
    logging.info(f"Processando todos os CSVs no diretório: {directory}")
    
    # Lista arquivos CSV do dataset
    csv_files = []
    for file in os.listdir(directory):
        if file.endswith('.csv') and 'lexml_' in file and '20250722_102507' in file:
            csv_files.append(file)
    
    if not csv_files:
        logging.warning("Nenhum arquivo CSV do dataset encontrado")
        return
    
    logging.info(f"Encontrados {len(csv_files)} arquivos CSV para processar")
    
    # Processa cada arquivo
    sucessos = 0
    for csv_file in csv_files:
        logging.info(f"\n--- Processando: {csv_file} ---")
        if process_csv_file(csv_file):
            sucessos += 1
        else:
            logging.error(f"Falha ao processar: {csv_file}")
    
    logging.info(f"\n=== PROCESSAMENTO CONCLUÍDO ===")
    logging.info(f"Arquivos processados com sucesso: {sucessos}/{len(csv_files)}")

def main():
    """Função principal"""
    
    platform = detect_platform()
    logging.info(f"=== SEPARADOR DE LOCALIDADES ===")
    logging.info(f"Plataforma detectada: {platform}")
    logging.info(f"Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Verifica argumentos da linha de comando
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        
        if os.path.exists(input_file):
            process_csv_file(input_file, output_file)
        else:
            logging.error(f"Arquivo não encontrado: {input_file}")
    else:
        # Processa todos os arquivos do dataset
        process_all_csv_files()

if __name__ == "__main__":
    main()

