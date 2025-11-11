#!/usr/bin/env python3
"""
Script de debug para analisar estrutura HTML do LexML
"""

import requests
from bs4 import BeautifulSoup
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def debug_lexml_structure():
    """Debug da estrutura HTML do LexML"""
    
    # Configurar sessão
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    })
    
    # URL de busca
    search_url = "https://www.lexml.gov.br/busca/search"
    params = {
        'keyword': 'transporte de carga',
        'f1-tipoDocumento': '',
        'page': 1
    }
    
    try:
        # Fazer requisição
        response = session.get(search_url, params=params, timeout=30)
        response.raise_for_status()
        
        print(f"Status Code: {response.status_code}")
        print(f"URL Final: {response.url}")
        print(f"Content Length: {len(response.content)}")
        
        # Parse HTML
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Analisar estrutura
        print("\\n=== ANÁLISE DE TABELAS ===")
        tables = soup.find_all('table')
        print(f"Total de tabelas encontradas: {len(tables)}")
        
        for i, table in enumerate(tables):
            rows = table.find_all('tr')
            print(f"Tabela {i}: {len(rows)} linhas")
            
            # Analisar primeiras linhas de cada tabela
            if len(rows) > 0:
                print(f"  Primeira linha: {len(rows[0].find_all(['td', 'th']))} células")
                first_cell_text = rows[0].find(['td', 'th'])
                if first_cell_text:
                    print(f"  Primeira célula: '{first_cell_text.get_text(strip=True)[:50]}'")
        
        # Procurar por padrões específicos
        print("\\n=== PROCURANDO PADRÕES ===")
        
        # Procurar por números de resultado
        all_cells = soup.find_all(['td', 'th'])
        result_numbers = []
        
        for cell in all_cells:
            text = cell.get_text(strip=True)
            if text.isdigit() and 1 <= int(text) <= 20:
                result_numbers.append(int(text))
        
        print(f"Números de resultado encontrados: {sorted(set(result_numbers))}")
        
        # Procurar por URNs
        page_text = soup.get_text()
        import re
        urns = re.findall(r'urn:lex:br:[^\\s\\]]+', page_text)
        print(f"URNs encontradas: {len(urns)}")
        for urn in urns[:3]:
            print(f"  {urn}")
        
        # Procurar por datas
        dates = re.findall(r'\\d{2}/\\d{2}/\\d{4}', page_text)
        print(f"Datas encontradas: {len(dates)}")
        for date in dates[:3]:
            print(f"  {date}")
        
        # Procurar por links "Adicionar"
        add_links = soup.find_all('a', string=lambda text: text and 'Adicionar' in text)
        print(f"Links 'Adicionar' encontrados: {len(add_links)}")
        
        # Salvar HTML para análise manual
        with open('debug_lexml_page.html', 'w', encoding='utf-8') as f:
            f.write(response.text)
        print("\\nHTML salvo em 'debug_lexml_page.html' para análise manual")
        
        # Analisar estrutura específica da tabela principal
        if tables:
            main_table = max(tables, key=lambda t: len(t.find_all('tr')))
            print(f"\\n=== TABELA PRINCIPAL ({len(main_table.find_all('tr'))} linhas) ===")
            
            rows = main_table.find_all('tr')
            for i, row in enumerate(rows[:10]):  # Primeiras 10 linhas
                cells = row.find_all(['td', 'th'])
                print(f"Linha {i}: {len(cells)} células")
                
                for j, cell in enumerate(cells[:4]):  # Primeiras 4 células
                    text = cell.get_text(strip=True)[:50]
                    print(f"  Célula {j}: '{text}'")
                
                if i >= 5:  # Limitar output
                    break
        
    except Exception as e:
        logger.error(f"Erro no debug: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_lexml_structure()

