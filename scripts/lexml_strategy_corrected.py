#!/usr/bin/env python3
"""
Estratégia LexML Corrigida
Autor: Manus AI
Data: 2025-07-12

Versão corrigida que resolve os problemas identificados:
1. Extração correta de datas dos documentos
2. Classificação adequada de tipos de documento
3. Melhoria na cobertura de resultados
4. Correção do date range para usar datas dos documentos
"""

import requests
import pandas as pd
from bs4 import BeautifulSoup
import time
import re
from datetime import datetime
from typing import Dict, List, Optional, Union
import logging
from urllib.parse import urljoin, urlparse, parse_qs

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LexMLStrategyCorrected:
    """
    Estratégia LexML corrigida para extração precisa de dados.
    """
    
    def __init__(self):
        self.base_url = "https://www.lexml.gov.br"
        self.search_url = f"{self.base_url}/busca/search"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive'
        })
    
    def search_documents(self, 
                        search_term: str,
                        document_category: str = "",
                        authority_sphere: str = "",
                        max_results: int = 100) -> List[Dict]:
        """
        Busca documentos no LexML com extração corrigida.
        
        Args:
            search_term: Termo de busca
            document_category: Categoria do documento
            authority_sphere: Esfera da autoridade
            max_results: Número máximo de resultados
            
        Returns:
            Lista de documentos com dados corrigidos
        """
        logger.info(f"Iniciando busca corrigida por: '{search_term}'")
        
        params = {
            'keyword': search_term,
            'f1-tipoDocumento': document_category
        }
        
        if authority_sphere:
            params['f2-autoridade'] = authority_sphere
        
        try:
            response = self.session.get(self.search_url, params=params)
            response.raise_for_status()
            
            logger.info(f"URL da busca: {response.url}")
            
            # Extrai resultados da primeira página
            results = self._extract_results_corrected(response.text, search_term)
            
            # Processa páginas adicionais se necessário
            page = 2
            while len(results) < max_results:
                next_url = self._get_next_page_url(response.text, response.url)
                if not next_url:
                    break
                
                logger.info(f"Processando página {page}")
                response = self.session.get(next_url)
                response.raise_for_status()
                
                page_results = self._extract_results_corrected(response.text, search_term)
                if not page_results:
                    break
                
                results.extend(page_results)
                page += 1
                time.sleep(1)  # Rate limiting
                
                if len(results) >= max_results:
                    results = results[:max_results]
                    break
            
            logger.info(f"Total de resultados extraídos: {len(results)}")
            return results
            
        except Exception as e:
            logger.error(f"Erro na busca: {e}")
            return []
    
    def _extract_results_corrected(self, html_content: str, search_term: str) -> List[Dict]:
        """
        Extrai resultados com correções implementadas.
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        results = []
        
        # Estratégia corrigida: busca por links "Adicionar"
        add_links = soup.find_all('a', href=re.compile(r'javascript:add_\d+'))
        logger.info(f"Encontrados {len(add_links)} botões 'Adicionar'")
        
        for add_link in add_links:
            try:
                # Encontra a tabela container
                container = add_link.find_parent('table')
                if not container:
                    # Fallback: procura por container div
                    container = add_link.find_parent('div')
                
                if container:
                    result = self._extract_single_result_corrected(container, search_term)
                    if result:
                        results.append(result)
                        
            except Exception as e:
                logger.warning(f"Erro ao extrair resultado: {e}")
                continue
        
        # Fallback: se não encontrou resultados, usa estratégia alternativa
        if not results:
            results = self._extract_fallback_strategy(soup, search_term)
        
        return results
    
    def _extract_single_result_corrected(self, container, search_term: str) -> Optional[Dict]:
        """
        Extrai um único resultado com todas as correções implementadas.
        """
        try:
            result = {
                'search_term': search_term,
                'date_searched': datetime.now().isoformat(),
                'url': '',
                'title': '',
                'urn': '',
                'urn_type': '',
                'country': '',
                'state': '',
                'municipality': '',
                'justice': '',
                'region': '',
                'court_class': '',
                'document_type_full': '',
                'enacting_date': '',
                'document_description': '',
                'document_summary': ''
            }
            
            # Extrai campos estruturados da tabela
            cells = container.find_all('td')
            
            for i in range(len(cells) - 1):
                label = cells[i].get_text(strip=True)
                value = cells[i + 1].get_text(strip=True)
                
                if label == 'Localidade':
                    result['locality'] = value
                elif label == 'Autoridade':
                    result['authority'] = value
                elif label == 'Título':
                    result['title'] = value
                    # Extrai URL do link no título
                    link = cells[i + 1].find('a')
                    if link and link.get('href'):
                        result['url'] = urljoin(self.base_url, link.get('href'))
                elif label == 'Data':
                    # CORREÇÃO: Extrai e converte data corretamente
                    date_str = value
                    result['enacting_date'] = self._convert_date_format(date_str)
                elif label == 'Ementa':
                    result['document_summary'] = value
                elif label == 'URN':
                    result['urn'] = value
                    # CORREÇÃO: Classifica URN corretamente
                    urn_data = self._parse_urn_corrected(value)
                    result.update(urn_data)
                elif label == 'Assuntos':
                    result['document_description'] = value
            
            # Validação: verifica se extraiu dados suficientes
            if result['title'] or result['urn'] or result['url']:
                return result
            
            return None
            
        except Exception as e:
            logger.error(f"Erro ao extrair resultado: {e}")
            return None
    
    def _convert_date_format(self, date_str: str) -> str:
        """
        Converte data de DD/MM/AAAA para AAAA-MM-DD.
        """
        try:
            # Remove espaços e caracteres extras
            date_str = date_str.strip()
            
            # Padrão DD/MM/AAAA
            match = re.search(r'(\d{2})/(\d{2})/(\d{4})', date_str)
            if match:
                day, month, year = match.groups()
                return f"{year}-{month}-{day}"
            
            # Padrão AAAA-MM-DD (já no formato correto)
            match = re.search(r'(\d{4})-(\d{2})-(\d{2})', date_str)
            if match:
                return match.group(0)
            
            # Padrão apenas ano
            match = re.search(r'(\d{4})', date_str)
            if match:
                return f"{match.group(1)}-01-01"
            
            return ''
            
        except Exception as e:
            logger.warning(f"Erro ao converter data '{date_str}': {e}")
            return ''
    
    def _parse_urn_corrected(self, urn: str) -> Dict[str, str]:
        """
        Parsing corrigido de URNs com classificação adequada.
        """
        if not urn or not urn.startswith('urn:lex:'):
            return {'urn_type': 'unknown'}
        
        try:
            # Remove prefixo urn:lex:
            urn_content = urn[8:]
            
            result = {
                'urn_type': 'unknown',
                'country': '',
                'state': '',
                'municipality': '',
                'justice': '',
                'region': '',
                'court_class': '',
                'document_type_full': ''
            }
            
            # CORREÇÃO: Classificação baseada no conteúdo da URN
            if 'justica' in urn_content:
                result['urn_type'] = 'jurisprudence'
                result = self._parse_jurisprudence_urn_corrected(urn_content, result)
            elif any(term in urn_content for term in [
                'federal:decreto', 'federal:lei', 'federal:medida.provisoria',
                'estadual:decreto', 'estadual:lei', 'municipal:decreto', 'municipal:lei',
                'senado.federal:', 'congresso.nacional:', 'camara.deputados:'
            ]):
                result['urn_type'] = 'legislation'
                result = self._parse_legislation_urn_corrected(urn_content, result)
            elif any(term in urn_content for term in [
                'rede.virtual.bibliotecas', 'biblioteca.digital', 'repositorio'
            ]):
                result['urn_type'] = 'doctrine'
                result = self._parse_doctrine_urn_corrected(urn_content, result)
            else:
                # Análise mais detalhada para casos ambíguos
                result = self._classify_ambiguous_urn(urn_content, result)
            
            # Extrai país
            if urn_content.startswith('br'):
                result['country'] = 'br'
            
            return result
            
        except Exception as e:
            logger.error(f"Erro no parsing da URN {urn}: {e}")
            return {'urn_type': 'unknown'}
    
    def _classify_ambiguous_urn(self, urn_content: str, result: Dict[str, str]) -> Dict[str, str]:
        """
        Classifica URNs ambíguas usando heurísticas adicionais.
        """
        # Padrões que indicam legislação
        legislation_patterns = [
            r'decreto', r'lei', r'resolucao', r'portaria', r'instrucao.normativa',
            r'medida.provisoria', r'emenda.constitucional', r'decreto.legislativo'
        ]
        
        # Padrões que indicam jurisprudência
        jurisprudence_patterns = [
            r'acordao', r'decisao', r'sumula', r'tribunal', r'turma'
        ]
        
        # Padrões que indicam doutrina
        doctrine_patterns = [
            r'artigo', r'livro', r'tese', r'dissertacao', r'revista'
        ]
        
        urn_lower = urn_content.lower()
        
        for pattern in legislation_patterns:
            if re.search(pattern, urn_lower):
                result['urn_type'] = 'legislation'
                return self._parse_legislation_urn_corrected(urn_content, result)
        
        for pattern in jurisprudence_patterns:
            if re.search(pattern, urn_lower):
                result['urn_type'] = 'jurisprudence'
                return self._parse_jurisprudence_urn_corrected(urn_content, result)
        
        for pattern in doctrine_patterns:
            if re.search(pattern, urn_lower):
                result['urn_type'] = 'doctrine'
                return self._parse_doctrine_urn_corrected(urn_content, result)
        
        # Default para legislação se não conseguir classificar
        result['urn_type'] = 'legislation'
        return result
    
    def _parse_legislation_urn_corrected(self, urn_content: str, result: Dict[str, str]) -> Dict[str, str]:
        """
        Parse corrigido para URNs de legislação.
        """
        try:
            parts = urn_content.split(':')
            
            if len(parts) >= 1:
                location_part = parts[0]
                
                # Identifica autoridade
                if 'federal' in location_part:
                    result['authority_level'] = 'federal'
                elif 'estadual' in location_part:
                    result['authority_level'] = 'estadual'
                elif 'municipal' in location_part:
                    result['authority_level'] = 'municipal'
                elif 'distrital' in location_part:
                    result['authority_level'] = 'distrital'
                elif 'senado.federal' in location_part:
                    result['authority_level'] = 'federal'
                    result['authority_organ'] = 'Senado Federal'
                elif 'congresso.nacional' in location_part:
                    result['authority_level'] = 'federal'
                    result['authority_organ'] = 'Congresso Nacional'
                
                # Extrai estado/município se presente
                location_parts = location_part.split(';')[0].split('.')
                if len(location_parts) >= 3:
                    result['state'] = location_parts[1].replace('-', ' ').title()
                    result['municipality'] = location_parts[2].replace('-', ' ').title()
            
            if len(parts) >= 2:
                result['document_type_full'] = parts[1].replace('.', ' ').title()
            
            return result
            
        except Exception:
            return result
    
    def _parse_jurisprudence_urn_corrected(self, urn_content: str, result: Dict[str, str]) -> Dict[str, str]:
        """
        Parse corrigido para URNs de jurisprudência.
        """
        try:
            parts = urn_content.split(':')
            
            if len(parts) >= 1:
                location_parts = parts[0].split(';')
                
                for part in location_parts:
                    if 'justica' in part:
                        justice_parts = part.split('.')
                        if len(justice_parts) >= 2:
                            result['justice'] = f"Justiça {justice_parts[1].title()}"
                    elif 'regiao' in part:
                        result['region'] = part.replace('.', ' ').title()
            
            if len(parts) >= 2:
                court_parts = parts[1].split(';')
                if court_parts:
                    result['court_class'] = court_parts[0].replace('.', ' ').title()
            
            if len(parts) >= 3:
                result['document_type_full'] = parts[2].title()
            
            return result
            
        except Exception:
            return result
    
    def _parse_doctrine_urn_corrected(self, urn_content: str, result: Dict[str, str]) -> Dict[str, str]:
        """
        Parse corrigido para URNs de doutrina.
        """
        try:
            parts = urn_content.split(':')
            
            if len(parts) >= 2:
                result['source'] = parts[1].replace('.', ' ').title()
            
            if len(parts) >= 3:
                doc_type = parts[2]
                type_mapping = {
                    'artigo.revista': 'Artigo de Revista',
                    'livro': 'Livro',
                    'tese': 'Tese',
                    'dissertacao': 'Dissertação',
                    'capitulo.livro': 'Capítulo de Livro'
                }
                result['document_type_full'] = type_mapping.get(doc_type, doc_type.replace('.', ' ').title())
            
            return result
            
        except Exception:
            return result
    
    def _extract_fallback_strategy(self, soup, search_term: str) -> List[Dict]:
        """
        Estratégia de fallback para casos onde a estratégia principal falha.
        """
        results = []
        
        # Procura por qualquer elemento que contenha URN
        urn_elements = soup.find_all(text=re.compile(r'urn:lex:', re.IGNORECASE))
        
        for urn_text in urn_elements:
            try:
                parent = urn_text.parent
                while parent and parent.name not in ['table', 'div', 'section']:
                    parent = parent.parent
                
                if parent:
                    result = {
                        'search_term': search_term,
                        'date_searched': datetime.now().isoformat(),
                        'urn': urn_text.strip(),
                        'document_summary': parent.get_text(strip=True)[:500]
                    }
                    
                    # Aplica parsing corrigido da URN
                    urn_data = self._parse_urn_corrected(urn_text.strip())
                    result.update(urn_data)
                    
                    results.append(result)
                    
            except Exception as e:
                logger.warning(f"Erro na estratégia de fallback: {e}")
                continue
        
        return results
    
    def _get_next_page_url(self, html_content: str, current_url: str) -> Optional[str]:
        """
        Encontra URL da próxima página.
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Procura por link "Próxima"
        next_links = soup.find_all('a', string=re.compile(r'Próxima|Next', re.IGNORECASE))
        
        for link in next_links:
            href = link.get('href')
            if href:
                return urljoin(current_url, href)
        
        return None
    
    def search_multiple_terms_corrected(self, terms: List[str], **kwargs) -> pd.DataFrame:
        """
        Busca múltiplos termos com estratégia corrigida.
        """
        all_results = []
        
        for term in terms:
            logger.info(f"Processando termo: {term}")
            results = self.search_documents(term, **kwargs)
            all_results.extend(results)
            time.sleep(2)  # Rate limiting
        
        # Converte para DataFrame
        df = pd.DataFrame(all_results)
        
        # Remove duplicatas baseado na URN
        if 'urn' in df.columns and len(df) > 0:
            df = df.drop_duplicates(subset=['urn'], keep='first')
        
        # Ordena por data de promulgação
        if 'enacting_date' in df.columns and len(df) > 0:
            df = df.sort_values('enacting_date', ascending=False)
        
        return df
    
    def get_date_range_from_results(self, df: pd.DataFrame) -> Dict[str, str]:
        """
        Calcula o range de datas dos documentos (não da busca).
        """
        if 'enacting_date' not in df.columns or len(df) == 0:
            return {'min_date': '', 'max_date': '', 'total_with_dates': 0}
        
        # Filtra datas válidas
        valid_dates = df[df['enacting_date'].str.len() >= 4]['enacting_date']
        
        if len(valid_dates) == 0:
            return {'min_date': '', 'max_date': '', 'total_with_dates': 0}
        
        # Extrai anos para análise
        years = []
        for date_str in valid_dates:
            try:
                if '-' in date_str:
                    year = int(date_str.split('-')[0])
                    years.append(year)
            except:
                continue
        
        if years:
            return {
                'min_date': f"{min(years)}-01-01",
                'max_date': f"{max(years)}-12-31",
                'total_with_dates': len(valid_dates),
                'year_range': f"{min(years)}-{max(years)}"
            }
        
        return {'min_date': '', 'max_date': '', 'total_with_dates': 0}

def test_corrected_strategy():
    """
    Testa a estratégia corrigida.
    """
    print("=== Teste da Estratégia Corrigida ===")
    
    strategy = LexMLStrategyCorrected()
    
    # Teste com termo que sabemos ter problemas
    results = strategy.search_documents("decreto", max_results=20)
    
    if results:
        df = pd.DataFrame(results)
        print(f"Resultados encontrados: {len(df)}")
        
        # Analisa datas extraídas
        dates_extracted = df[df['enacting_date'].str.len() > 0]
        print(f"Documentos com data extraída: {len(dates_extracted)}")
        
        # Analisa tipos de documento
        type_counts = df['urn_type'].value_counts()
        print(f"Distribuição de tipos: {type_counts.to_dict()}")
        
        # Mostra amostra de datas
        if len(dates_extracted) > 0:
            print("\nAmostras de datas extraídas:")
            for i, row in dates_extracted.head(5).iterrows():
                print(f"  {row['title'][:50]}... → {row['enacting_date']}")
        
        # Calcula range de datas
        date_range = strategy.get_date_range_from_results(df)
        print(f"\nRange de datas dos documentos: {date_range}")
        
        # Salva resultados
        df.to_csv('lexml_corrected_results.csv', index=False, encoding='utf-8')
        print("\nResultados salvos em: lexml_corrected_results.csv")
        
    else:
        print("Nenhum resultado encontrado")

if __name__ == "__main__":
    test_corrected_strategy()

