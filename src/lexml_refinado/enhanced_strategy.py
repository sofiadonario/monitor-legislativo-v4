#!/usr/bin/env python3
"""
Estratégia LexML Refinada v2.0
Sistema integrado com classificação hierárquica e parsing especializado

Autor: Manus AI
Data: 2025-07-14
Versão: 2.0
"""

import requests
import csv
import time
import re
import json
import logging
from datetime import datetime, timedelta
from urllib.parse import urlencode, quote
from bs4 import BeautifulSoup
from typing import Dict, List, Optional, Tuple, Any

# Importa os módulos refinados
from .classification_system import RefinedDocumentClassifier
from .parsing_prompts import IntegratedParsingSystem
from .thematic_enrichment import ThematicEnrichmentSystem
from .quality_controller import ParsingQualityController

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('lexml_enhanced_v2.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


class EnhancedLexMLStrategy:
    """
    Estratégia LexML refinada com classificação hierárquica,
    parsing especializado e enriquecimento temático
    """
    
    def __init__(self):
        self.base_url = "https://www.lexml.gov.br/busca/SRU"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Inicializa os sistemas refinados
        self.document_classifier = RefinedDocumentClassifier()
        self.parsing_system = IntegratedParsingSystem()
        self.enrichment_system = ThematicEnrichmentSystem()
        self.quality_controller = ParsingQualityController()
        
        # Carrega os novos termos de busca
        self.enhanced_search_terms = self._load_enhanced_search_terms()
        
        # Estatísticas de execução
        self.execution_stats = {
            'total_searches': 0,
            'total_documents': 0,
            'classification_stats': {},
            'parsing_stats': {},
            'quality_stats': {},
            'errors': []
        }
    
    def execute_comprehensive_search(self, 
                                   categories: Optional[List[str]] = None,
                                   max_results_per_category: int = 100,
                                   include_all_document_types: bool = True) -> Dict[str, Any]:
        """
        Executa busca abrangente com os novos termos organizados por categoria
        
        Args:
            categories: Lista de categorias para buscar (None = todas)
            max_results_per_category: Máximo de resultados por categoria
            include_all_document_types: Incluir todos os tipos de documento
            
        Returns:
            Dicionário com resultados e estatísticas
        """
        logger.info("Iniciando busca abrangente com termos refinados")
        
        if categories is None:
            categories = list(self.enhanced_search_terms.keys())
        
        all_results = []
        category_stats = {}
        
        for category in categories:
            logger.info(f"Processando categoria: {category}")
            
            try:
                category_results = self._search_by_category(
                    category, 
                    max_results_per_category,
                    include_all_document_types
                )
                
                # Processamento e enriquecimento dos resultados
                enriched_results = []
                for result in category_results:
                    try:
                        enriched_result = self._process_document_complete(result, category)
                        enriched_results.append(enriched_result)
                    except Exception as e:
                        logger.error(f"Erro no processamento do documento: {e}")
                        # Adiciona resultado básico mesmo com erro
                        enriched_results.append({
                            **result,
                            'search_category': category,
                            'processing_error': str(e)
                        })
                
                all_results.extend(enriched_results)
                category_stats[category] = {
                    'total_found': len(category_results),
                    'successfully_processed': len(enriched_results),
                    'primary_themes': self._analyze_category_themes(enriched_results)
                }
                
                # Pausa entre categorias
                time.sleep(2)
                
            except Exception as e:
                logger.error(f"Erro na busca da categoria {category}: {e}")
                self.execution_stats['errors'].append({
                    'category': category,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        # Remoção de duplicatas
        unique_results = self._remove_duplicates(all_results)
        
        # Geração de estatísticas finais
        final_stats = self._generate_final_statistics(
            categories, all_results, unique_results, category_stats
        )
        
        logger.info(f"Busca concluída: {len(unique_results)} documentos únicos encontrados")
        
        return {
            'results': unique_results,
            'statistics': final_stats,
            'execution_timestamp': datetime.now().isoformat(),
            'version': '2.0'
        }
    
    def _search_by_category(self, category: str, max_results: int, 
                           include_all_types: bool) -> List[Dict[str, Any]]:
        """
        Executa busca para uma categoria específica
        """
        terms = self.enhanced_search_terms.get(category, [])
        if not terms:
            logger.warning(f"Categoria {category} não encontrada")
            return []
        
        category_results = []
        
        # Busca por combinações de termos (limitando para evitar sobrecarga)
        for i, term in enumerate(terms[:5]):  # Máximo 5 termos por categoria
            try:
                # Busca com termo legal obrigatório
                legal_query = f'("{term}") AND (lei OR decreto OR portaria OR resolução OR "medida provisória" OR "projeto de lei" OR "instrução normativa")'
                
                results = self._execute_search_query(legal_query, max_results // 5)
                
                # Adiciona metadados da busca
                for result in results:
                    result['search_category'] = category
                    result['search_term_used'] = term
                    result['search_query'] = legal_query
                
                category_results.extend(results)
                
                # Pausa entre termos
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Erro na busca do termo '{term}': {e}")
                self.execution_stats['errors'].append({
                    'category': category,
                    'term': term,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        return category_results
    
    def _execute_search_query(self, query: str, max_results: int) -> List[Dict[str, Any]]:
        """
        Executa uma consulta específica no LexML
        """
        results = []
        start_record = 1
        records_per_page = 50
        
        while len(results) < max_results:
            try:
                params = {
                    'query': query,
                    'startRecord': start_record,
                    'maximumRecords': min(records_per_page, max_results - len(results)),
                    'recordSchema': 'oai_dc'
                }
                
                response = self.session.get(self.base_url, params=params, timeout=30)
                response.raise_for_status()
                
                # Parse da resposta
                soup = BeautifulSoup(response.content, 'xml') or BeautifulSoup(response.content, 'html.parser')
                
                # Extração dos registros
                records = self._extract_records_from_response(soup)
                
                if not records:
                    break
                
                results.extend(records)
                start_record += len(records)
                
                # Pausa entre páginas
                time.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Erro na execução da consulta: {e}")
                break
        
        return results[:max_results]
    
    def _extract_records_from_response(self, soup) -> List[Dict[str, Any]]:
        """
        Extrai registros da resposta do LexML
        """
        records = []
        
        # Tentativa de extração via XML estruturado
        xml_records = soup.find_all('record') or soup.find_all('item')
        
        if xml_records:
            for record in xml_records:
                try:
                    extracted_record = self._extract_xml_record(record)
                    if extracted_record:
                        records.append(extracted_record)
                except Exception as e:
                    logger.error(f"Erro na extração de registro XML: {e}")
        
        # Fallback para extração HTML
        if not records:
            html_records = soup.find_all('div', class_='result-item') or soup.find_all('tr')
            
            for record in html_records:
                try:
                    extracted_record = self._extract_html_record(record)
                    if extracted_record:
                        records.append(extracted_record)
                except Exception as e:
                    logger.error(f"Erro na extração de registro HTML: {e}")
        
        return records
    
    def _extract_xml_record(self, record) -> Optional[Dict[str, Any]]:
        """
        Extrai dados de um registro XML
        """
        try:
            # Extração de campos básicos
            title_elem = record.find('title') or record.find('dc:title')
            title = title_elem.get_text(strip=True) if title_elem else ""
            
            identifier_elem = record.find('identifier') or record.find('dc:identifier')
            urn = identifier_elem.get_text(strip=True) if identifier_elem else ""
            
            description_elem = record.find('description') or record.find('dc:description')
            description = description_elem.get_text(strip=True) if description_elem else ""
            
            date_elem = record.find('date') or record.find('dc:date')
            date_text = date_elem.get_text(strip=True) if date_elem else ""
            
            # Processamento da data
            enacting_date = self._extract_and_format_date(title, description, date_text)
            
            # Extração de metadados adicionais
            subject_elem = record.find('subject') or record.find('dc:subject')
            subject = subject_elem.get_text(strip=True) if subject_elem else ""
            
            creator_elem = record.find('creator') or record.find('dc:creator')
            creator = creator_elem.get_text(strip=True) if creator_elem else ""
            
            # Classificação inicial baseada na URN
            urn_classification = self._classify_from_urn(urn)
            
            return {
                'date_searched': datetime.now().strftime('%Y-%m-%d'),
                'url': f"https://www.lexml.gov.br/urn/{urn}" if urn else "",
                'title': title,
                'urn': urn,
                'urn_type': urn_classification['urn_type'],
                'country': urn_classification['country'],
                'state': urn_classification['state'],
                'municipality': urn_classification['municipality'],
                'justice': urn_classification['justice'],
                'region': urn_classification['region'],
                'court_class': urn_classification['court_class'],
                'document_type_full': urn_classification['document_type_full'],
                'enacting_date': enacting_date,
                'document_description': description,
                'document_summary': description,
                'subject': subject,
                'creator': creator,
                'extraction_method': 'xml',
                'extraction_confidence': 0.9
            }
            
        except Exception as e:
            logger.error(f"Erro na extração XML: {e}")
            return None
    
    def _extract_html_record(self, record) -> Optional[Dict[str, Any]]:
        """
        Extrai dados de um registro HTML
        """
        try:
            # Busca por links "Adicionar" ou títulos
            title_elem = (record.find('a', href=lambda x: x and 'adicionar' in x.lower()) or
                         record.find('a', class_='title') or
                         record.find('h3') or
                         record.find('strong'))
            
            title = title_elem.get_text(strip=True) if title_elem else ""
            
            # Extração da URN do href
            urn = ""
            if title_elem and title_elem.get('href'):
                href = title_elem.get('href')
                urn_match = re.search(r'urn:lex:[^&\s]+', href)
                if urn_match:
                    urn = urn_match.group(0)
            
            # Busca por descrição/ementa
            description_elem = (record.find('div', class_='description') or
                              record.find('p') or
                              record.find('td', string=lambda x: x and len(x) > 50))
            
            description = description_elem.get_text(strip=True) if description_elem else ""
            
            # Extração de data
            enacting_date = self._extract_and_format_date(title, description)
            
            # Classificação baseada na URN
            urn_classification = self._classify_from_urn(urn)
            
            return {
                'date_searched': datetime.now().strftime('%Y-%m-%d'),
                'url': f"https://www.lexml.gov.br/urn/{urn}" if urn else "",
                'title': title,
                'urn': urn,
                'urn_type': urn_classification['urn_type'],
                'country': urn_classification['country'],
                'state': urn_classification['state'],
                'municipality': urn_classification['municipality'],
                'justice': urn_classification['justice'],
                'region': urn_classification['region'],
                'court_class': urn_classification['court_class'],
                'document_type_full': urn_classification['document_type_full'],
                'enacting_date': enacting_date,
                'document_description': description,
                'document_summary': description,
                'extraction_method': 'html',
                'extraction_confidence': 0.7
            }
            
        except Exception as e:
            logger.error(f"Erro na extração HTML: {e}")
            return None
    
    def _process_document_complete(self, document: Dict[str, Any], 
                                  category: str) -> Dict[str, Any]:
        """
        Processa um documento completamente com todos os sistemas refinados
        """
        try:
            # 1. Classificação refinada
            classification = self.document_classifier.classify_document(
                document.get('urn', ''),
                document.get('title', ''),
                document.get('document_summary', ''),
                document.get('document_type_full', '')
            )
            
            # 2. Parsing especializado
            parsed_content = self.parsing_system.parse_document(document)
            
            # 3. Enriquecimento temático
            enriched_content = self.enrichment_system.enrich_document_analysis(
                parsed_content, document
            )
            
            # 4. Controle de qualidade
            quality_assessment = self.quality_controller.validate_parsing_result(
                enriched_content, document
            )
            
            # 5. Montagem do resultado final
            final_result = {
                **document,
                'classification': classification,
                'parsed_content': enriched_content,
                'quality_assessment': quality_assessment,
                'processing_timestamp': datetime.now().isoformat(),
                'system_version': '2.0'
            }
            
            return final_result
            
        except Exception as e:
            logger.error(f"Erro no processamento completo: {e}")
            # Retorna documento básico em caso de erro
            return {
                **document,
                'processing_error': str(e),
                'processing_timestamp': datetime.now().isoformat()
            }
    
    def _extract_and_format_date(self, title: str, description: str, 
                                date_field: str = "") -> str:
        """
        Extrai e formata data com múltiplas estratégias
        """
        # Padrões de data em português
        date_patterns = [
            r'(\d{1,2})\s+de\s+(\w+)\s+de\s+(\d{4})',  # "14 de junho de 2023"
            r'(\d{1,2})/(\d{1,2})/(\d{4})',             # "14/06/2023"
            r'(\d{4})-(\d{2})-(\d{2})',                 # "2023-06-14"
            r'(\d{1,2})\.(\d{1,2})\.(\d{4})',           # "14.06.2023"
            r'(\d{4})/(\d{2})/(\d{2})',                 # "2023/06/14"
        ]
        
        # Mapeamento de meses
        month_names = {
            'janeiro': '01', 'fevereiro': '02', 'março': '03', 'abril': '04',
            'maio': '05', 'junho': '06', 'julho': '07', 'agosto': '08',
            'setembro': '09', 'outubro': '10', 'novembro': '11', 'dezembro': '12'
        }
        
        # Texto combinado para busca
        search_text = f"{title} {description} {date_field}".lower()
        
        # Tentativa de extração por padrões
        for pattern in date_patterns:
            matches = re.findall(pattern, search_text)
            if matches:
                match = matches[0]
                
                try:
                    if len(match) == 3:
                        if pattern == date_patterns[0]:  # "14 de junho de 2023"
                            day, month_name, year = match
                            month = month_names.get(month_name.lower(), '01')
                            return f"{year}-{month.zfill(2)}-{day.zfill(2)}"
                        
                        elif pattern == date_patterns[1]:  # "14/06/2023"
                            day, month, year = match
                            return f"{year}-{month.zfill(2)}-{day.zfill(2)}"
                        
                        elif pattern == date_patterns[2]:  # "2023-06-14"
                            return f"{match[0]}-{match[1]}-{match[2]}"
                        
                        elif pattern == date_patterns[3]:  # "14.06.2023"
                            day, month, year = match
                            return f"{year}-{month.zfill(2)}-{day.zfill(2)}"
                        
                        elif pattern == date_patterns[4]:  # "2023/06/14"
                            year, month, day = match
                            return f"{year}-{month.zfill(2)}-{day.zfill(2)}"
                
                except Exception as e:
                    logger.error(f"Erro na formatação de data: {e}")
                    continue
        
        # Fallback: busca por ano
        year_match = re.search(r'\b(19|20)\d{2}\b', search_text)
        if year_match:
            year = year_match.group(0)
            return f"{year}-01-01"
        
        return ""
    
    def _classify_from_urn(self, urn: str) -> Dict[str, str]:
        """
        Classifica documento baseado na URN
        """
        if not urn:
            return self._get_default_classification()
        
        urn_lower = urn.lower()
        urn_parts = urn.split(':')
        
        classification = {
            'urn_type': 'unknown',
            'country': 'br',
            'state': '',
            'municipality': '',
            'justice': '',
            'region': '',
            'court_class': '',
            'document_type_full': 'unknown'
        }
        
        # Identificação do país
        if len(urn_parts) > 2:
            classification['country'] = urn_parts[2]
        
        # Identificação da esfera e tipo
        if 'federal' in urn_lower:
            classification['region'] = 'Federal'
            classification['urn_type'] = 'legislation'
        elif 'estadual' in urn_lower:
            classification['region'] = 'Estadual'
            classification['urn_type'] = 'legislation'
        elif 'municipal' in urn_lower:
            classification['region'] = 'Municipal'
            classification['urn_type'] = 'legislation'
        
        # Identificação do tipo de documento
        document_type_patterns = {
            'lei': 'Lei',
            'decreto': 'Decreto',
            'portaria': 'Portaria',
            'resolucao': 'Resolução',
            'instrucao.normativa': 'Instrução Normativa',
            'medida.provisoria': 'Medida Provisória',
            'jurisprudencia': 'Jurisprudência',
            'acordao': 'Acórdão',
            'sumula': 'Súmula'
        }
        
        for pattern, doc_type in document_type_patterns.items():
            if pattern in urn_lower:
                classification['document_type_full'] = doc_type
                if pattern in ['jurisprudencia', 'acordao', 'sumula']:
                    classification['urn_type'] = 'jurisprudence'
                else:
                    classification['urn_type'] = 'legislation'
                break
        
        # Identificação de estado
        state_patterns = {
            'sp': 'São Paulo', 'rj': 'Rio de Janeiro', 'mg': 'Minas Gerais',
            'rs': 'Rio Grande do Sul', 'pr': 'Paraná', 'sc': 'Santa Catarina',
            'ba': 'Bahia', 'go': 'Goiás', 'pe': 'Pernambuco', 'ce': 'Ceará'
        }
        
        for state_code, state_name in state_patterns.items():
            if f':{state_code}:' in urn_lower or f';{state_code};' in urn_lower:
                classification['state'] = state_name
                break
        
        # Se não identificou tipo, classifica como doutrina
        if classification['urn_type'] == 'unknown':
            classification['urn_type'] = 'doctrine'
            classification['document_type_full'] = 'Documento Doutrinário'
        
        return classification
    
    def _get_default_classification(self) -> Dict[str, str]:
        """
        Retorna classificação padrão
        """
        return {
            'urn_type': 'doctrine',
            'country': 'br',
            'state': '',
            'municipality': '',
            'justice': '',
            'region': '',
            'court_class': '',
            'document_type_full': 'Documento Não Classificado'
        }
    
    def _remove_duplicates(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicatas baseado na URN
        """
        seen_urns = set()
        unique_results = []
        
        for result in results:
            urn = result.get('urn', '')
            if urn and urn not in seen_urns:
                seen_urns.add(urn)
                unique_results.append(result)
            elif not urn:
                # Para documentos sem URN, usa título como chave
                title_key = result.get('title', '')[:100]
                if title_key not in seen_urns:
                    seen_urns.add(title_key)
                    unique_results.append(result)
        
        return unique_results
    
    def _analyze_category_themes(self, results: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Analisa temas principais por categoria
        """
        theme_counts = {}
        
        for result in results:
            parsed_content = result.get('parsed_content', {})
            thematic_enrichment = parsed_content.get('thematic_enrichment', {})
            primary_themes = thematic_enrichment.get('primary_themes', [])
            
            for theme in primary_themes:
                theme_counts[theme] = theme_counts.get(theme, 0) + 1
        
        return dict(sorted(theme_counts.items(), key=lambda x: x[1], reverse=True))
    
    def _generate_final_statistics(self, categories: List[str], 
                                  all_results: List[Dict[str, Any]],
                                  unique_results: List[Dict[str, Any]],
                                  category_stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gera estatísticas finais da execução
        """
        # Distribuição por categoria principal
        main_categories = {}
        document_types = {}
        quality_levels = {}
        
        for result in unique_results:
            classification = result.get('classification', {})
            quality_assessment = result.get('quality_assessment', {})
            
            # Categoria principal
            main_cat = classification.get('main_category', 'unknown')
            main_categories[main_cat] = main_categories.get(main_cat, 0) + 1
            
            # Tipo de documento
            doc_type = classification.get('document_type', 'unknown')
            document_types[doc_type] = document_types.get(doc_type, 0) + 1
            
            # Qualidade
            quality_grade = quality_assessment.get('quality_grade', 'F')
            quality_levels[quality_grade] = quality_levels.get(quality_grade, 0) + 1
        
        # Métricas de qualidade agregadas
        quality_metrics = self._calculate_aggregated_quality_metrics(unique_results)
        
        return {
            'execution_summary': {
                'total_categories_searched': len(categories),
                'total_documents_found': len(all_results),
                'unique_documents': len(unique_results),
                'duplicate_rate': (len(all_results) - len(unique_results)) / len(all_results) if all_results else 0
            },
            'category_breakdown': category_stats,
            'classification_distribution': {
                'main_categories': main_categories,
                'document_types': document_types,
                'quality_levels': quality_levels
            },
            'quality_metrics': quality_metrics,
            'processing_errors': len(self.execution_stats['errors']),
            'system_performance': {
                'average_processing_time': 'N/A',  # Seria calculado em implementação real
                'success_rate': (len(unique_results) / len(all_results)) if all_results else 0
            }
        }
    
    def _calculate_aggregated_quality_metrics(self, results: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Calcula métricas agregadas de qualidade
        """
        if not results:
            return {}
        
        quality_scores = {
            'completeness': [],
            'accuracy': [],
            'consistency': [],
            'relevance': [],
            'overall': []
        }
        
        for result in results:
            quality_assessment = result.get('quality_assessment', {})
            
            quality_scores['completeness'].append(quality_assessment.get('completeness_score', 0))
            quality_scores['accuracy'].append(quality_assessment.get('accuracy_score', 0))
            quality_scores['consistency'].append(quality_assessment.get('consistency_score', 0))
            quality_scores['relevance'].append(quality_assessment.get('relevance_score', 0))
            quality_scores['overall'].append(quality_assessment.get('overall_quality', 0))
        
        # Calcula médias
        aggregated_metrics = {}
        for metric, scores in quality_scores.items():
            aggregated_metrics[f'avg_{metric}'] = sum(scores) / len(scores) if scores else 0
            aggregated_metrics[f'min_{metric}'] = min(scores) if scores else 0
            aggregated_metrics[f'max_{metric}'] = max(scores) if scores else 0
        
        return aggregated_metrics
    
    def save_enhanced_results(self, search_results: Dict[str, Any], 
                            filename: str = None) -> str:
        """
        Salva resultados com metadados enriquecidos
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'lexml_enhanced_results_{timestamp}.csv'
        
        results = search_results['results']
        
        # Cabeçalhos expandidos para o CSV
        headers = [
            'search_term', 'search_category', 'date_searched', 'url', 'title', 'urn',
            'urn_type', 'country', 'state', 'municipality', 'justice', 'region',
            'court_class', 'document_type_full', 'enacting_date', 'document_description',
            'document_summary', 'main_category', 'document_type_refined', 'document_subtype',
            'classification_confidence', 'primary_themes', 'secondary_themes',
            'relevance_score', 'stakeholders_identified', 'sectoral_impact',
            'regulatory_complexity', 'emerging_trends', 'program_alignment',
            'quality_grade', 'overall_quality', 'completeness_score', 'accuracy_score',
            'consistency_score', 'relevance_score_quality', 'critical_issues',
            'extraction_method', 'extraction_confidence', 'processing_timestamp'
        ]
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            
            for result in results:
                try:
                    classification = result.get('classification', {})
                    parsed_content = result.get('parsed_content', {})
                    thematic_enrichment = parsed_content.get('thematic_enrichment', {})
                    quality_assessment = result.get('quality_assessment', {})
                    
                    row = [
                        result.get('search_term_used', ''),
                        result.get('search_category', ''),
                        result.get('date_searched', ''),
                        result.get('url', ''),
                        result.get('title', ''),
                        result.get('urn', ''),
                        result.get('urn_type', ''),
                        result.get('country', ''),
                        result.get('state', ''),
                        result.get('municipality', ''),
                        result.get('justice', ''),
                        result.get('region', ''),
                        result.get('court_class', ''),
                        result.get('document_type_full', ''),
                        result.get('enacting_date', ''),
                        result.get('document_description', ''),
                        result.get('document_summary', ''),
                        classification.get('main_category', ''),
                        classification.get('document_type', ''),
                        classification.get('document_subtype', ''),
                        classification.get('classification_confidence', ''),
                        '; '.join(thematic_enrichment.get('primary_themes', [])),
                        '; '.join(thematic_enrichment.get('secondary_themes', [])),
                        thematic_enrichment.get('relevance_score', ''),
                        '; '.join(thematic_enrichment.get('stakeholders_identified', [])),
                        json.dumps(thematic_enrichment.get('sectoral_impact', {})),
                        json.dumps(thematic_enrichment.get('regulatory_complexity', {})),
                        '; '.join(thematic_enrichment.get('emerging_trends', [])),
                        json.dumps(thematic_enrichment.get('program_alignment', {})),
                        quality_assessment.get('quality_grade', ''),
                        quality_assessment.get('overall_quality', ''),
                        quality_assessment.get('completeness_score', ''),
                        quality_assessment.get('accuracy_score', ''),
                        quality_assessment.get('consistency_score', ''),
                        quality_assessment.get('relevance_score', ''),
                        '; '.join(quality_assessment.get('critical_issues', [])),
                        result.get('extraction_method', ''),
                        result.get('extraction_confidence', ''),
                        result.get('processing_timestamp', '')
                    ]
                    
                    writer.writerow(row)
                    
                except Exception as e:
                    logger.error(f"Erro ao salvar resultado: {e}")
        
        # Salva estatísticas separadamente
        stats_filename = filename.replace('.csv', '_statistics.json')
        with open(stats_filename, 'w', encoding='utf-8') as f:
            json.dump(search_results['statistics'], f, indent=2, ensure_ascii=False)
        
        logger.info(f"Resultados salvos em {filename}")
        logger.info(f"Estatísticas salvas em {stats_filename}")
        
        return filename
    
    def _load_enhanced_search_terms(self) -> Dict[str, List[str]]:
        """
        Carrega os novos termos de busca organizados por categoria
        """
        return {
            'transporte_geral': [
                'transporte de carga', 'transporte rodoviário de carga',
                'logística de carga', 'frete', 'fretamento', 'caminhão',
                'caminhões', 'veículos pesados', 'veículos de carga',
                'veículos comerciais', 'transporte de mercadorias', 'modal rodoviário'
            ],
            'combustiveis_energia': [
                'gás natural veicular', 'biometano', 'diesel', 'biodiesel',
                'diesel verde', 'combustível sustentável', 'hidrogênio',
                'etanol', 'SAF', 'nuclear', 'célula de combustível',
                'algas marinhas', 'HVO', 'combustível marinho', 'petróleo'
            ],
            'eficiencia_emissoes': [
                'eficiência energética', 'emissões', 'descarbonização',
                'gases de efeito estufa', 'rotulagem veicular',
                'consumo de combustível'
            ],
            'tecnologia_inovacao': [
                'tecnologias assistivas', 'veículos autônomos', 'telemetria',
                'rastreamento', 'motorização', 'conversão'
            ],
            'infraestrutura': [
                'postos de abastecimento', 'infraestrutura',
                'terminais de carga', 'centros de distribuição',
                'armazéns'
            ],
            'regulamentacao_normas': [
                'CONTRAN', 'ANTT', 'registro', 'habilitação',
                'licenciamento', 'RNTRC', 'segurança veicular',
                'CNPE', 'CCEE', 'ANA', 'ANP', 'ONS'
            ],
            'incentivos_tributacao': [
                'IPI', 'ICMS', 'incentivo fiscal', 'isenção',
                'benefício tributário', 'financiamento'
            ],
            'programas_governamentais': [
                'Rota 2030', 'Paten', 'Programa de Aceleração da Transição Energética',
                'mobilidade e logística', 'transição energética',
                'desenvolvimento sustentável', 'P&D', 'Lei do Combustível do Futuro'
            ],
            'maquinas_equipamentos': [
                'máquinas agrícolas', 'implementos rodoviários', 'reboque',
                'semi-reboque', 'carreta', 'bitrem', 'rodotrem',
                'equipamentos de transporte'
            ],
            'operacoes_servicos': [
                'transportador autônomo', 'empresa de transporte',
                'operador logístico', 'embarcador', 'terceirização',
                'contrato de frete', 'tabela de frete'
            ]
        }


# Função principal para execução
def main():
    """
    Função principal para execução da estratégia refinada
    """
    logger.info("Iniciando Estratégia LexML Refinada v2.0")
    
    try:
        # Inicialização do sistema
        lexml_strategy = EnhancedLexMLStrategy()
        
        # Execução da busca abrangente
        search_results = lexml_strategy.execute_comprehensive_search(
            categories=None,  # Todas as categorias
            max_results_per_category=25,  # Reduzido para teste
            include_all_document_types=True
        )
        
        # Salvamento dos resultados
        output_file = lexml_strategy.save_enhanced_results(search_results)
        
        # Log das estatísticas finais
        stats = search_results['statistics']
        logger.info(f"Busca concluída com sucesso:")
        logger.info(f"- Total de documentos únicos: {stats['execution_summary']['unique_documents']}")
        logger.info(f"- Categorias processadas: {stats['execution_summary']['total_categories_searched']}")
        logger.info(f"- Qualidade média geral: {stats['quality_metrics'].get('avg_overall', 0):.2f}")
        
        print(f"\n✅ Estratégia LexML Refinada v2.0 executada com sucesso!")
        print(f"📁 Resultados salvos em: {output_file}")
        print(f"📊 Documentos únicos encontrados: {stats['execution_summary']['unique_documents']}")
        print(f"🎯 Qualidade média: {stats['quality_metrics'].get('avg_overall', 0):.2f}")
        
    except Exception as e:
        logger.error(f"Erro na execução da estratégia: {e}")
        print(f"❌ Erro na execução: {e}")


if __name__ == "__main__":
    main()