#!/usr/bin/env python3
"""
LexML Integration System
Script principal para integrar todos os componentes do sistema LexML
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Optional
import pandas as pd

# Importar componentes do sistema
from lexml_web_scraper_final import LexMLWebScraperFinal
from document_classifier import RefinedDocumentClassifier
from search_terms_processor import EnhancedSearchTermsProcessor
from parsing_prompt_system import IntegratedParsingSystem

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('lexml_integration.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class LexMLIntegrationSystem:
    """
    Sistema de integração completo para LexML
    Coordena todos os componentes do sistema
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Inicializa o sistema de integração
        """
        
        logger.info("🚀 Iniciando Sistema de Integração LexML")
        logger.info("=" * 60)
        
        # Carregar configuração
        self.config = self._load_config(config_file)
        
        # Inicializar componentes
        self.scraper = LexMLWebScraperFinal()
        self.classifier = RefinedDocumentClassifier()
        self.search_processor = EnhancedSearchTermsProcessor()
        self.parsing_system = IntegratedParsingSystem()
        
        # Configurar diretórios
        self.output_dir = self.config.get('output_dir', 'output')
        self.data_dir = self.config.get('data_dir', 'data')
        self._ensure_directories()
        
        # Estatísticas de execução
        self.stats = {
            'start_time': datetime.now(),
            'documents_collected': 0,
            'documents_classified': 0,
            'documents_parsed': 0,
            'errors': 0
        }
        
        logger.info("✅ Sistema de integração inicializado com sucesso!")
    
    def _load_config(self, config_file: Optional[str]) -> Dict:
        """
        Carrega configuração do sistema
        """
        
        default_config = {
            'output_dir': 'output',
            'data_dir': 'data',
            'max_results_per_term': None,
            'enable_classification': True,
            'enable_parsing': True,
            'enable_analytics': True,
            'batch_size': 100,
            'rate_limit_delay': 1.0,
            'retry_attempts': 3,
            'output_formats': ['csv', 'json'],
            'search_categories': [
                'transporte_geral',
                'combustiveis_energia',
                'eficiencia_emissoes',
                'tecnologia_inovacao',
                'regulamentacao_normas'
            ]
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
                    logger.info(f"📋 Configuração carregada de: {config_file}")
            except Exception as e:
                logger.warning(f"⚠️ Erro ao carregar configuração: {e}")
                logger.info("📋 Usando configuração padrão")
        
        return default_config
    
    def _ensure_directories(self):
        """
        Garante que os diretórios necessários existem
        """
        
        directories = [
            self.output_dir,
            self.data_dir,
            os.path.join(self.output_dir, 'raw_data'),
            os.path.join(self.output_dir, 'classified_data'),
            os.path.join(self.output_dir, 'parsed_data'),
            os.path.join(self.output_dir, 'analytics'),
            os.path.join(self.output_dir, 'reports')
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def collect_documents(self, 
                         search_terms: Optional[List[str]] = None,
                         max_results_per_term: Optional[int] = None) -> List[Dict]:
        """
        Coleta documentos usando o web scraper
        """
        
        logger.info("🔍 Iniciando coleta de documentos...")
        
        try:
            if search_terms:
                # Usar termos específicos fornecidos
                logger.info(f"📝 Usando {len(search_terms)} termos específicos")
                all_results = []
                
                for term in search_terms:
                    logger.info(f"🔍 Coletando documentos para: {term}")
                    results = self.scraper.search_term(term, max_results_per_term)
                    all_results.extend(results)
                    
                    # Delay entre termos
                    if len(search_terms) > 1:
                        import time
                        time.sleep(self.config['rate_limit_delay'])
            else:
                # Usar todos os termos do sistema
                logger.info("📝 Usando todos os termos do sistema")
                all_results = self.scraper.search_all_terms(max_results_per_term)
            
            # Remover duplicatas
            unique_results = self._remove_duplicates(all_results)
            
            # Salvar dados brutos
            self._save_raw_data(unique_results)
            
            self.stats['documents_collected'] = len(unique_results)
            logger.info(f"✅ Coleta concluída: {len(unique_results)} documentos únicos")
            
            return unique_results
            
        except Exception as e:
            logger.error(f"❌ Erro durante coleta: {e}")
            self.stats['errors'] += 1
            raise
    
    def classify_documents(self, documents: List[Dict]) -> List[Dict]:
        """
        Classifica documentos usando o sistema de classificação
        """
        
        if not self.config['enable_classification']:
            logger.info("⏭️ Classificação desabilitada na configuração")
            return documents
        
        logger.info("🏷️ Iniciando classificação de documentos...")
        
        try:
            # Classificar em lotes
            batch_size = self.config['batch_size']
            classified_documents = []
            
            for i in range(0, len(documents), batch_size):
                batch = documents[i:i + batch_size]
                logger.info(f"🔄 Classificando lote {i//batch_size + 1}/{(len(documents) + batch_size - 1)//batch_size}")
                
                classified_batch = self.classifier.classify_batch(batch)
                classified_documents.extend(classified_batch)
            
            # Salvar dados classificados
            self._save_classified_data(classified_documents)
            
            # Gerar estatísticas de classificação
            self._generate_classification_stats(classified_documents)
            
            self.stats['documents_classified'] = len(classified_documents)
            logger.info(f"✅ Classificação concluída: {len(classified_documents)} documentos")
            
            return classified_documents
            
        except Exception as e:
            logger.error(f"❌ Erro durante classificação: {e}")
            self.stats['errors'] += 1
            raise
    
    def parse_documents(self, documents: List[Dict]) -> List[Dict]:
        """
        Faz parsing dos documentos usando o sistema de prompts
        """
        
        if not self.config['enable_parsing']:
            logger.info("⏭️ Parsing desabilitado na configuração")
            return documents
        
        logger.info("📝 Iniciando parsing de documentos...")
        
        try:
            parsed_documents = []
            
            for i, doc in enumerate(documents):
                if i % 10 == 0:
                    logger.info(f"🔄 Processando documento {i+1}/{len(documents)}")
                
                try:
                    parsed_result = self.parsing_system.parse_document(doc)
                    
                    # Adicionar resultado do parsing ao documento
                    doc_with_parsing = {
                        **doc,
                        'parsing_result': {
                            'extraction_confidence': parsed_result.extraction_confidence,
                            'structured_data': parsed_result.structured_data,
                            'parsing_timestamp': parsed_result.parsing_timestamp
                        }
                    }
                    
                    parsed_documents.append(doc_with_parsing)
                    
                except Exception as e:
                    logger.warning(f"⚠️ Erro ao fazer parsing do documento {doc.get('urn', 'sem URN')}: {e}")
                    parsed_documents.append(doc)  # Adicionar documento sem parsing
                    continue
            
            # Salvar dados com parsing
            self._save_parsed_data(parsed_documents)
            
            self.stats['documents_parsed'] = len(parsed_documents)
            logger.info(f"✅ Parsing concluído: {len(parsed_documents)} documentos")
            
            return parsed_documents
            
        except Exception as e:
            logger.error(f"❌ Erro durante parsing: {e}")
            self.stats['errors'] += 1
            raise
    
    def analyze_search_effectiveness(self, documents: List[Dict]) -> Dict:
        """
        Analisa efetividade dos termos de busca
        """
        
        logger.info("📊 Analisando efetividade dos termos de busca...")
        
        try:
            # Categorizar resultados
            categorized_results = self.search_processor.categorize_search_results(documents)
            
            # Analisar efetividade
            effectiveness_analysis = self.search_processor.analyze_term_effectiveness(documents)
            
            # Gerar relatório de análise
            report_file = self.search_processor.generate_search_report(
                documents, 
                os.path.join(self.output_dir, 'reports', 'search_analysis_report.json')
            )
            
            logger.info(f"✅ Análise de efetividade concluída: {report_file}")
            
            return {
                'categorized_results': categorized_results,
                'effectiveness_analysis': effectiveness_analysis,
                'report_file': report_file
            }
            
        except Exception as e:
            logger.error(f"❌ Erro durante análise de efetividade: {e}")
            self.stats['errors'] += 1
            raise
    
    def run_complete_pipeline(self, 
                            search_terms: Optional[List[str]] = None,
                            max_results_per_term: Optional[int] = None) -> Dict:
        """
        Executa o pipeline completo do sistema
        """
        
        logger.info("🚀 Iniciando pipeline completo do LexML")
        logger.info("=" * 60)
        
        try:
            # 1. Coleta de documentos
            documents = self.collect_documents(search_terms, max_results_per_term)
            
            # 2. Classificação de documentos
            classified_documents = self.classify_documents(documents)
            
            # 3. Parsing de documentos
            parsed_documents = self.parse_documents(classified_documents)
            
            # 4. Análise de efetividade
            search_analysis = self.analyze_search_effectiveness(parsed_documents)
            
            # 5. Gerar relatório final
            final_report = self._generate_final_report(parsed_documents, search_analysis)
            
            # 6. Salvar dados finais
            self._save_final_data(parsed_documents)
            
            logger.info("🎉 Pipeline completo executado com sucesso!")
            self._print_final_stats()
            
            return {
                'documents': parsed_documents,
                'search_analysis': search_analysis,
                'final_report': final_report,
                'stats': self.stats
            }
            
        except Exception as e:
            logger.error(f"❌ Erro durante execução do pipeline: {e}")
            self.stats['errors'] += 1
            raise
    
    def _remove_duplicates(self, documents: List[Dict]) -> List[Dict]:
        """
        Remove documentos duplicados baseado em URN
        """
        
        seen_urns = set()
        unique_documents = []
        
        for doc in documents:
            urn = doc.get('urn', '')
            title = doc.get('title', '')
            
            # Usar URN como identificador principal
            if urn and urn not in seen_urns:
                seen_urns.add(urn)
                unique_documents.append(doc)
            # Fallback para título se não houver URN
            elif not urn and title and title not in seen_urns:
                seen_urns.add(title)
                unique_documents.append(doc)
        
        logger.info(f"🔄 Removidas {len(documents) - len(unique_documents)} duplicatas")
        return unique_documents
    
    def _save_raw_data(self, documents: List[Dict]):
        """
        Salva dados brutos coletados
        """
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Salvar CSV
        if 'csv' in self.config['output_formats']:
            csv_file = os.path.join(self.output_dir, 'raw_data', f'raw_documents_{timestamp}.csv')
            df = pd.DataFrame(documents)
            df.to_csv(csv_file, index=False, encoding='utf-8')
            logger.info(f"💾 Dados brutos salvos em CSV: {csv_file}")
        
        # Salvar JSON
        if 'json' in self.config['output_formats']:
            json_file = os.path.join(self.output_dir, 'raw_data', f'raw_documents_{timestamp}.json')
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(documents, f, ensure_ascii=False, indent=2)
            logger.info(f"💾 Dados brutos salvos em JSON: {json_file}")
    
    def _save_classified_data(self, documents: List[Dict]):
        """
        Salva dados classificados
        """
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Salvar CSV
        if 'csv' in self.config['output_formats']:
            csv_file = os.path.join(self.output_dir, 'classified_data', f'classified_documents_{timestamp}.csv')
            df = pd.DataFrame(documents)
            df.to_csv(csv_file, index=False, encoding='utf-8')
            logger.info(f"💾 Dados classificados salvos em CSV: {csv_file}")
        
        # Salvar JSON
        if 'json' in self.config['output_formats']:
            json_file = os.path.join(self.output_dir, 'classified_data', f'classified_documents_{timestamp}.json')
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(documents, f, ensure_ascii=False, indent=2)
            logger.info(f"💾 Dados classificados salvos em JSON: {json_file}")
    
    def _save_parsed_data(self, documents: List[Dict]):
        """
        Salva dados com parsing
        """
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Salvar CSV (achatar estrutura para CSV)
        if 'csv' in self.config['output_formats']:
            csv_file = os.path.join(self.output_dir, 'parsed_data', f'parsed_documents_{timestamp}.csv')
            df = pd.json_normalize(documents)
            df.to_csv(csv_file, index=False, encoding='utf-8')
            logger.info(f"💾 Dados com parsing salvos em CSV: {csv_file}")
        
        # Salvar JSON
        if 'json' in self.config['output_formats']:
            json_file = os.path.join(self.output_dir, 'parsed_data', f'parsed_documents_{timestamp}.json')
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(documents, f, ensure_ascii=False, indent=2)
            logger.info(f"💾 Dados com parsing salvos em JSON: {json_file}")
    
    def _save_final_data(self, documents: List[Dict]):
        """
        Salva dados finais processados
        """
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Salvar CSV
        if 'csv' in self.config['output_formats']:
            csv_file = os.path.join(self.output_dir, f'lexml_final_dataset_{timestamp}.csv')
            df = pd.json_normalize(documents)
            df.to_csv(csv_file, index=False, encoding='utf-8')
            logger.info(f"💾 Dataset final salvo em CSV: {csv_file}")
        
        # Salvar JSON
        if 'json' in self.config['output_formats']:
            json_file = os.path.join(self.output_dir, f'lexml_final_dataset_{timestamp}.json')
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(documents, f, ensure_ascii=False, indent=2)
            logger.info(f"💾 Dataset final salvo em JSON: {json_file}")
    
    def _generate_classification_stats(self, documents: List[Dict]):
        """
        Gera estatísticas de classificação
        """
        
        stats = self.classifier.get_classification_statistics(documents)
        
        # Salvar estatísticas
        stats_file = os.path.join(self.output_dir, 'reports', 'classification_stats.json')
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)
        
        logger.info(f"📊 Estatísticas de classificação salvas: {stats_file}")
    
    def _generate_final_report(self, documents: List[Dict], search_analysis: Dict) -> str:
        """
        Gera relatório final do pipeline
        """
        
        logger.info("📄 Gerando relatório final...")
        
        # Calcular estatísticas finais
        total_docs = len(documents)
        
        # Estatísticas por categoria
        category_stats = {}
        for doc in documents:
            category = doc.get('main_category', 'unknown')
            category_stats[category] = category_stats.get(category, 0) + 1
        
        # Estatísticas por tipo
        type_stats = {}
        for doc in documents:
            doc_type = doc.get('document_type', 'unknown')
            type_stats[doc_type] = type_stats.get(doc_type, 0) + 1
        
        # Estatísticas temporais
        years = []
        for doc in documents:
            date_str = doc.get('enacting_date', '')
            if date_str and len(date_str) >= 4:
                year = date_str[:4]
                if year.isdigit():
                    years.append(int(year))
        
        year_range = f"{min(years)}-{max(years)}" if years else "N/A"
        
        # Compilar relatório
        report = {
            'metadata': {
                'generation_date': datetime.now().isoformat(),
                'system_version': '3.0 Final',
                'pipeline_duration': str(datetime.now() - self.stats['start_time']),
                'configuration': self.config
            },
            'execution_stats': self.stats,
            'data_summary': {
                'total_documents': total_docs,
                'year_range': year_range,
                'categories': category_stats,
                'document_types': type_stats
            },
            'search_analysis_summary': {
                'total_categories': len(self.search_processor.search_categories),
                'total_terms': sum(len(terms) for terms in self.search_processor.search_categories.values()),
                'effectiveness_score': self._calculate_overall_effectiveness(search_analysis)
            },
            'quality_metrics': {
                'classification_coverage': self._calculate_classification_coverage(documents),
                'parsing_coverage': self._calculate_parsing_coverage(documents),
                'data_completeness': self._calculate_data_completeness(documents)
            }
        }
        
        # Salvar relatório
        report_file = os.path.join(self.output_dir, 'reports', 'final_report.json')
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        logger.info(f"📄 Relatório final salvo: {report_file}")
        return report_file
    
    def _calculate_overall_effectiveness(self, search_analysis: Dict) -> float:
        """
        Calcula efetividade geral dos termos de busca
        """
        
        if 'effectiveness_analysis' not in search_analysis:
            return 0.0
        
        effectiveness_scores = []
        for category, analysis in search_analysis['effectiveness_analysis'].items():
            effectiveness_scores.append(analysis.get('category_coverage', 0))
        
        return sum(effectiveness_scores) / len(effectiveness_scores) if effectiveness_scores else 0.0
    
    def _calculate_classification_coverage(self, documents: List[Dict]) -> float:
        """
        Calcula cobertura da classificação
        """
        
        classified_docs = sum(1 for doc in documents if doc.get('main_category') and doc.get('main_category') != 'unknown')
        return classified_docs / len(documents) if documents else 0.0
    
    def _calculate_parsing_coverage(self, documents: List[Dict]) -> float:
        """
        Calcula cobertura do parsing
        """
        
        parsed_docs = sum(1 for doc in documents if 'parsing_result' in doc)
        return parsed_docs / len(documents) if documents else 0.0
    
    def _calculate_data_completeness(self, documents: List[Dict]) -> float:
        """
        Calcula completude dos dados
        """
        
        required_fields = ['title', 'urn', 'document_summary', 'enacting_date']
        total_fields = len(required_fields) * len(documents)
        
        filled_fields = 0
        for doc in documents:
            for field in required_fields:
                if doc.get(field) and doc[field] != '':
                    filled_fields += 1
        
        return filled_fields / total_fields if total_fields > 0 else 0.0
    
    def _print_final_stats(self):
        """
        Imprime estatísticas finais
        """
        
        duration = datetime.now() - self.stats['start_time']
        
        print("\n" + "=" * 60)
        print("📊 RELATÓRIO FINAL DE EXECUÇÃO")
        print("=" * 60)
        print(f"⏱️  Duração total: {duration}")
        print(f"🔍 Documentos coletados: {self.stats['documents_collected']:,}")
        print(f"🏷️  Documentos classificados: {self.stats['documents_classified']:,}")
        print(f"📝 Documentos com parsing: {self.stats['documents_parsed']:,}")
        print(f"❌ Erros encontrados: {self.stats['errors']}")
        print(f"📁 Dados salvos em: {self.output_dir}")
        print("=" * 60)
        print("🎉 Pipeline executado com sucesso!")
        print("=" * 60)


def main():
    """
    Função principal com interface de linha de comando
    """
    
    parser = argparse.ArgumentParser(description='Sistema de Integração LexML')
    parser.add_argument('--config', type=str, help='Arquivo de configuração JSON')
    parser.add_argument('--terms', nargs='+', help='Termos específicos para busca')
    parser.add_argument('--max-results', type=int, help='Máximo de resultados por termo')
    parser.add_argument('--categories', nargs='+', help='Categorias de busca específicas')
    parser.add_argument('--skip-classification', action='store_true', help='Pular classificação')
    parser.add_argument('--skip-parsing', action='store_true', help='Pular parsing')
    parser.add_argument('--output-dir', type=str, help='Diretório de saída')
    parser.add_argument('--verbose', '-v', action='store_true', help='Modo verboso')
    
    args = parser.parse_args()
    
    # Configurar logging verboso
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Criar sistema de integração
        system = LexMLIntegrationSystem(args.config)
        
        # Aplicar configurações da linha de comando
        if args.skip_classification:
            system.config['enable_classification'] = False
        if args.skip_parsing:
            system.config['enable_parsing'] = False
        if args.output_dir:
            system.config['output_dir'] = args.output_dir
            system.output_dir = args.output_dir
            system._ensure_directories()
        
        # Executar pipeline
        result = system.run_complete_pipeline(
            search_terms=args.terms,
            max_results_per_term=args.max_results
        )
        
        print(f"\n🎯 Pipeline executado com sucesso!")
        print(f"📊 {len(result['documents'])} documentos processados")
        print(f"📁 Resultados salvos em: {system.output_dir}")
        
    except KeyboardInterrupt:
        print("\n⚠️ Execução interrompida pelo usuário")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Erro durante execução: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()