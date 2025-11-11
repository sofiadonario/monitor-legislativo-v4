#!/usr/bin/env python3
"""
Test Script for LexML System
Testa todos os componentes do sistema LexML integrado
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, List

# Adicionar src ao path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Importar componentes
from lexml_web_scraper_final import LexMLWebScraperFinal
from document_classifier import RefinedDocumentClassifier
from search_terms_processor import EnhancedSearchTermsProcessor
from parsing_prompt_system import IntegratedParsingSystem
from lexml_integration import LexMLIntegrationSystem

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_sample_documents() -> List[Dict]:
    """
    Cria documentos de exemplo para teste
    """
    
    sample_docs = [
        {
            'urn': 'urn:lex:br:federal:lei:2021-12-29;14.267',
            'title': 'Lei sobre uso de biometano em transporte de carga',
            'document_summary': 'Estabelece diretrizes para o uso de biometano como combustível em veículos pesados de transporte de carga, visando reduzir emissões de gases de efeito estufa e promover a sustentabilidade no setor.',
            'document_type_original': 'Lei Federal',
            'enacting_date': '2021-12-29',
            'justice': 'Federal',
            'search_term': 'biometano',
            'date_searched': '2025-01-14',
            'url': 'https://www.lexml.gov.br/urn/urn:lex:br:federal:lei:2021-12-29;14.267',
            'urn_type': 'legislation',
            'country': 'br',
            'state': '',
            'municipality': '',
            'region': '',
            'court_class': 'Federal',
            'document_type_full': 'Lei Federal',
            'document_description': 'Regulamentação do uso de biometano'
        },
        {
            'urn': 'urn:lex:br:federal:decreto:2022-06-15;11.097',
            'title': 'Decreto regulamenta transporte rodoviário de carga perigosa',
            'document_summary': 'Regulamenta o transporte rodoviário de cargas perigosas, estabelecendo normas de segurança, licenciamento de veículos e habilitação de motoristas especializados.',
            'document_type_original': 'Decreto Federal',
            'enacting_date': '2022-06-15',
            'justice': 'Federal',
            'search_term': 'transporte de carga',
            'date_searched': '2025-01-14',
            'url': 'https://www.lexml.gov.br/urn/urn:lex:br:federal:decreto:2022-06-15;11.097',
            'urn_type': 'legislation',
            'country': 'br',
            'state': '',
            'municipality': '',
            'region': '',
            'court_class': 'Federal',
            'document_type_full': 'Decreto Federal',
            'document_description': 'Regulamentação de transporte de carga perigosa'
        },
        {
            'urn': 'urn:lex:br:tribunal.superior.trabalho:acordao:2023-03-10;TST-RR-123456',
            'title': 'Acórdão sobre jornada de trabalho de motoristas de caminhão',
            'document_summary': 'Acórdão do TST estabelece limites para jornada de trabalho de motoristas de transporte de carga, considerando segurança viária e direitos trabalhistas.',
            'document_type_original': 'Acórdão TST',
            'enacting_date': '2023-03-10',
            'justice': 'TST',
            'search_term': 'motorista',
            'date_searched': '2025-01-14',
            'url': 'https://www.lexml.gov.br/urn/urn:lex:br:tribunal.superior.trabalho:acordao:2023-03-10;TST-RR-123456',
            'urn_type': 'jurisprudence',
            'country': 'br',
            'state': '',
            'municipality': '',
            'region': '',
            'court_class': 'Superior',
            'document_type_full': 'Acórdão',
            'document_description': 'Decisão sobre jornada de trabalho'
        }
    ]
    
    return sample_docs

def test_web_scraper():
    """
    Testa o web scraper
    """
    
    print("🔍 Testando Web Scraper...")
    
    try:
        scraper = LexMLWebScraperFinal()
        
        # Teste com termo específico e limite baixo
        results = scraper.search_term("transporte de carga", max_results=10)
        
        print(f"✅ Web Scraper OK - {len(results)} documentos coletados")
        
        if results:
            print(f"📄 Exemplo de documento:")
            print(f"  - Título: {results[0].get('title', 'N/A')}")
            print(f"  - URN: {results[0].get('urn', 'N/A')}")
            print(f"  - Tipo: {results[0].get('urn_type', 'N/A')}")
        
        return True, results[:3]  # Retornar apenas os primeiros 3 para teste
        
    except Exception as e:
        print(f"❌ Erro no Web Scraper: {e}")
        return False, []

def test_document_classifier():
    """
    Testa o classificador de documentos
    """
    
    print("\n🏷️ Testando Classificador de Documentos...")
    
    try:
        classifier = RefinedDocumentClassifier()
        sample_docs = create_sample_documents()
        
        # Testar classificação individual
        for i, doc in enumerate(sample_docs):
            result = classifier.classify_document(
                doc['urn'],
                doc['title'],
                doc['document_summary'],
                doc['document_type_original']
            )
            
            print(f"📄 Documento {i+1}:")
            print(f"  - Categoria: {result['main_category']}")
            print(f"  - Tipo: {result['document_type']}")
            print(f"  - Subtipo: {result['document_subtype']}")
            print(f"  - Confiança: {result['classification_confidence']}")
        
        # Testar classificação em lote
        classified_docs = classifier.classify_batch(sample_docs)
        
        print(f"✅ Classificador OK - {len(classified_docs)} documentos classificados")
        
        return True, classified_docs
        
    except Exception as e:
        print(f"❌ Erro no Classificador: {e}")
        return False, []

def test_search_terms_processor():
    """
    Testa o processador de termos de busca
    """
    
    print("\n🔍 Testando Processador de Termos...")
    
    try:
        processor = EnhancedSearchTermsProcessor()
        
        # Testar geração de queries
        comprehensive_query = processor.generate_search_query(
            categories=['combustiveis_energia', 'tecnologia_inovacao'],
            query_type='comprehensive'
        )
        
        print(f"📝 Query gerada (primeiros 100 chars): {comprehensive_query[:100]}...")
        
        # Testar categorização com documentos de exemplo
        sample_docs = create_sample_documents()
        categorized = processor.categorize_search_results(sample_docs)
        
        print(f"📊 Categorização:")
        for category, docs in categorized.items():
            if docs:
                print(f"  - {category}: {len(docs)} documentos")
        
        print(f"✅ Processador de Termos OK")
        
        return True, categorized
        
    except Exception as e:
        print(f"❌ Erro no Processador de Termos: {e}")
        return False, {}

def test_parsing_system():
    """
    Testa o sistema de parsing
    """
    
    print("\n📝 Testando Sistema de Parsing...")
    
    try:
        parsing_system = IntegratedParsingSystem()
        sample_docs = create_sample_documents()
        
        # Testar parsing de diferentes tipos de documento
        for i, doc in enumerate(sample_docs):
            result = parsing_system.parse_document(doc)
            
            print(f"📄 Documento {i+1}:")
            print(f"  - Confiança: {result.extraction_confidence}")
            print(f"  - Classificação: {result.classification['main_category']}")
            print(f"  - Dados estruturados: {len(result.structured_data)} campos")
        
        print(f"✅ Sistema de Parsing OK")
        
        return True, sample_docs
        
    except Exception as e:
        print(f"❌ Erro no Sistema de Parsing: {e}")
        return False, []

def test_integration_system():
    """
    Testa o sistema de integração
    """
    
    print("\n🔗 Testando Sistema de Integração...")
    
    try:
        # Criar configuração de teste
        test_config = {
            'output_dir': 'test_output',
            'enable_classification': True,
            'enable_parsing': True,
            'max_results_per_term': 5,
            'batch_size': 2
        }
        
        # Salvar configuração temporária
        with open('test_config.json', 'w') as f:
            json.dump(test_config, f)
        
        # Criar sistema de integração
        system = LexMLIntegrationSystem('test_config.json')
        
        # Testar com termos específicos
        print("🔍 Testando coleta com termos específicos...")
        results = system.run_complete_pipeline(
            search_terms=['biometano'],
            max_results_per_term=3
        )
        
        print(f"✅ Sistema de Integração OK")
        print(f"📊 Resultados:")
        print(f"  - Documentos processados: {len(results['documents'])}")
        print(f"  - Erros: {results['stats']['errors']}")
        
        # Limpar arquivo de teste
        if os.path.exists('test_config.json'):
            os.remove('test_config.json')
        
        return True, results
        
    except Exception as e:
        print(f"❌ Erro no Sistema de Integração: {e}")
        return False, {}

def run_all_tests():
    """
    Executa todos os testes
    """
    
    print("🚀 INICIANDO TESTES DO SISTEMA LEXML")
    print("=" * 60)
    
    test_results = {
        'web_scraper': False,
        'classifier': False,
        'search_processor': False,
        'parsing_system': False,
        'integration_system': False
    }
    
    # Teste 1: Web Scraper
    try:
        success, data = test_web_scraper()
        test_results['web_scraper'] = success
    except Exception as e:
        print(f"❌ Erro crítico no Web Scraper: {e}")
    
    # Teste 2: Classificador
    try:
        success, data = test_document_classifier()
        test_results['classifier'] = success
    except Exception as e:
        print(f"❌ Erro crítico no Classificador: {e}")
    
    # Teste 3: Processador de Termos
    try:
        success, data = test_search_terms_processor()
        test_results['search_processor'] = success
    except Exception as e:
        print(f"❌ Erro crítico no Processador de Termos: {e}")
    
    # Teste 4: Sistema de Parsing
    try:
        success, data = test_parsing_system()
        test_results['parsing_system'] = success
    except Exception as e:
        print(f"❌ Erro crítico no Sistema de Parsing: {e}")
    
    # Teste 5: Sistema de Integração
    try:
        success, data = test_integration_system()
        test_results['integration_system'] = success
    except Exception as e:
        print(f"❌ Erro crítico no Sistema de Integração: {e}")
    
    # Relatório final
    print("\n" + "=" * 60)
    print("📊 RELATÓRIO FINAL DOS TESTES")
    print("=" * 60)
    
    total_tests = len(test_results)
    passed_tests = sum(test_results.values())
    
    for test_name, passed in test_results.items():
        status = "✅ PASSOU" if passed else "❌ FALHOU"
        print(f"{test_name}: {status}")
    
    print(f"\n📈 RESUMO: {passed_tests}/{total_tests} testes passaram")
    
    if passed_tests == total_tests:
        print("🎉 TODOS OS TESTES PASSARAM - SISTEMA FUNCIONANDO CORRETAMENTE!")
    else:
        print("⚠️ ALGUNS TESTES FALHARAM - VERIFIQUE OS ERROS ACIMA")
    
    print("=" * 60)
    
    return test_results

if __name__ == "__main__":
    # Executar todos os testes
    results = run_all_tests()
    
    # Salvar resultados dos testes
    with open('test_results.json', 'w') as f:
        json.dump({
            'test_results': results,
            'timestamp': datetime.now().isoformat(),
            'summary': f"{sum(results.values())}/{len(results)} tests passed"
        }, f, indent=2)
    
    print(f"\n💾 Resultados salvos em: test_results.json")