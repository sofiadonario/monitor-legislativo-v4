#!/usr/bin/env python3
"""
Teste básico do sistema LexML refinado sem dependências externas
"""

import sys
import os
import json
from datetime import datetime

# Adiciona o diretório src ao path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def test_import_modules():
    """Testa a importação dos módulos"""
    try:
        from lexml_refinado.classification_system import RefinedDocumentClassifier
        print("✅ RefinedDocumentClassifier importado com sucesso")
        
        from lexml_refinado.parsing_prompts import IntegratedParsingSystem
        print("✅ IntegratedParsingSystem importado com sucesso")
        
        from lexml_refinado.thematic_enrichment import ThematicEnrichmentSystem
        print("✅ ThematicEnrichmentSystem importado com sucesso")
        
        from lexml_refinado.quality_controller import ParsingQualityController
        print("✅ ParsingQualityController importado com sucesso")
        
        return True
        
    except ImportError as e:
        print(f"❌ Erro na importação: {e}")
        return False

def test_classification_system():
    """Testa o sistema de classificação"""
    try:
        from lexml_refinado.classification_system import RefinedDocumentClassifier
        
        classifier = RefinedDocumentClassifier()
        
        # Teste com documento de exemplo
        test_doc = {
            'urn': 'urn:lex:br:federal:lei:2023-01-01;12345',
            'title': 'Lei sobre transporte de carga e combustíveis',
            'document_summary': 'Esta lei estabelece normas para o transporte de carga rodoviária e uso de combustíveis sustentáveis',
            'document_type_original': 'Lei'
        }
        
        result = classifier.classify_document(
            test_doc['urn'],
            test_doc['title'], 
            test_doc['document_summary'],
            test_doc['document_type_original']
        )
        
        print("✅ Sistema de classificação funcionando:")
        print(f"   Categoria principal: {result['main_category']}")
        print(f"   Tipo de documento: {result['document_type']}")
        print(f"   Subtipo: {result['document_subtype']}")
        print(f"   Confiança: {result['classification_confidence']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro no sistema de classificação: {e}")
        return False

def test_parsing_system():
    """Testa o sistema de parsing"""
    try:
        from lexml_refinado.parsing_prompts import IntegratedParsingSystem
        
        parsing_system = IntegratedParsingSystem()
        
        # Teste com documento de exemplo
        test_doc = {
            'urn': 'urn:lex:br:federal:lei:2023-01-01;12345',
            'title': 'Lei sobre transporte de carga e combustíveis',
            'document_summary': 'Esta lei estabelece normas para o transporte de carga rodoviária e uso de combustíveis sustentáveis',
            'document_type_original': 'Lei',
            'enacting_date': '2023-01-01'
        }
        
        result = parsing_system.parse_document(test_doc)
        
        print("✅ Sistema de parsing funcionando:")
        print(f"   Confiança de extração: {result['extraction_confidence']}")
        print(f"   Dados estruturados: {len(result['structured_data'])} campos")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro no sistema de parsing: {e}")
        return False

def test_thematic_enrichment():
    """Testa o sistema de enriquecimento temático"""
    try:
        from lexml_refinado.thematic_enrichment import ThematicEnrichmentSystem
        
        enrichment_system = ThematicEnrichmentSystem()
        
        # Teste com documento de exemplo
        test_doc = {
            'title': 'Resolução ANTT sobre transporte de carga e combustíveis',
            'document_summary': 'Estabelece regras para o transporte rodoviário de carga com uso de biodiesel e gás natural veicular',
        }
        
        parsed_content = {
            'structured_data': {
                'document_identification': {'tipo_norma': 'Resolução'},
                'thematic_classification': {'categoria_principal': 'Combustíveis e Energia'}
            }
        }
        
        result = enrichment_system.enrich_document_analysis(parsed_content, test_doc)
        
        print("✅ Sistema de enriquecimento temático funcionando:")
        thematic_enrichment = result['thematic_enrichment']
        print(f"   Temas primários: {thematic_enrichment['primary_themes']}")
        print(f"   Score de relevância: {thematic_enrichment['relevance_score']}")
        print(f"   Stakeholders: {thematic_enrichment['stakeholders_identified']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro no sistema de enriquecimento: {e}")
        return False

def test_quality_controller():
    """Testa o controlador de qualidade"""
    try:
        from lexml_refinado.quality_controller import ParsingQualityController
        
        quality_controller = ParsingQualityController()
        
        # Teste com conteúdo de exemplo
        parsed_content = {
            'structured_data': {
                'document_identification': {
                    'tipo_norma': 'Lei',
                    'data_publicacao': '2023-01-01',
                    'orgao_emissor': 'Congresso Nacional'
                },
                'thematic_classification': {
                    'categoria_principal': 'Transporte Geral'
                },
                'content_analysis': {
                    'objetivo_principal': 'Regulamentar transporte de carga'
                },
                'regulatory_impact': {
                    'normas_revogadas': []
                }
            },
            'thematic_enrichment': {
                'primary_themes': ['transporte_geral'],
                'relevance_score': 0.8,
                'stakeholders_identified': ['transportadores', 'reguladores']
            }
        }
        
        original_document = {
            'urn': 'urn:lex:br:federal:lei:2023-01-01;12345',
            'title': 'Lei sobre transporte de carga',
            'document_summary': 'Esta lei estabelece normas para o transporte de carga rodoviária'
        }
        
        result = quality_controller.validate_parsing_result(parsed_content, original_document)
        
        print("✅ Controlador de qualidade funcionando:")
        print(f"   Qualidade geral: {result['overall_quality']}")
        print(f"   Nota: {result['quality_grade']}")
        print(f"   Completude: {result['completeness_score']}")
        print(f"   Precisão: {result['accuracy_score']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro no controlador de qualidade: {e}")
        return False

def test_search_terms():
    """Testa os termos de busca"""
    try:
        from lexml_refinado.thematic_enrichment import ThematicEnrichmentSystem
        
        enrichment_system = ThematicEnrichmentSystem()
        search_terms = enrichment_system.search_terms
        
        print("✅ Termos de busca carregados:")
        for category, terms in search_terms.items():
            print(f"   {category}: {len(terms)} termos")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro nos termos de busca: {e}")
        return False

def main():
    """Função principal de teste"""
    print("🧪 TESTE DO SISTEMA LEXML REFINADO v2.0")
    print("="*50)
    
    tests = [
        ("Importação de módulos", test_import_modules),
        ("Sistema de classificação", test_classification_system),
        ("Sistema de parsing", test_parsing_system),
        ("Enriquecimento temático", test_thematic_enrichment),
        ("Controlador de qualidade", test_quality_controller),
        ("Termos de busca", test_search_terms)
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        print(f"\n🔍 Testando: {test_name}")
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Erro inesperado: {e}")
            failed += 1
    
    print("\n" + "="*50)
    print("📊 RESULTADOS DOS TESTES")
    print("="*50)
    print(f"✅ Testes aprovados: {passed}")
    print(f"❌ Testes falharam: {failed}")
    print(f"📈 Taxa de sucesso: {passed/(passed+failed)*100:.1f}%")
    
    if failed == 0:
        print("\n🎉 TODOS OS TESTES PASSARAM!")
        print("O sistema LexML refinado está funcionando corretamente.")
    else:
        print(f"\n⚠️  {failed} teste(s) falharam.")
        print("Verifique os erros acima antes de prosseguir.")
    
    return failed == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)