#!/usr/bin/env python3
"""
Script para execução em background do sistema LexML Refinado v2.0
Salva resultados em ./data/processed/
"""

import sys
import os
import time
import logging
from datetime import datetime

# Adiciona o diretório src ao path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from lexml_refinado import EnhancedLexMLStrategy

# Configuração de logging detalhada
log_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'processed', 'lexml_enhanced_execution.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def main():
    """Executa o sistema LexML refinado em background"""
    
    print("🚀 Iniciando Sistema LexML Refinado v2.0 em Background")
    print("=" * 60)
    
    # Configurações de execução
    categories = [
        'combustiveis_energia',
        'tecnologia_inovacao', 
        'regulamentacao_normas',
        'transporte_geral',
        'eficiencia_emissoes'
    ]
    
    max_results_per_category = 50
    
    print(f"📊 Categorias: {', '.join(categories)}")
    print(f"🎯 Máximo de resultados por categoria: {max_results_per_category}")
    print(f"📁 Resultados serão salvos em: ./data/processed/")
    print(f"📋 Log detalhado em: {log_file}")
    print()
    
    start_time = time.time()
    
    try:
        # Inicializa o sistema
        print("🔧 Inicializando sistema LexML refinado...")
        logger.info("Inicializando EnhancedLexMLStrategy")
        
        strategy = EnhancedLexMLStrategy()
        
        # Executa busca abrangente
        print("🔍 Executando busca abrangente...")
        logger.info(f"Iniciando busca com categorias: {categories}")
        
        # Mostra progresso durante a execução
        print("📈 Progresso da busca:")
        print("   - Iniciando coleta de dados...")
        
        results = strategy.execute_comprehensive_search(
            categories=categories,
            max_results_per_category=max_results_per_category,
            include_all_document_types=True
        )
        
        elapsed_time = time.time() - start_time
        
        # Salva resultados no diretório correto
        print("💾 Salvando resultados...")
        
        # Gera nome do arquivo com timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_filename = f"lexml_enhanced_results_{timestamp}.csv"
        output_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'processed', output_filename)
        
        # Modifica o método para salvar no local correto
        stats_filename = output_path.replace('.csv', '_statistics.json')
        
        # Salva resultados manualmente
        import csv
        import json
        
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            # Cabeçalhos expandidos
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
            
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            
            for result in results['results']:
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
        
        # Salva estatísticas
        with open(stats_filename, 'w', encoding='utf-8') as f:
            json.dump(results['statistics'], f, indent=2, ensure_ascii=False)
        
        # Exibe resultados finais
        print("\n" + "=" * 60)
        print("🎉 EXECUÇÃO CONCLUÍDA COM SUCESSO!")
        print("=" * 60)
        
        stats = results['statistics']
        execution_summary = stats['execution_summary']
        quality_metrics = stats['quality_metrics']
        
        print(f"📁 Resultados salvos em: {output_path}")
        print(f"📊 Estatísticas salvas em: {stats_filename}")
        print(f"⏱️  Tempo de execução: {elapsed_time:.1f} segundos")
        print(f"🎯 Documentos únicos encontrados: {execution_summary['unique_documents']}")
        print(f"📈 Categorias processadas: {execution_summary['total_categories_searched']}")
        print(f"🔍 Taxa de duplicatas: {execution_summary['duplicate_rate']:.1%}")
        
        if quality_metrics:
            print(f"🏆 Qualidade média geral: {quality_metrics.get('avg_overall', 0):.2f}")
            print(f"📋 Completude média: {quality_metrics.get('avg_completeness', 0):.2f}")
            print(f"🎯 Precisão média: {quality_metrics.get('avg_accuracy', 0):.2f}")
            print(f"🔗 Consistência média: {quality_metrics.get('avg_consistency', 0):.2f}")
            print(f"📌 Relevância média: {quality_metrics.get('avg_relevance', 0):.2f}")
        
        # Distribuição por categoria
        print("\n📊 DISTRIBUIÇÃO POR CATEGORIA:")
        classification_dist = stats['classification_distribution']
        for category, count in classification_dist['main_categories'].items():
            print(f"   {category}: {count} documentos")
        
        # Distribuição por qualidade
        print("\n🏆 DISTRIBUIÇÃO POR QUALIDADE:")
        for grade, count in classification_dist['quality_levels'].items():
            print(f"   Nota {grade}: {count} documentos")
        
        processing_errors = stats.get('processing_errors', 0)
        if processing_errors > 0:
            print(f"\n⚠️  Erros de processamento: {processing_errors}")
        
        logger.info(f"Execução concluída com sucesso. Resultados em: {output_path}")
        
    except Exception as e:
        logger.error(f"Erro na execução: {e}")
        print(f"❌ Erro na execução: {e}")
        raise

if __name__ == "__main__":
    main()