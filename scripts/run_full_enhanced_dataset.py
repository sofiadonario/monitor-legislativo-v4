#!/usr/bin/env python3
"""
Script para coleta COMPLETA do dataset LexML Refinado v2.0
Executa busca abrangente com limites altos para dataset completo
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
log_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'processed', 'lexml_full_dataset_execution.log')
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
    """Executa coleta completa do dataset LexML refinado"""
    
    print("🚀 INICIANDO COLETA COMPLETA DO DATASET LEXML REFINADO v2.0")
    print("=" * 70)
    
    # Configurações para dataset completo
    categories = [
        'transporte_geral',
        'combustiveis_energia',
        'eficiencia_emissoes',
        'tecnologia_inovacao',
        'infraestrutura',
        'regulamentacao_normas',
        'incentivos_tributacao',
        'programas_governamentais',
        'maquinas_equipamentos',
        'operacoes_servicos'
    ]
    
    # Limites altos para dataset completo
    max_results_per_category = 500  # Muito mais alto para capturar tudo
    
    print(f"📊 TODAS as categorias: {len(categories)} categorias")
    print(f"🎯 Máximo de resultados por categoria: {max_results_per_category}")
    print(f"📁 Resultados serão salvos em: ./data/processed/")
    print(f"📋 Log detalhado em: {log_file}")
    print(f"⏱️  Tempo estimado: 15-30 minutos")
    print()
    
    print("🔍 CATEGORIAS A SEREM PROCESSADAS:")
    for i, category in enumerate(categories, 1):
        print(f"   {i:2d}. {category}")
    
    print("\n⚠️  ATENÇÃO: Esta é uma coleta COMPLETA que pode demorar!")
    print("   Monitorar progresso no log ou terminal")
    print()
    
    start_time = time.time()
    
    try:
        # Inicializa o sistema
        print("🔧 Inicializando sistema LexML refinado...")
        logger.info("=== INICIANDO COLETA COMPLETA DO DATASET ===")
        logger.info("Inicializando EnhancedLexMLStrategy para coleta completa")
        
        strategy = EnhancedLexMLStrategy()
        
        # Executa busca abrangente COMPLETA
        print("🔍 Executando busca abrangente COMPLETA...")
        logger.info(f"Iniciando busca COMPLETA com {len(categories)} categorias")
        logger.info(f"Limite por categoria: {max_results_per_category}")
        
        # Mostra progresso durante a execução
        print("📈 Progresso da busca:")
        print("   - Iniciando coleta de dados completa...")
        print("   - Processando todas as categorias...")
        print("   - Aplicando classificação hierárquica...")
        print("   - Executando enriquecimento temático...")
        print("   - Validando qualidade dos dados...")
        
        results = strategy.execute_comprehensive_search(
            categories=categories,  # TODAS as categorias
            max_results_per_category=max_results_per_category,
            include_all_document_types=True
        )
        
        elapsed_time = time.time() - start_time
        
        # Salva resultados no diretório correto
        print("💾 Salvando dataset completo...")
        
        # Gera nome do arquivo com timestamp para dataset completo
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_filename = f"lexml_full_dataset_{timestamp}.csv"
        output_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'processed', output_filename)
        
        # Salva estatísticas
        stats_filename = output_path.replace('.csv', '_statistics.json')
        
        # Salva resultados manualmente com estrutura completa
        import csv
        import json
        
        print(f"📊 Preparando {len(results['results'])} documentos para salvamento...")
        
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            # Cabeçalhos expandidos para dataset completo
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
            
            processed_count = 0
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
                    processed_count += 1
                    
                    # Mostra progresso a cada 100 documentos
                    if processed_count % 100 == 0:
                        print(f"   📝 Processados: {processed_count}/{len(results['results'])} documentos")
                    
                except Exception as e:
                    logger.error(f"Erro ao salvar resultado: {e}")
        
        # Salva estatísticas do dataset completo
        with open(stats_filename, 'w', encoding='utf-8') as f:
            json.dump(results['statistics'], f, indent=2, ensure_ascii=False)
        
        # Exibe resultados finais do dataset completo
        print("\n" + "=" * 70)
        print("🎉 DATASET COMPLETO COLETADO COM SUCESSO!")
        print("=" * 70)
        
        stats = results['statistics']
        execution_summary = stats['execution_summary']
        quality_metrics = stats['quality_metrics']
        
        print(f"📁 Dataset completo salvo em: {output_path}")
        print(f"📊 Estatísticas salvas em: {stats_filename}")
        print(f"⏱️  Tempo total de execução: {elapsed_time/60:.1f} minutos")
        print(f"🎯 Total de documentos únicos: {execution_summary['unique_documents']}")
        print(f"📈 Categorias processadas: {execution_summary['total_categories_searched']}")
        print(f"🔍 Taxa de duplicatas: {execution_summary['duplicate_rate']:.1%}")
        print(f"💾 Tamanho do arquivo: {os.path.getsize(output_path)/1024/1024:.1f} MB")
        
        if quality_metrics:
            print(f"\n🏆 MÉTRICAS DE QUALIDADE DO DATASET:")
            print(f"   Qualidade média geral: {quality_metrics.get('avg_overall', 0):.3f}")
            print(f"   Completude média: {quality_metrics.get('avg_completeness', 0):.3f}")
            print(f"   Precisão média: {quality_metrics.get('avg_accuracy', 0):.3f}")
            print(f"   Consistência média: {quality_metrics.get('avg_consistency', 0):.3f}")
            print(f"   Relevância média: {quality_metrics.get('avg_relevance', 0):.3f}")
        
        # Distribuição detalhada por categoria
        print(f"\n📊 DISTRIBUIÇÃO POR CATEGORIA PRINCIPAL:")
        classification_dist = stats['classification_distribution']
        total_docs = sum(classification_dist['main_categories'].values())
        for category, count in classification_dist['main_categories'].items():
            percentage = (count/total_docs)*100
            print(f"   {category}: {count} documentos ({percentage:.1f}%)")
        
        # Distribuição por tipo de documento
        print(f"\n📋 DISTRIBUIÇÃO POR TIPO DE DOCUMENTO:")
        for doc_type, count in list(classification_dist['document_types'].items())[:10]:  # Top 10
            percentage = (count/total_docs)*100
            print(f"   {doc_type}: {count} documentos ({percentage:.1f}%)")
        
        # Distribuição por qualidade
        print(f"\n🏆 DISTRIBUIÇÃO POR QUALIDADE:")
        total_quality = sum(classification_dist['quality_levels'].values())
        for grade, count in classification_dist['quality_levels'].items():
            percentage = (count/total_quality)*100
            print(f"   Nota {grade}: {count} documentos ({percentage:.1f}%)")
        
        # Breakdown por categoria de busca
        print(f"\n🔍 BREAKDOWN POR CATEGORIA DE BUSCA:")
        for category, stats_cat in stats['category_breakdown'].items():
            count = stats_cat['total_found']
            percentage = (count/execution_summary['total_documents_found'])*100 if execution_summary['total_documents_found'] > 0 else 0
            print(f"   {category}: {count} documentos ({percentage:.1f}%)")
        
        processing_errors = stats.get('processing_errors', 0)
        if processing_errors > 0:
            print(f"\n⚠️  Erros de processamento: {processing_errors}")
        
        print(f"\n✅ DATASET COMPLETO PRONTO PARA ANÁLISE!")
        print(f"📁 Arquivo principal: {output_filename}")
        print(f"📊 Total de registros: {execution_summary['unique_documents']}")
        
        logger.info(f"=== COLETA COMPLETA FINALIZADA ===")
        logger.info(f"Dataset completo salvo em: {output_path}")
        logger.info(f"Total de documentos únicos: {execution_summary['unique_documents']}")
        logger.info(f"Tempo total: {elapsed_time/60:.1f} minutos")
        
    except Exception as e:
        logger.error(f"Erro na coleta completa: {e}")
        print(f"❌ Erro na coleta completa: {e}")
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    main()