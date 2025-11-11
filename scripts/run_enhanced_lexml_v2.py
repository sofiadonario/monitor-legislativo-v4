#!/usr/bin/env python3
"""
Script para execução da Estratégia LexML Refinada v2.0
Integra todos os componentes refinados para análise legislativa

Uso:
    python run_enhanced_lexml_v2.py [--categories categoria1,categoria2] [--max-results 50]

Autor: Manus AI
Data: 2025-07-14
Versão: 2.0
"""

import sys
import os
import argparse
import logging
from datetime import datetime

# Adiciona o diretório src ao path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from lexml_refinado import EnhancedLexMLStrategy
except ImportError as e:
    print(f"Erro ao importar módulos: {e}")
    print("Verifique se o diretório src/lexml_refinado existe e contém todos os arquivos necessários")
    sys.exit(1)

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def parse_arguments():
    """
    Processa argumentos da linha de comando
    """
    parser = argparse.ArgumentParser(
        description='Executa a Estratégia LexML Refinada v2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Categorias disponíveis:
  - transporte_geral
  - combustiveis_energia
  - eficiencia_emissoes
  - tecnologia_inovacao
  - infraestrutura
  - regulamentacao_normas
  - incentivos_tributacao
  - programas_governamentais
  - maquinas_equipamentos
  - operacoes_servicos

Exemplos:
  python run_enhanced_lexml_v2.py
  python run_enhanced_lexml_v2.py --categories combustiveis_energia,tecnologia_inovacao
  python run_enhanced_lexml_v2.py --max-results 100
        """
    )
    
    parser.add_argument(
        '--categories',
        type=str,
        help='Categorias para buscar (separadas por vírgula). Se não especificado, usa todas.'
    )
    
    parser.add_argument(
        '--max-results',
        type=int,
        default=50,
        help='Número máximo de resultados por categoria (padrão: 50)'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        help='Nome do arquivo de saída (padrão: gerado automaticamente)'
    )
    
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help='Modo verboso (mais detalhes no log)'
    )
    
    parser.add_argument(
        '--test-mode',
        action='store_true',
        help='Modo de teste (apenas 2 resultados por categoria)'
    )
    
    return parser.parse_args()


def validate_categories(categories_str):
    """
    Valida e processa lista de categorias
    """
    if not categories_str:
        return None
    
    available_categories = [
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
    
    requested_categories = [cat.strip() for cat in categories_str.split(',')]
    
    # Valida categorias
    invalid_categories = [cat for cat in requested_categories if cat not in available_categories]
    if invalid_categories:
        logger.error(f"Categorias inválidas: {invalid_categories}")
        logger.info(f"Categorias disponíveis: {available_categories}")
        return None
    
    return requested_categories


def main():
    """
    Função principal
    """
    args = parse_arguments()
    
    # Ajusta nível de log se verboso
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validação de argumentos
    categories = validate_categories(args.categories)
    if args.categories and categories is None:
        sys.exit(1)
    
    # Ajusta max_results para modo de teste
    max_results = 2 if args.test_mode else args.max_results
    
    logger.info("="*60)
    logger.info("Iniciando Estratégia LexML Refinada v2.0")
    logger.info("="*60)
    
    if categories:
        logger.info(f"Categorias selecionadas: {categories}")
    else:
        logger.info("Usando todas as categorias disponíveis")
    
    logger.info(f"Máximo de resultados por categoria: {max_results}")
    
    if args.test_mode:
        logger.info("MODO DE TESTE ATIVADO - Resultados limitados")
    
    try:
        # Inicialização da estratégia
        logger.info("Inicializando sistema LexML refinado...")
        lexml_strategy = EnhancedLexMLStrategy()
        
        # Execução da busca
        logger.info("Executando busca abrangente...")
        search_results = lexml_strategy.execute_comprehensive_search(
            categories=categories,
            max_results_per_category=max_results,
            include_all_document_types=True
        )
        
        # Salvamento dos resultados
        logger.info("Salvando resultados...")
        output_file = lexml_strategy.save_enhanced_results(
            search_results, 
            filename=args.output
        )
        
        # Exibição de estatísticas
        stats = search_results['statistics']
        execution_summary = stats['execution_summary']
        quality_metrics = stats['quality_metrics']
        
        print("\n" + "="*60)
        print("RESULTADOS DA EXECUÇÃO")
        print("="*60)
        print(f"✅ Busca concluída com sucesso!")
        print(f"📁 Resultados salvos em: {output_file}")
        print(f"📊 Documentos únicos encontrados: {execution_summary['unique_documents']}")
        print(f"🎯 Categorias processadas: {execution_summary['total_categories_searched']}")
        print(f"📈 Taxa de duplicatas: {execution_summary['duplicate_rate']:.1%}")
        
        if quality_metrics:
            print(f"🔍 Qualidade média geral: {quality_metrics.get('avg_overall', 0):.2f}")
            print(f"📋 Completude média: {quality_metrics.get('avg_completeness', 0):.2f}")
            print(f"🎯 Precisão média: {quality_metrics.get('avg_accuracy', 0):.2f}")
            print(f"🔗 Consistência média: {quality_metrics.get('avg_consistency', 0):.2f}")
            print(f"📌 Relevância média: {quality_metrics.get('avg_relevance', 0):.2f}")
        
        # Distribuição por categoria
        print("\n📊 DISTRIBUIÇÃO POR CATEGORIA PRINCIPAL:")
        classification_dist = stats['classification_distribution']
        for category, count in classification_dist['main_categories'].items():
            print(f"   {category}: {count} documentos")
        
        # Distribuição por qualidade
        print("\n🏆 DISTRIBUIÇÃO POR QUALIDADE:")
        for grade, count in classification_dist['quality_levels'].items():
            print(f"   Nota {grade}: {count} documentos")
        
        # Erros de processamento
        processing_errors = stats.get('processing_errors', 0)
        if processing_errors > 0:
            print(f"\n⚠️  Erros de processamento: {processing_errors}")
        
        print("\n" + "="*60)
        print("EXECUÇÃO CONCLUÍDA COM SUCESSO!")
        print("="*60)
        
    except KeyboardInterrupt:
        logger.info("\nExecução interrompida pelo usuário")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"Erro na execução: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()