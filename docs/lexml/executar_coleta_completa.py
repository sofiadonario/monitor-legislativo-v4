#!/usr/bin/env python3
"""
Script para executar coleta completa do LexML com todos os termos de busca
Baseado no arquivo de termos fornecido pelo usuário

Desenvolvido por: Manus AI
Data: 2025-07-14
"""

import sys
import os
sys.path.append('/home/ubuntu')

from lexml_scraper_final_corrigido import LexMLScraperFinalCorrigido, search_multiple_terms
from datetime import datetime
import logging

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('coleta_completa.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_search_terms():
    """
    Carrega termos de busca do arquivo fornecido pelo usuário
    """
    # Termos baseados no arquivo TermosdeBuscaparaMonitorLegislativo-TransportedeCarga.txt
    terms = [
        # Combustíveis e Energia
        "diesel", "gasolina", "etanol", "biodiesel", "gás natural", "GNV", "GNC",
        "biometano", "hidrogênio", "HVO", "combustível sintético", "combustível do futuro",
        "descarbonização", "transição energética", "energia renovável",
        
        # Transporte e Logística
        "transporte de carga", "transporte rodoviário", "transporte ferroviário",
        "transporte aquaviário", "transporte multimodal", "logística", "frete",
        "cabotagem", "navegação interior", "hidrovia", "ferrovia", "rodovia",
        
        # Veículos e Tecnologia
        "veículo elétrico", "veículo híbrido", "veículo autônomo", "caminhão elétrico",
        "ônibus elétrico", "eletrificação", "bateria", "carregamento", "infraestrutura de recarga",
        "telemetria", "rastreamento", "conversão veicular", "retrofit",
        
        # Regulamentação e Órgãos
        "CONTRAN", "ANTT", "ANP", "ANA", "ANEEL", "IBAMA", "DNIT", "DENATRAN",
        "CNPE", "CCEE", "ONS", "EPE", "Ministério dos Transportes", "MME",
        
        # Programas e Políticas
        "Rota 2030", "Paten", "Lei do Combustível do Futuro", "Marco do Gás",
        "Novo Marco do Saneamento", "Renovabio", "PNPB", "Proálcool",
        "incentivo fiscal", "tributação", "ICMS", "PIS", "COFINS", "CIDE",
        
        # Meio Ambiente e Sustentabilidade
        "emissão", "poluição", "sustentabilidade", "carbono neutro", "pegada de carbono",
        "licenciamento ambiental", "impacto ambiental", "mudança climática",
        "acordo de Paris", "NDC", "inventário de emissões",
        
        # Segurança e Qualidade
        "segurança viária", "acidente", "fiscalização", "inspeção veicular",
        "qualidade do combustível", "adulteração", "ANP", "Inmetro",
        "certificação", "homologação", "recall",
        
        # Economia e Mercado
        "preço do combustível", "política de preços", "subsídio", "financiamento",
        "BNDES", "crédito", "investimento", "infraestrutura", "concessão",
        "PPP", "marco regulatório", "agência reguladora",
        
        # Inovação e P&D
        "pesquisa e desenvolvimento", "inovação", "tecnologia", "startup",
        "incubadora", "aceleradora", "patent", "propriedade intelectual",
        "transferência de tecnologia", "cooperação internacional"
    ]
    
    logger.info(f"Carregados {len(terms)} termos de busca")
    return terms

def main():
    """
    Função principal para executar coleta completa
    """
    print("="*60)
    print("COLETA COMPLETA LEXML - TRANSPORTE DE CARGA")
    print("="*60)
    print(f"Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Carregar termos de busca
    terms = load_search_terms()
    print(f"Total de termos: {len(terms)}")
    
    # Configurar limites (remover para coleta completa)
    max_results_per_term = None  # None = todos os resultados
    
    print(f"Limite por termo: {'Todos os resultados' if max_results_per_term is None else max_results_per_term}")
    
    # Executar coleta
    try:
        search_multiple_terms(terms, max_results_per_term)
        print("\\n" + "="*60)
        print("COLETA COMPLETA FINALIZADA COM SUCESSO!")
        print("="*60)
        
    except KeyboardInterrupt:
        print("\\n" + "="*60)
        print("COLETA INTERROMPIDA PELO USUÁRIO")
        print("="*60)
        
    except Exception as e:
        logger.error(f"Erro na coleta completa: {str(e)}")
        print("\\n" + "="*60)
        print("ERRO NA COLETA COMPLETA")
        print("="*60)
        print(f"Erro: {str(e)}")
    
    print(f"Fim: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()

