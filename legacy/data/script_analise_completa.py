#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de Análise Completa - Projeto MACK PESQUISA CEMAPI
Script reutilizável para análise abrangente de políticas públicas de transporte

Uso: python3 script_analise_completa.py [caminho_dataset.xlsx]
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import sys
import os
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class AnalisadorPoliticasTransporte:
    """
    Classe principal para análise de políticas públicas de transporte
    """
    
    def __init__(self, caminho_dataset):
        """
        Inicializa o analisador com o dataset
        
        Args:
            caminho_dataset (str): Caminho para o arquivo Excel do dataset
        """
        self.caminho_dataset = caminho_dataset
        self.df = None
        self.df_temporal = None
        self.resultados = {}
        
        # Configuração de estilo
        plt.style.use('seaborn-v0_8')
        plt.rcParams['figure.figsize'] = (14, 10)
        plt.rcParams['font.size'] = 12
        
        # Criar diretórios de saída
        self.dir_saida = f"analise_completa_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.dir_saida, exist_ok=True)
        os.makedirs(f"{self.dir_saida}/visualizacoes", exist_ok=True)
        os.makedirs(f"{self.dir_saida}/dados", exist_ok=True)
        os.makedirs(f"{self.dir_saida}/relatorios", exist_ok=True)
    
    def carregar_dados(self):
        """Carrega e prepara os dados para análise"""
        print("📊 Carregando dataset...")
        try:
            self.df = pd.read_excel(self.caminho_dataset)
            print(f"✓ Dataset carregado: {len(self.df)} registros")
            
            # Extrair anos das URNs
            self.df['Ano'] = self.df['Urn'].apply(self._extrair_ano_urn)
            self.df_temporal = self.df[self.df['Ano'].notna()].copy()
            
            print(f"✓ Dados temporais: {len(self.df_temporal)} registros ({len(self.df_temporal)/len(self.df)*100:.1f}%)")
            
            return True
        except Exception as e:
            print(f"❌ Erro ao carregar dados: {e}")
            return False
    
    def _extrair_ano_urn(self, urn):
        """Extrai o ano da URN usando regex"""
        import re
        if pd.isna(urn):
            return None
        
        patterns = [
            r':(\d{4})-\d{2}-\d{2};',
            r':(\d{4});',
            r':(\d{4})-',
            r'(\d{4})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, str(urn))
            if match:
                ano = int(match.group(1))
                if 1850 <= ano <= 2024:
                    return ano
        return None
    
    def analise_temporal(self):
        """Executa análise temporal completa"""
        print("\n⏰ Executando análise temporal...")
        
        # Estatísticas anuais
        stats_anuais = self.df_temporal.groupby('Ano').size().reset_index(name='Documentos')
        
        # Análise por décadas
        self.df_temporal['Decada'] = (self.df_temporal['Ano'] // 10) * 10
        stats_decadas = self.df_temporal.groupby('Decada').size().reset_index(name='Documentos')
        stats_decadas['Periodo'] = stats_decadas['Decada'].astype(int).astype(str) + 's'
        
        # Análise por períodos históricos
        self.df_temporal['Periodo_Historico'] = self.df_temporal['Ano'].apply(self._classificar_periodo)
        stats_periodos = self.df_temporal.groupby('Periodo_Historico').size().reset_index(name='Documentos')
        
        # Salvar resultados
        stats_anuais.to_csv(f"{self.dir_saida}/dados/analise_temporal_anual.csv", index=False)
        stats_decadas.to_csv(f"{self.dir_saida}/dados/analise_temporal_decadas.csv", index=False)
        stats_periodos.to_csv(f"{self.dir_saida}/dados/analise_temporal_periodos.csv", index=False)
        
        self.resultados['temporal'] = {
            'anual': stats_anuais,
            'decadas': stats_decadas,
            'periodos': stats_periodos
        }
        
        print(f"✓ Análise temporal concluída: {len(stats_anuais)} anos analisados")
    
    def _classificar_periodo(self, ano):
        """Classifica o ano em períodos históricos"""
        if ano < 1930:
            return "República Velha (até 1930)"
        elif ano < 1945:
            return "Era Vargas (1930-1945)"
        elif ano < 1964:
            return "República Populista (1945-1964)"
        elif ano < 1985:
            return "Regime Militar (1964-1985)"
        elif ano < 1995:
            return "Nova República I (1985-1995)"
        elif ano < 2003:
            return "Era FHC (1995-2003)"
        elif ano < 2011:
            return "Era Lula (2003-2011)"
        elif ano < 2016:
            return "Era Dilma (2011-2016)"
        elif ano < 2019:
            return "Era Temer (2016-2019)"
        elif ano < 2023:
            return "Era Bolsonaro (2019-2023)"
        else:
            return "Era Lula III (2023-)"
    
    def analise_institucional(self):
        """Executa análise institucional completa"""
        print("\n🏛️ Executando análise institucional...")
        
        # Limpeza de nomes de órgãos
        self.df['Justice_Clean'] = self.df['Justice'].apply(self._limpar_nome_orgao)
        
        # Estatísticas por órgão
        stats_orgaos = self.df['Justice_Clean'].value_counts().reset_index()
        stats_orgaos.columns = ['Orgao', 'Documentos']
        stats_orgaos['Percentual'] = (stats_orgaos['Documentos'] / len(self.df) * 100).round(2)
        
        # Análise por região
        stats_regiao = self.df['Region'].value_counts().reset_index()
        stats_regiao.columns = ['Regiao', 'Documentos']
        stats_regiao['Percentual'] = (stats_regiao['Documentos'] / len(self.df) * 100).round(2)
        
        # Salvar resultados
        stats_orgaos.to_csv(f"{self.dir_saida}/dados/analise_orgaos.csv", index=False)
        stats_regiao.to_csv(f"{self.dir_saida}/dados/analise_regioes.csv", index=False)
        
        self.resultados['institucional'] = {
            'orgaos': stats_orgaos,
            'regioes': stats_regiao
        }
        
        print(f"✓ Análise institucional concluída: {len(stats_orgaos)} órgãos identificados")
    
    def _limpar_nome_orgao(self, nome):
        """Limpa e padroniza nomes de órgãos"""
        if pd.isna(nome):
            return "Não Identificado"
        
        nome = str(nome).strip()
        padronizacoes = {
            'Agência Nacional de EnergiaElétrica': 'Agência Nacional de Energia Elétrica',
            'ANEEL': 'Agência Nacional de Energia Elétrica',
            'ANTT': 'Agência Nacional de Transportes Terrestres',
            'ANP': 'Agência Nacional do Petróleo',
            'CONTRAN': 'Conselho Nacional de Trânsito',
            'ANA': 'Agência Nacional de Águas',
        }
        
        for original, padronizado in padronizacoes.items():
            if original.lower() in nome.lower():
                return padronizado
        return nome
    
    def analise_tipos_documento(self):
        """Executa análise de tipos de documento"""
        print("\n📄 Executando análise de tipos de documento...")
        
        # Estatísticas por tipo
        stats_tipos = self.df['Urn_type'].value_counts().reset_index()
        stats_tipos.columns = ['Tipo', 'Documentos']
        stats_tipos['Percentual'] = (stats_tipos['Documentos'] / len(self.df) * 100).round(2)
        
        # Análise temática básica
        temas_transporte = {
            'energia': ['energia', 'energético', 'energética', 'elétrica'],
            'combustível': ['combustível', 'combustíveis', 'gasolina', 'diesel', 'etanol'],
            'transporte': ['transporte', 'transportes', 'trânsito', 'veículo'],
            'ambiental': ['ambiental', 'ambiente', 'sustentável', 'emissão'],
            'regulação': ['regulação', 'agência', 'reguladora'],
        }
        
        stats_temas = {}
        for tema, palavras in temas_transporte.items():
            count = 0
            for palavra in palavras:
                count += self.df['Title'].str.lower().str.contains(palavra, na=False).sum()
            stats_temas[tema] = count
        
        # Salvar resultados
        stats_tipos.to_csv(f"{self.dir_saida}/dados/analise_tipos_documento.csv", index=False)
        
        temas_df = pd.DataFrame(list(stats_temas.items()), columns=['Tema', 'Ocorrencias'])
        temas_df.to_csv(f"{self.dir_saida}/dados/analise_tematica.csv", index=False)
        
        self.resultados['tipos'] = {
            'tipos': stats_tipos,
            'temas': temas_df
        }
        
        print(f"✓ Análise de tipos concluída: {len(stats_tipos)} tipos identificados")
    
    def criar_visualizacoes(self):
        """Cria todas as visualizações"""
        print("\n📈 Criando visualizações...")
        
        # 1. Evolução temporal
        fig, ax = plt.subplots(figsize=(16, 8))
        stats_anuais = self.resultados['temporal']['anual']
        ax.plot(stats_anuais['Ano'], stats_anuais['Documentos'], 
                linewidth=3, marker='o', markersize=6, color='#2E86AB')
        ax.fill_between(stats_anuais['Ano'], stats_anuais['Documentos'], alpha=0.3, color='#2E86AB')
        ax.set_title('Evolução da Produção Normativa no Transporte', fontsize=18, fontweight='bold')
        ax.set_xlabel('Ano')
        ax.set_ylabel('Número de Documentos')
        ax.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(f"{self.dir_saida}/visualizacoes/evolucao_temporal.png", dpi=300, bbox_inches='tight')
        plt.close()
        
        # 2. Top órgãos
        fig, ax = plt.subplots(figsize=(16, 10))
        top_orgaos = self.resultados['institucional']['orgaos'].head(15)
        bars = ax.barh(range(len(top_orgaos)), top_orgaos['Documentos'], color='#C73E1D', alpha=0.8)
        ax.set_yticks(range(len(top_orgaos)))
        ax.set_yticklabels([org[:50] + '...' if len(org) > 50 else org for org in top_orgaos['Orgao']])
        ax.set_xlabel('Número de Documentos')
        ax.set_title('Top 15 Órgãos Emissores', fontsize=18, fontweight='bold')
        ax.grid(True, alpha=0.3, axis='x')
        plt.tight_layout()
        plt.savefig(f"{self.dir_saida}/visualizacoes/top_orgaos.png", dpi=300, bbox_inches='tight')
        plt.close()
        
        # 3. Tipos de documento
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 8))
        stats_tipos = self.resultados['tipos']['tipos']
        
        # Pizza
        colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7']
        ax1.pie(stats_tipos['Documentos'], labels=stats_tipos['Tipo'], autopct='%1.1f%%', 
                startangle=90, colors=colors)
        ax1.set_title('Distribuição por Tipo de Documento')
        
        # Barras
        ax2.bar(stats_tipos['Tipo'], stats_tipos['Documentos'], color=colors[:len(stats_tipos)])
        ax2.set_title('Quantidade por Tipo de Documento')
        ax2.set_ylabel('Número de Documentos')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(f"{self.dir_saida}/visualizacoes/tipos_documento.png", dpi=300, bbox_inches='tight')
        plt.close()
        
        print("✓ Visualizações criadas com sucesso")
    
    def gerar_relatorio_executivo(self):
        """Gera relatório executivo das análises"""
        print("\n📋 Gerando relatório executivo...")
        
        with open(f"{self.dir_saida}/relatorios/relatorio_executivo.txt", 'w', encoding='utf-8') as f:
            f.write("RELATÓRIO EXECUTIVO - ANÁLISE DE POLÍTICAS PÚBLICAS DE TRANSPORTE\n")
            f.write("="*70 + "\n\n")
            f.write(f"Data da análise: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
            f.write(f"Dataset analisado: {self.caminho_dataset}\n\n")
            
            # Resumo geral
            f.write("RESUMO GERAL:\n")
            f.write(f"- Total de documentos: {len(self.df):,}\n")
            f.write(f"- Documentos com dados temporais: {len(self.df_temporal):,} ({len(self.df_temporal)/len(self.df)*100:.1f}%)\n")
            f.write(f"- Período coberto: {self.df_temporal['Ano'].min():.0f} - {self.df_temporal['Ano'].max():.0f}\n")
            f.write(f"- Órgãos identificados: {len(self.resultados['institucional']['orgaos'])}\n\n")
            
            # Principais achados temporais
            f.write("PRINCIPAIS ACHADOS TEMPORAIS:\n")
            stats_anuais = self.resultados['temporal']['anual']
            top_anos = stats_anuais.nlargest(5, 'Documentos')
            f.write("Top 5 anos com maior produção:\n")
            for _, row in top_anos.iterrows():
                f.write(f"  - {row['Ano']:.0f}: {row['Documentos']} documentos\n")
            
            # Principais órgãos
            f.write("\nPRINCIPAIS ÓRGÃOS EMISSORES:\n")
            top_orgaos = self.resultados['institucional']['orgaos'].head(10)
            for _, row in top_orgaos.iterrows():
                f.write(f"  - {row['Orgao']}: {row['Documentos']} docs ({row['Percentual']:.1f}%)\n")
            
            # Tipos de documento
            f.write("\nDISTRIBUIÇÃO POR TIPO:\n")
            for _, row in self.resultados['tipos']['tipos'].iterrows():
                f.write(f"  - {row['Tipo']}: {row['Documentos']} docs ({row['Percentual']:.1f}%)\n")
            
            # Análise temática
            f.write("\nANÁLISE TEMÁTICA:\n")
            for _, row in self.resultados['tipos']['temas'].iterrows():
                f.write(f"  - {row['Tema']}: {row['Ocorrencias']} ocorrências\n")
        
        print("✓ Relatório executivo gerado")
    
    def executar_analise_completa(self):
        """Executa todas as análises em sequência"""
        print("🚀 Iniciando análise completa do dataset...")
        print(f"📁 Resultados serão salvos em: {self.dir_saida}")
        
        if not self.carregar_dados():
            return False
        
        # Executar todas as análises
        self.analise_temporal()
        self.analise_institucional()
        self.analise_tipos_documento()
        self.criar_visualizacoes()
        self.gerar_relatorio_executivo()
        
        print(f"\n✅ Análise completa concluída!")
        print(f"📊 Resultados disponíveis em: {self.dir_saida}")
        print(f"📈 Visualizações: {self.dir_saida}/visualizacoes/")
        print(f"📋 Relatórios: {self.dir_saida}/relatorios/")
        print(f"💾 Dados processados: {self.dir_saida}/dados/")
        
        return True

def main():
    """Função principal"""
    if len(sys.argv) > 1:
        caminho_dataset = sys.argv[1]
    else:
        caminho_dataset = '/home/ubuntu/upload/dataset_14072025.xlsx'
    
    if not os.path.exists(caminho_dataset):
        print(f"❌ Arquivo não encontrado: {caminho_dataset}")
        print("Uso: python3 script_analise_completa.py [caminho_dataset.xlsx]")
        return
    
    analisador = AnalisadorPoliticasTransporte(caminho_dataset)
    analisador.executar_analise_completa()

if __name__ == "__main__":
    main()

