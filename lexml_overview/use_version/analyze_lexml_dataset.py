#!/usr/bin/env python3
"""
Enhanced script to analyze the LexML dataset for transport regulation
Based on the advanced analytics prompt requirements
"""

import pandas as pd
import numpy as np
from datetime import datetime
import json
import os
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

class LexMLDatasetAnalyzer:
    """Comprehensive analyzer for LexML transport regulation dataset"""
    
    def __init__(self, filepath):
        self.filepath = filepath
        self.datasets = {}
        self.analysis_results = {}
        
    def load_dataset(self):
        """Load all sheets from the Excel file"""
        print("="*80)
        print("ANÁLISE AVANÇADA DO DATASET LEXL - TRANSPORTE DE CARGA")
        print("="*80)
        
        try:
            print(f"\nCarregando arquivo: {self.filepath}")
            self.excel_file = pd.ExcelFile(self.filepath)
            print(f"✓ Arquivo carregado com sucesso!")
            print(f"✓ Sheets encontradas: {len(self.excel_file.sheet_names)}")
            
            # Load all sheets
            for sheet_name in self.excel_file.sheet_names:
                print(f"\nCarregando sheet: {sheet_name}")
                self.datasets[sheet_name] = pd.read_excel(self.filepath, sheet_name=sheet_name)
                print(f"  ✓ {self.datasets[sheet_name].shape[0]} registros carregados")
                
            return True
        except Exception as e:
            print(f"✗ Erro ao carregar arquivo: {str(e)}")
            return False
    
    def analyze_sheet(self, sheet_name, df):
        """Analyze individual sheet with comprehensive statistics"""
        print(f"\n{'='*60}")
        print(f"ANÁLISE DETALHADA: {sheet_name}")
        print(f"{'='*60}")
        
        analysis = {
            'sheet_name': sheet_name,
            'dimensions': df.shape,
            'columns': list(df.columns),
            'data_quality': {},
            'temporal_analysis': {},
            'content_analysis': {},
            'geographic_analysis': {}
        }
        
        # Basic statistics
        print(f"\n📊 ESTATÍSTICAS BÁSICAS:")
        print(f"  - Total de registros: {len(df)}")
        print(f"  - Total de colunas: {len(df.columns)}")
        print(f"  - Registros únicos: {df.drop_duplicates().shape[0]}")
        print(f"  - Duplicatas: {len(df) - df.drop_duplicates().shape[0]}")
        
        # Data quality analysis
        print(f"\n🔍 QUALIDADE DOS DADOS:")
        null_summary = {}
        for col in df.columns:
            null_count = df[col].isnull().sum()
            null_pct = (null_count / len(df)) * 100
            null_summary[col] = {'null_count': int(null_count), 'null_pct': round(null_pct, 2)}
            if null_pct > 0:
                print(f"  - {col}: {null_count} nulos ({null_pct:.1f}%)")
        analysis['data_quality']['null_summary'] = null_summary
        
        # Column standardization check
        expected_cols = ['Search_term', 'Date_searched', 'Url', 'Title', 'Urn', 'Urn_type', 
                        'Country', 'State', 'Municipality', 'Justice', 'Region', 'Court_class',
                        'Document_type_full', 'Enacting_date', 'Document_description', 'Document_summary']
        
        missing_cols = set(expected_cols) - set(df.columns)
        if missing_cols:
            print(f"  ⚠️  Colunas esperadas ausentes: {missing_cols}")
        
        # Temporal analysis
        if 'Enacting_date' in df.columns:
            print(f"\n📅 ANÁLISE TEMPORAL:")
            df_temp = df.copy()
            
            # Convert dates with multiple formats
            df_temp['Enacting_date_parsed'] = pd.to_datetime(df_temp['Enacting_date'], errors='coerce')
            valid_dates = df_temp['Enacting_date_parsed'].dropna()
            
            if len(valid_dates) > 0:
                date_range = (valid_dates.min(), valid_dates.max())
                print(f"  - Período coberto: {date_range[0].strftime('%Y-%m-%d')} a {date_range[1].strftime('%Y-%m-%d')}")
                print(f"  - Amplitude temporal: {(date_range[1] - date_range[0]).days} dias (~{(date_range[1] - date_range[0]).days/365:.1f} anos)")
                print(f"  - Documentos com data válida: {len(valid_dates)} ({len(valid_dates)/len(df)*100:.1f}%)")
                
                # Decade distribution
                df_temp['decade'] = (df_temp['Enacting_date_parsed'].dt.year // 10) * 10
                decade_dist = df_temp['decade'].value_counts().sort_index()
                
                print(f"\n  📊 Distribuição por década:")
                for decade, count in decade_dist.items():
                    if not pd.isna(decade):
                        print(f"    - {int(decade)}s: {count} documentos")
                
                # Year distribution for recent years
                recent_years = df_temp[df_temp['Enacting_date_parsed'].dt.year >= 2010]
                if len(recent_years) > 0:
                    year_dist = recent_years['Enacting_date_parsed'].dt.year.value_counts().sort_index()
                    print(f"\n  📈 Produção anual (2010-presente):")
                    for year, count in year_dist.items():
                        print(f"    - {int(year)}: {count} documentos")
                
                analysis['temporal_analysis'] = {
                    'date_range': (str(date_range[0]), str(date_range[1])),
                    'valid_dates_count': int(len(valid_dates)),
                    'decade_distribution': decade_dist.to_dict() if len(decade_dist) > 0 else {}
                }
        
        # Document type analysis
        if 'Document_type_full' in df.columns:
            print(f"\n📋 TIPOS DE DOCUMENTO:")
            doc_types = df['Document_type_full'].value_counts().head(10)
            for doc_type, count in doc_types.items():
                pct = (count / len(df)) * 100
                print(f"  - {doc_type}: {count} ({pct:.1f}%)")
            analysis['content_analysis']['document_types'] = doc_types.to_dict()
        
        # URN type analysis
        if 'Urn_type' in df.columns:
            print(f"\n🏷️ CATEGORIAS URN:")
            urn_types = df['Urn_type'].value_counts()
            for urn_type, count in urn_types.items():
                pct = (count / len(df)) * 100
                print(f"  - {urn_type}: {count} ({pct:.1f}%)")
            analysis['content_analysis']['urn_types'] = urn_types.to_dict()
        
        # Geographic analysis
        if 'State' in df.columns:
            print(f"\n🗺️ DISTRIBUIÇÃO GEOGRÁFICA:")
            state_dist = df['State'].value_counts().head(10)
            federal_count = df[df['State'].isna() | (df['State'] == 'BR')].shape[0]
            print(f"  - Documentos federais: {federal_count} ({federal_count/len(df)*100:.1f}%)")
            print(f"\n  Estados mais representados:")
            for state, count in state_dist.items():
                if pd.notna(state) and state != 'BR':
                    print(f"    - {state}: {count} documentos")
            analysis['geographic_analysis']['state_distribution'] = state_dist.to_dict()
        
        # Search term analysis
        if 'Search_term' in df.columns:
            print(f"\n🔍 TERMOS DE BUSCA MAIS FREQUENTES:")
            search_terms = df['Search_term'].value_counts().head(10)
            for term, count in search_terms.items():
                print(f"  - '{term}': {count} ocorrências")
            analysis['content_analysis']['top_search_terms'] = search_terms.to_dict()
        
        return analysis
    
    def generate_global_analysis(self):
        """Generate comprehensive analysis across all sheets"""
        print(f"\n{'='*80}")
        print("ANÁLISE GLOBAL DO DATASET")
        print(f"{'='*80}")
        
        # Combine all dataframes
        all_data = pd.concat(self.datasets.values(), ignore_index=True)
        
        print(f"\n📊 ESTATÍSTICAS GLOBAIS:")
        print(f"  - Total de registros (todas as sheets): {len(all_data)}")
        print(f"  - Registros únicos globais: {all_data.drop_duplicates().shape[0]}")
        print(f"  - Taxa de duplicação global: {(1 - all_data.drop_duplicates().shape[0]/len(all_data))*100:.1f}%")
        
        # Sheet comparison
        print(f"\n📑 COMPARAÇÃO ENTRE SHEETS:")
        sheet_stats = []
        for sheet_name, df in self.datasets.items():
            stats = {
                'sheet': sheet_name,
                'records': len(df),
                'pct_of_total': round((len(df) / len(all_data)) * 100, 2)
            }
            sheet_stats.append(stats)
            print(f"  - {sheet_name}: {stats['records']} registros ({stats['pct_of_total']}%)")
        
        # Temporal coverage
        if 'Enacting_date' in all_data.columns:
            all_data['Enacting_date_parsed'] = pd.to_datetime(all_data['Enacting_date'], errors='coerce')
            valid_dates = all_data['Enacting_date_parsed'].dropna()
            if len(valid_dates) > 0:
                print(f"\n📅 COBERTURA TEMPORAL GLOBAL:")
                print(f"  - Período total: {valid_dates.min().year} - {valid_dates.max().year}")
                print(f"  - Amplitude: {valid_dates.max().year - valid_dates.min().year} anos")
        
        # Document type distribution
        if 'Urn_type' in all_data.columns:
            print(f"\n📊 DISTRIBUIÇÃO GLOBAL POR TIPO:")
            global_types = all_data['Urn_type'].value_counts()
            for doc_type, count in global_types.items():
                pct = (count / len(all_data)) * 100
                print(f"  - {doc_type}: {count} ({pct:.1f}%)")
        
        return {
            'total_records': len(all_data),
            'unique_records': all_data.drop_duplicates().shape[0],
            'sheet_statistics': sheet_stats,
            'temporal_coverage': {
                'min_year': int(valid_dates.min().year) if len(valid_dates) > 0 else None,
                'max_year': int(valid_dates.max().year) if len(valid_dates) > 0 else None
            } if 'Enacting_date' in all_data.columns else None
        }
    
    def save_analysis(self):
        """Save comprehensive analysis to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"lexml_comprehensive_analysis_{timestamp}.json"
        
        analysis_output = {
            'timestamp': timestamp,
            'file_analyzed': self.filepath,
            'sheets': list(self.datasets.keys()),
            'total_records': sum(len(df) for df in self.datasets.values()),
            'sheet_analyses': self.analysis_results,
            'global_analysis': self.generate_global_analysis()
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(analysis_output, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n✅ ANÁLISE SALVA EM: {output_file}")
        return output_file
    
    def run_complete_analysis(self):
        """Execute complete dataset analysis"""
        if not self.load_dataset():
            return None, None
        
        # Analyze each sheet
        for sheet_name, df in self.datasets.items():
            self.analysis_results[sheet_name] = self.analyze_sheet(sheet_name, df)
        
        # Generate and save global analysis
        output_file = self.save_analysis()
        
        print(f"\n{'='*80}")
        print("ANÁLISE CONCLUÍDA COM SUCESSO!")
        print(f"{'='*80}")
        print(f"\n📊 Resumo Final:")
        print(f"  - Sheets analisadas: {len(self.datasets)}")
        print(f"  - Total de registros: {sum(len(df) for df in self.datasets.values())}")
        print(f"  - Arquivo de análise: {output_file}")
        
        return self.datasets, self.analysis_results


def main():
    # Updated filepath to the correct location
    filepath = "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/lexml_overview/use_version/dataset_14072025.xlsx"
    
    # Check if file exists
    if not os.path.exists(filepath):
        print(f"❌ Erro: Arquivo não encontrado em {filepath}")
        return
    
    # Run analysis
    analyzer = LexMLDatasetAnalyzer(filepath)
    datasets, results = analyzer.run_complete_analysis()
    
    return datasets, results


if __name__ == "__main__":
    datasets, results = main()