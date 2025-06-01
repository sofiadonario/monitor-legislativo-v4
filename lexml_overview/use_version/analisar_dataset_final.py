#!/usr/bin/env python3
"""
Script para analisar o dataset final processado pela equipe de pesquisa
"""

import pandas as pd
import numpy as np
from datetime import datetime
import json

def analisar_dataset_excel(filepath):
    """
    Analisa o dataset final em formato Excel
    """
    print("="*60)
    print("ANÁLISE DO DATASET FINAL PROCESSADO")
    print("="*60)
    
    try:
        # Ler arquivo Excel
        print(f"Carregando arquivo: {filepath}")
        
        # Verificar sheets disponíveis
        excel_file = pd.ExcelFile(filepath)
        print(f"Sheets disponíveis: {excel_file.sheet_names}")
        
        # Analisar cada sheet
        datasets = {}
        for sheet_name in excel_file.sheet_names:
            print(f"\n--- ANÁLISE DA SHEET: {sheet_name} ---")
            
            df = pd.read_excel(filepath, sheet_name=sheet_name)
            datasets[sheet_name] = df
            
            print(f"Dimensões: {df.shape[0]} linhas × {df.shape[1]} colunas")
            print(f"Colunas: {list(df.columns)}")
            
            # Estatísticas básicas
            print(f"\nEstatísticas básicas:")
            print(f"- Registros totais: {len(df)}")
            print(f"- Registros únicos: {df.drop_duplicates().shape[0]}")
            print(f"- Valores nulos por coluna:")
            
            for col in df.columns:
                null_count = df[col].isnull().sum()
                null_pct = (null_count / len(df)) * 100
                print(f"  {col}: {null_count} ({null_pct:.1f}%)")
            
            # Análise de tipos de dados
            print(f"\nTipos de dados:")
            for col in df.columns:
                dtype = df[col].dtype
                unique_count = df[col].nunique()
                print(f"  {col}: {dtype} ({unique_count} valores únicos)")
            
            # Análise de campos específicos se existirem
            if 'urn_type' in df.columns:
                print(f"\nDistribuição por tipo de documento:")
                type_dist = df['urn_type'].value_counts()
                for tipo, count in type_dist.items():
                    pct = (count / len(df)) * 100
                    print(f"  {tipo}: {count} ({pct:.1f}%)")
            
            if 'enacting_date' in df.columns:
                print(f"\nAnálise temporal:")
                df_temp = df.copy()
                df_temp['enacting_date'] = pd.to_datetime(df_temp['enacting_date'], errors='coerce')
                date_range = df_temp['enacting_date'].dropna()
                if len(date_range) > 0:
                    print(f"  Período: {date_range.min()} a {date_range.max()}")
                    print(f"  Documentos com data: {len(date_range)} ({len(date_range)/len(df)*100:.1f}%)")
                    
                    # Distribuição por década
                    df_temp['decade'] = (df_temp['enacting_date'].dt.year // 10) * 10
                    decade_dist = df_temp['decade'].value_counts().sort_index()
                    print(f"  Distribuição por década:")
                    for decade, count in decade_dist.items():
                        if not pd.isna(decade):
                            print(f"    {int(decade)}s: {count}")
            
            if 'search_term' in df.columns:
                print(f"\nTermos de busca mais frequentes:")
                term_dist = df['search_term'].value_counts().head(10)
                for term, count in term_dist.items():
                    print(f"  '{term}': {count}")
            
            if 'document_type_full' in df.columns:
                print(f"\nTipos de documento detalhados:")
                doc_dist = df['document_type_full'].value_counts().head(15)
                for doc_type, count in doc_dist.items():
                    print(f"  {doc_type}: {count}")
            
            # Amostra dos dados
            print(f"\nAmostra dos dados (primeiras 3 linhas):")
            print(df.head(3).to_string())
            
        # Salvar análise em arquivo
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        analysis_file = f"analise_dataset_{timestamp}.json"
        
        analysis_summary = {
            'timestamp': timestamp,
            'sheets': list(datasets.keys()),
            'total_records': sum(len(df) for df in datasets.values()),
            'columns': {sheet: list(df.columns) for sheet, df in datasets.items()},
            'shapes': {sheet: df.shape for sheet, df in datasets.items()}
        }
        
        with open(analysis_file, 'w', encoding='utf-8') as f:
            json.dump(analysis_summary, f, indent=2, ensure_ascii=False)
        
        print(f"\n{'='*60}")
        print(f"ANÁLISE SALVA EM: {analysis_file}")
        print(f"{'='*60}")
        
        return datasets, analysis_summary
        
    except Exception as e:
        print(f"Erro na análise: {str(e)}")
        return None, None

def main():
    filepath = "/home/ubuntu/upload/CSV-Ajustado.xlsx"
    datasets, summary = analisar_dataset_excel(filepath)
    
    if datasets:
        print(f"\nAnálise concluída com sucesso!")
        print(f"Total de sheets analisadas: {len(datasets)}")
        print(f"Total de registros: {sum(len(df) for df in datasets.values())}")

if __name__ == "__main__":
    main()

