#!/usr/bin/env python3
"""
Script de Validação das Correções LexML
Autor: Manus AI
Data: 2025-07-12

Valida se todas as correções implementadas estão funcionando adequadamente.
"""

import pandas as pd
import re
from datetime import datetime
from lexml_strategy_corrected import LexMLStrategyCorrected

def validate_date_extraction():
    """Valida se a extração de datas está funcionando."""
    print("=== Validação da Extração de Datas ===")
    
    strategy = LexMLStrategyCorrected()
    
    # Testa com diferentes termos
    test_terms = ["decreto", "lei", "resolução"]
    total_results = 0
    total_with_dates = 0
    
    for term in test_terms:
        print(f"\nTestando termo: '{term}'")
        results = strategy.search_documents(term, max_results=10)
        
        if results:
            df = pd.DataFrame(results)
            dates_extracted = df[df['enacting_date'].str.len() > 0]
            
            print(f"  Resultados: {len(df)}")
            print(f"  Com datas: {len(dates_extracted)}")
            print(f"  Taxa de extração: {len(dates_extracted)/len(df)*100:.1f}%")
            
            total_results += len(df)
            total_with_dates += len(dates_extracted)
            
            # Valida formato das datas
            for date_str in dates_extracted['enacting_date'].head(3):
                if re.match(r'\d{4}-\d{2}-\d{2}', date_str):
                    print(f"  ✓ Data válida: {date_str}")
                else:
                    print(f"  ✗ Data inválida: {date_str}")
    
    overall_rate = total_with_dates / total_results * 100 if total_results > 0 else 0
    print(f"\n📊 Taxa geral de extração de datas: {overall_rate:.1f}% ({total_with_dates}/{total_results})")
    
    return overall_rate >= 90  # Considera sucesso se >= 90%

def validate_urn_classification():
    """Valida se a classificação de URNs está correta."""
    print("\n=== Validação da Classificação de URNs ===")
    
    strategy = LexMLStrategyCorrected()
    
    # Testa com termos que sabemos ter tipos específicos
    test_cases = [
        ("decreto", "legislation"),
        ("lei", "legislation"),
        ("medida provisória", "legislation"),
        ("acórdão", "jurisprudence"),
        ("artigo", "doctrine")
    ]
    
    classification_correct = True
    
    for term, expected_type in test_cases:
        print(f"\nTestando '{term}' (esperado: {expected_type})")
        results = strategy.search_documents(term, max_results=5)
        
        if results:
            df = pd.DataFrame(results)
            type_counts = df['urn_type'].value_counts()
            
            print(f"  Distribuição: {type_counts.to_dict()}")
            
            # Verifica se o tipo esperado é predominante
            if expected_type in type_counts and type_counts[expected_type] >= len(df) * 0.7:
                print(f"  ✓ Classificação correta ({type_counts[expected_type]}/{len(df)})")
            else:
                print(f"  ✗ Classificação incorreta")
                classification_correct = False
    
    return classification_correct

def validate_date_range():
    """Valida se o range de datas está baseado nos documentos."""
    print("\n=== Validação do Range de Datas ===")
    
    strategy = LexMLStrategyCorrected()
    
    # Busca documentos
    results = strategy.search_documents("decreto", max_results=20)
    
    if results:
        df = pd.DataFrame(results)
        date_range = strategy.get_date_range_from_results(df)
        
        print(f"Range calculado: {date_range}")
        
        # Valida se o range faz sentido
        if date_range['total_with_dates'] > 0:
            min_year = int(date_range['min_date'][:4])
            max_year = int(date_range['max_date'][:4])
            current_year = datetime.now().year
            
            # Verifica se as datas são razoáveis
            if 1800 <= min_year <= current_year and min_year <= max_year <= current_year:
                print("✓ Range de datas válido")
                return True
            else:
                print("✗ Range de datas inválido")
                return False
    
    print("✗ Não foi possível calcular range")
    return False

def validate_data_completeness():
    """Valida se os dados estão completos."""
    print("\n=== Validação da Completude dos Dados ===")
    
    strategy = LexMLStrategyCorrected()
    results = strategy.search_documents("decreto", max_results=10)
    
    if not results:
        print("✗ Nenhum resultado encontrado")
        return False
    
    df = pd.DataFrame(results)
    
    # Campos obrigatórios
    required_fields = ['search_term', 'urn', 'title', 'enacting_date']
    
    completeness_scores = {}
    
    for field in required_fields:
        if field in df.columns:
            non_empty = df[df[field].astype(str).str.len() > 0]
            score = len(non_empty) / len(df) * 100
            completeness_scores[field] = score
            print(f"  {field}: {score:.1f}% completo ({len(non_empty)}/{len(df)})")
        else:
            completeness_scores[field] = 0
            print(f"  {field}: Campo ausente")
    
    # Considera sucesso se todos os campos têm >= 80% de completude
    all_complete = all(score >= 80 for score in completeness_scores.values())
    
    if all_complete:
        print("✓ Dados suficientemente completos")
    else:
        print("✗ Dados incompletos")
    
    return all_complete

def compare_with_original():
    """Compara resultados com a estratégia original."""
    print("\n=== Comparação com Estratégia Original ===")
    
    # Simula resultados da estratégia original (baseado nos dados fornecidos)
    original_stats = {
        'total_documents': 1904,
        'documents_with_dates': 201,
        'date_extraction_rate': 201/1904*100,
        'legislation_count': 112,
        'doctrine_count': 1591,
        'jurisprudence_count': 200
    }
    
    # Testa estratégia corrigida
    strategy = LexMLStrategyCorrected()
    results = strategy.search_documents("decreto", max_results=50)
    
    if results:
        df = pd.DataFrame(results)
        dates_extracted = df[df['enacting_date'].str.len() > 0]
        type_counts = df['urn_type'].value_counts()
        
        corrected_stats = {
            'total_documents': len(df),
            'documents_with_dates': len(dates_extracted),
            'date_extraction_rate': len(dates_extracted)/len(df)*100,
            'legislation_count': type_counts.get('legislation', 0),
            'doctrine_count': type_counts.get('doctrine', 0),
            'jurisprudence_count': type_counts.get('jurisprudence', 0)
        }
        
        print("Comparação:")
        print(f"  Taxa de extração de datas:")
        print(f"    Original: {original_stats['date_extraction_rate']:.1f}%")
        print(f"    Corrigida: {corrected_stats['date_extraction_rate']:.1f}%")
        print(f"    Melhoria: +{corrected_stats['date_extraction_rate'] - original_stats['date_extraction_rate']:.1f}%")
        
        print(f"  Classificação de decretos:")
        print(f"    Original: {original_stats['doctrine_count']} como doutrina (incorreto)")
        print(f"    Corrigida: {corrected_stats['legislation_count']} como legislação (correto)")
        
        # Considera sucesso se houve melhoria significativa
        improvement = corrected_stats['date_extraction_rate'] > original_stats['date_extraction_rate'] + 50
        correct_classification = corrected_stats['legislation_count'] > corrected_stats['doctrine_count']
        
        if improvement and correct_classification:
            print("✓ Melhorias significativas confirmadas")
            return True
        else:
            print("✗ Melhorias insuficientes")
            return False
    
    return False

def main():
    """Executa todas as validações."""
    print("🔍 VALIDAÇÃO COMPLETA DAS CORREÇÕES LEXML")
    print("=" * 50)
    
    validations = [
        ("Extração de Datas", validate_date_extraction),
        ("Classificação de URNs", validate_urn_classification),
        ("Range de Datas", validate_date_range),
        ("Completude dos Dados", validate_data_completeness),
        ("Comparação com Original", compare_with_original)
    ]
    
    results = {}
    
    for name, validation_func in validations:
        try:
            results[name] = validation_func()
        except Exception as e:
            print(f"✗ Erro na validação '{name}': {e}")
            results[name] = False
    
    print("\n" + "=" * 50)
    print("📋 RESUMO DAS VALIDAÇÕES")
    print("=" * 50)
    
    passed = 0
    for name, result in results.items():
        status = "✓ PASSOU" if result else "✗ FALHOU"
        print(f"{name}: {status}")
        if result:
            passed += 1
    
    success_rate = passed / len(results) * 100
    print(f"\n🎯 Taxa de Sucesso: {success_rate:.1f}% ({passed}/{len(results)})")
    
    if success_rate >= 80:
        print("🎉 CORREÇÕES VALIDADAS COM SUCESSO!")
    else:
        print("⚠️  CORREÇÕES PRECISAM DE AJUSTES")
    
    return success_rate >= 80

if __name__ == "__main__":
    main()

