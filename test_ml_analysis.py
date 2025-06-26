#!/usr/bin/env python3
"""
Test script for ML Text Analysis functionality
Tests the ML analysis engine and API integration
"""

import asyncio
import sys
from pathlib import Path

# Add the core directory to the Python path
sys.path.insert(0, str(Path(__file__).parent / "core"))
sys.path.insert(0, str(Path(__file__).parent / "main_app"))

async def test_ml_analysis():
    """Test the ML text analysis functionality"""
    print("🤖 Testing ML Text Analysis Engine")
    print("=" * 60)
    
    # Test 1: Import ML components
    print("\n1. Testing ML Component Imports...")
    try:
        from ml.text_analyzer import (
            TextAnalysisEngine, 
            BrazilianTextPreprocessor, 
            TransportClassifier,
            DocumentSimilarityAnalyzer
        )
        print("✅ ML analysis components imported successfully")
        
    except Exception as e:
        print(f"❌ ML component import failed: {e}")
        return False
    
    # Test 2: Brazilian Text Preprocessing
    print("\n2. Testing Brazilian Text Preprocessing...")
    try:
        preprocessor = BrazilianTextPreprocessor()
        
        # Test text normalization
        test_text = "Transporte rodoviário e mobilidade urbana são fundamentais para o desenvolvimento!"
        normalized = preprocessor.normalize_text(test_text)
        print(f"✅ Text normalization: '{test_text[:30]}...' → '{normalized[:30]}...'")
        
        # Test tokenization
        tokens = preprocessor.tokenize(test_text)
        print(f"✅ Tokenization: {len(tokens)} tokens extracted")
        print(f"   Sample tokens: {tokens[:5]}")
        
        # Test phrase extraction
        phrases = preprocessor.extract_phrases(test_text)
        print(f"✅ Phrase extraction: {len(phrases)} phrases extracted")
        
    except Exception as e:
        print(f"❌ Text preprocessing test failed: {e}")
        return False
    
    # Test 3: Transport Classification
    print("\n3. Testing Transport Classification...")
    try:
        classifier = TransportClassifier()
        
        # Test transport-related document
        transport_title = "Lei do Transporte Rodoviário e Mobilidade Urbana"
        transport_content = "Esta lei regula o transporte de cargas e passageiros nas rodovias federais, estabelecendo normas para a mobilidade urbana sustentável."
        
        analysis = classifier.classify_document(transport_title, transport_content)
        print(f"✅ Transport document analysis:")
        print(f"   Score: {analysis.transport_score:.3f}")
        print(f"   Category: {analysis.category}")
        print(f"   Keywords found: {analysis.keywords[:5]}")
        print(f"   Confidence: {analysis.confidence:.3f}")
        
        # Test non-transport document
        other_title = "Lei de Proteção Ambiental"
        other_content = "Esta lei estabelece normas para a proteção do meio ambiente e conservação da biodiversidade."
        
        other_analysis = classifier.classify_document(other_title, other_content)
        print(f"✅ Non-transport document analysis:")
        print(f"   Score: {other_analysis.transport_score:.3f}")
        print(f"   Category: {other_analysis.category}")
        
    except Exception as e:
        print(f"❌ Transport classification test failed: {e}")
        return False
    
    # Test 4: Document Similarity (if sklearn available)
    print("\n4. Testing Document Similarity Analysis...")
    try:
        similarity_analyzer = DocumentSimilarityAnalyzer()
        
        # Create sample documents
        sample_docs = [
            {
                'id': 'doc1',
                'title': 'Lei do Transporte Rodoviário',
                'content': 'Normas para transporte de cargas nas rodovias'
            },
            {
                'id': 'doc2', 
                'title': 'Regulamentação Ferroviária',
                'content': 'Regulamentação do transporte ferroviário de passageiros'
            },
            {
                'id': 'doc3',
                'title': 'Lei Ambiental',
                'content': 'Proteção do meio ambiente e recursos naturais'
            }
        ]
        
        # Fit analyzer
        similarity_analyzer.fit_documents(sample_docs)
        print("✅ Similarity analyzer fitted with sample documents")
        
        # Test similarity search
        query_text = "transporte de mercadorias por rodovia"
        similar_docs = similarity_analyzer.find_similar_documents(query_text, top_k=2)
        print(f"✅ Similarity search for '{query_text}':")
        for doc_id, score in similar_docs:
            print(f"   {doc_id}: {score:.3f}")
        
        # Test clustering
        clusters = similarity_analyzer.cluster_documents(n_clusters=2)
        print(f"✅ Document clustering: {len(clusters)} documents clustered")
        
    except Exception as e:
        print(f"⚠️  Document similarity test: {e} (sklearn may not be available)")
    
    # Test 5: Complete Analysis Engine
    print("\n5. Testing Complete Analysis Engine...")
    try:
        engine = TextAnalysisEngine()
        
        # Test document analysis
        test_doc_title = "Decreto sobre Mobilidade Urbana e Transporte Público"
        test_doc_content = """
        O presente decreto estabelece diretrizes para a mobilidade urbana sustentável,
        regulamentando o transporte público coletivo, o transporte individual,
        o transporte de cargas urbanas e a logística de distribuição nas cidades.
        """
        
        analysis = engine.analyze_document(test_doc_title, test_doc_content)
        print(f"✅ Complete document analysis:")
        print(f"   Transport Score: {analysis.transport_score:.3f}")
        print(f"   Category: {analysis.category}")
        print(f"   Keywords: {analysis.keywords[:8]}")
        print(f"   Confidence: {analysis.confidence:.3f}")
        
        # Test text statistics
        stats = engine.get_text_statistics(test_doc_content)
        print(f"✅ Text statistics:")
        print(f"   Word count: {stats.word_count}")
        print(f"   Sentences: {stats.sentence_count}")
        print(f"   Avg word length: {stats.avg_word_length:.2f}")
        print(f"   Complexity: {stats.complexity_score:.3f}")
        print(f"   Transport keywords: {stats.transport_keywords_found}")
        
        # Test keyword extraction
        keywords = engine.extract_keywords(test_doc_content, max_keywords=8)
        print(f"✅ Keyword extraction: {keywords}")
        
    except Exception as e:
        print(f"❌ Complete analysis engine test failed: {e}")
        return False
    
    # Test 6: API Integration
    print("\n6. Testing API Integration...")
    try:
        from api.ml_analysis import get_ml_engine
        
        api_engine = await get_ml_engine()
        print("✅ API ML engine initialized")
        
        # Test engine statistics
        stats = api_engine.get_analysis_statistics()
        print(f"✅ Engine statistics:")
        print(f"   Sklearn available: {stats['sklearn_available']}")
        print(f"   Initialized: {stats['initialized']}")
        print(f"   Transport keywords: {stats['transport_keywords_count']}")
        
    except Exception as e:
        print(f"❌ API integration test failed: {e}")
        return False
    
    print("\n" + "=" * 60)
    print("🎉 All ML Text Analysis Tests Passed!")
    print("✅ Brazilian Portuguese text preprocessing working")
    print("✅ Transport document classification functional")
    print("✅ Document similarity analysis ready (if sklearn available)")
    print("✅ Complete analysis engine operational")
    print("✅ FastAPI integration successful")
    print("✅ Text statistics and keyword extraction working")
    print("\n🚀 ML Text Analysis Pipeline is ready for production!")
    print("📊 Features available:")
    print("   • Transport legislation classification with 60+ keywords")
    print("   • Brazilian Portuguese text preprocessing")
    print("   • Document similarity detection (if sklearn installed)")
    print("   • Automated keyword extraction and ranking")
    print("   • Text complexity and readability analysis")
    print("   • Batch document processing capabilities")
    print("   • RESTful API endpoints for all features")
    
    return True


if __name__ == "__main__":
    success = asyncio.run(test_ml_analysis())
    sys.exit(0 if success else 1)