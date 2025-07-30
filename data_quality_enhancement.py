#!/usr/bin/env python3
"""
Data Quality Enhancement Framework for Monitor Legislativo v4
Advanced NLP and ML pipeline for Brazilian legislative document enhancement

Target: Improve data completeness from 77.7% to >90%
Focus Areas:
- Author extraction (0% → 80%+)
- Classification inference (0% → 85%+) 
- Geographic data enhancement (14.3% → 80%+)
- URN validation and reconstruction (94.2% → 98%+)
"""

import pandas as pd
import numpy as np
import re
import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# NLP and ML libraries
try:
    import spacy
    from spacy import displacy
    from spacy.matcher import Matcher
    from spacy.tokens import Doc
except ImportError:
    print("Installing spacy...")
    import subprocess
    subprocess.check_call(["pip", "install", "spacy"])
    import spacy

try:
    import nltk
    from nltk.corpus import stopwords
    from nltk.tokenize import word_tokenize, sent_tokenize
    from nltk.stem import SnowballStemmer
except ImportError:
    print("Installing nltk...")
    import subprocess
    subprocess.check_call(["pip", "install", "nltk"])
    import nltk

# Machine Learning
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import SVC
from sklearn.metrics import classification_report, accuracy_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder

# Text processing
import unicodedata
from collections import Counter, defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data_quality_enhancement.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class BrazilianLegalNLP:
    """Advanced NLP processor for Brazilian legal documents"""
    
    def __init__(self):
        """Initialize NLP components"""
        self.setup_nltk()
        self.setup_spacy()
        self.setup_legal_patterns()
        
    def setup_nltk(self):
        """Setup NLTK components"""
        try:
            nltk.data.find('tokenizers/punkt')
        except LookupError:
            nltk.download('punkt')
            
        try:
            nltk.data.find('corpora/stopwords')
        except LookupError:
            nltk.download('stopwords')
            
        try:
            nltk.data.find('corpora/rslp')
        except LookupError:
            nltk.download('rslp')
            
        self.portuguese_stopwords = set(stopwords.words('portuguese'))
        self.stemmer = SnowballStemmer('portuguese')
        
    def setup_spacy(self):
        """Setup spaCy Portuguese model"""
        try:
            self.nlp = spacy.load("pt_core_news_sm")
        except OSError:
            logger.info("Installing Portuguese spaCy model...")
            spacy.cli.download("pt_core_news_sm")
            self.nlp = spacy.load("pt_core_news_sm")
            
        # Add custom patterns for legal entities
        self.matcher = Matcher(self.nlp.vocab)
        
    def setup_legal_patterns(self):
        """Setup patterns for Brazilian legal document parsing"""
        
        # Brazilian institutional patterns
        self.institutional_patterns = {
            'federal_agencies': [
                r'ANTT|Agência Nacional de Transportes Terrestres',
                r'ANTAQ|Agência Nacional de Transportes Aquaviários',
                r'ANAC|Agência Nacional de Aviação Civil',
                r'ANP|Agência Nacional do Petróleo',
                r'ANEEL|Agência Nacional de Energia Elétrica',
                r'ANVISA|Agência Nacional de Vigilância Sanitária',
                r'ANA|Agência Nacional de Águas',
                r'ANCINE|Agência Nacional do Cinema'
            ],
            'federal_ministries': [
                r'Ministério dos Transportes',
                r'Ministério da Infraestrutura',
                r'Ministério do Desenvolvimento Regional',
                r'Ministério da Economia',
                r'Casa Civil',
                r'Presidência da República'
            ],
            'courts': [
                r'STF|Supremo Tribunal Federal',
                r'STJ|Superior Tribunal de Justiça',
                r'TST|Tribunal Superior do Trabalho',
                r'TCU|Tribunal de Contas da União',
                r'TRF|Tribunal Regional Federal',
                r'TJSP|Tribunal de Justiça de São Paulo',
                r'TJRJ|Tribunal de Justiça do Rio de Janeiro',
                r'TJMG|Tribunal de Justiça de Minas Gerais'
            ],
            'congress': [
                r'Câmara dos Deputados',
                r'Senado Federal',
                r'Congresso Nacional',
                r'Comissão de Viação e Transportes',
                r'Comissão de Desenvolvimento Urbano'
            ]
        }
        
        # Author extraction patterns
        self.author_patterns = [
            r'Autor:\s*([^;]+)',
            r'Autoria:\s*([^;]+)',
            r'De autoria de:\s*([^;]+)',
            r'Elaborado por:\s*([^;]+)',
            r'Proposto por:\s*([^;]+)',
            r'Relatoria:\s*([^;]+)',
            r'Relator:\s*([^;]+)'
        ]
        
        # Classification patterns for legal documents
        self.classification_patterns = {
            'legislacao': [
                r'Lei nº', r'Decreto nº', r'Medida Provisória',
                r'Portaria nº', r'Resolução nº', r'Instrução Normativa',
                r'Constituição', r'Emenda Constitucional'
            ],
            'jurisprudencia': [
                r'Acórdão', r'Decisão', r'Sentença', r'Despacho',
                r're:\s*\d+', r'Recurso', r'Agravo', r'Apelação',
                r'Mandado de Segurança', r'Ação'
            ],
            'doutrina': [
                r'Artigo', r'Livro', r'Tese', r'Dissertação',
                r'Monografia', r'Paper', r'Estudo'
            ],
            'proposicoes': [
                r'Projeto de Lei', r'PL nº', r'PEC nº',
                r'Proposta de Emenda', r'Indicação',
                r'Requerimento', r'Moção'
            ]
        }
        
        # Brazilian states and regions
        self.states_mapping = {
            'AC': 'Acre', 'AL': 'Alagoas', 'AP': 'Amapá', 'AM': 'Amazonas',
            'BA': 'Bahia', 'CE': 'Ceará', 'DF': 'Distrito Federal', 'ES': 'Espírito Santo',
            'GO': 'Goiás', 'MA': 'Maranhão', 'MT': 'Mato Grosso', 'MS': 'Mato Grosso do Sul',
            'MG': 'Minas Gerais', 'PA': 'Pará', 'PB': 'Paraíba', 'PR': 'Paraná',
            'PE': 'Pernambuco', 'PI': 'Piauí', 'RJ': 'Rio de Janeiro', 'RN': 'Rio Grande do Norte',
            'RS': 'Rio Grande do Sul', 'RO': 'Rondônia', 'RR': 'Roraima', 'SC': 'Santa Catarina',
            'SP': 'São Paulo', 'SE': 'Sergipe', 'TO': 'Tocantins'
        }
        
        self.regions_mapping = {
            'Norte': ['AC', 'AP', 'AM', 'PA', 'RO', 'RR', 'TO'],
            'Nordeste': ['AL', 'BA', 'CE', 'MA', 'PB', 'PE', 'PI', 'RN', 'SE'],
            'Centro-Oeste': ['GO', 'MT', 'MS', 'DF'],
            'Sudeste': ['ES', 'MG', 'RJ', 'SP'],
            'Sul': ['PR', 'RS', 'SC']
        }

class AuthorExtractor:
    """Extract and infer author information from legal documents"""
    
    def __init__(self, nlp_processor: BrazilianLegalNLP):
        self.nlp = nlp_processor
        
    def extract_from_text(self, text: str) -> Optional[str]:
        """Extract author from document text using multiple strategies"""
        if not text or pd.isna(text):
            return None
            
        # Strategy 1: Direct pattern matching
        for pattern in self.nlp.author_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                author = matches[0].strip()
                if len(author) > 3 and not author.lower() in ['autor', 'autoria']:
                    return self.clean_author_name(author)
        
        # Strategy 2: Look for person names in the beginning of documents
        sentences = sent_tokenize(text)[:3]  # First 3 sentences
        for sentence in sentences:
            doc = self.nlp.nlp(sentence)
            for ent in doc.ents:
                if ent.label_ == "PERSON" and len(ent.text.split()) >= 2:
                    return self.clean_author_name(ent.text)
                    
        # Strategy 3: Institutional authorship
        return self.extract_institutional_author(text)
    
    def extract_from_assuntos(self, assuntos: str) -> Optional[str]:
        """Extract author from 'assuntos' field which often contains author info"""
        if not assuntos or pd.isna(assuntos):
            return None
            
        # Look for author information in subjects field
        for pattern in self.nlp.author_patterns:
            matches = re.findall(pattern, assuntos, re.IGNORECASE)
            if matches:
                author = matches[0].strip()
                return self.clean_author_name(author)
                
        return None
    
    def extract_institutional_author(self, text: str) -> Optional[str]:
        """Extract institutional author from text"""
        text_upper = text.upper()
        
        # Check for federal agencies
        for pattern in self.nlp.institutional_patterns['federal_agencies']:
            if re.search(pattern, text_upper):
                match = re.search(pattern, text_upper)
                return match.group(0)
                
        # Check for ministries
        for pattern in self.nlp.institutional_patterns['federal_ministries']:
            if re.search(pattern, text_upper):
                match = re.search(pattern, text_upper)
                return match.group(0)
                
        # Check for courts
        for pattern in self.nlp.institutional_patterns['courts']:
            if re.search(pattern, text_upper):
                match = re.search(pattern, text_upper)
                return match.group(0)
                
        return None
    
    def clean_author_name(self, author: str) -> str:
        """Clean and standardize author names"""
        if not author:
            return None
            
        # Remove common prefixes and suffixes
        author = re.sub(r'^(Autor:|Autoria:|De autoria de:|Elaborado por:|Proposto por:)\s*', '', author, flags=re.IGNORECASE)
        author = re.sub(r'\s*[;,].*$', '', author)  # Remove everything after ; or ,
        
        # Clean whitespace
        author = ' '.join(author.split())
        
        # Capitalize properly
        if len(author) > 10:  # Only if it looks like a real name
            author = ' '.join([word.capitalize() if word.lower() not in ['de', 'da', 'do', 'dos', 'das'] 
                              else word.lower() for word in author.split()])
        
        return author.strip()


class ClassificationInferencer:
    """Infer document classification using ML and pattern matching"""
    
    def __init__(self, nlp_processor: BrazilianLegalNLP):
        self.nlp = nlp_processor
        self.model = None
        self.vectorizer = None
        self.label_encoder = None
        
    def train_classification_model(self, df: pd.DataFrame):
        """Train ML model for document classification"""
        logger.info("Training classification model...")
        
        # Prepare training data from documents with existing categories
        training_data = df[df['categoria'].notna() & df['titulo'].notna()].copy()
        
        if len(training_data) < 100:
            logger.warning("Insufficient training data for ML model")
            return False
            
        # Feature engineering
        X = []
        y = []
        
        for _, row in training_data.iterrows():
            features = self.extract_text_features(row)
            if features:
                X.append(features)
                y.append(row['categoria'])
        
        if len(X) < 50:
            logger.warning("Insufficient feature data for training")
            return False
            
        # Prepare vectorizer and model
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            stop_words=list(self.nlp.portuguese_stopwords),
            lowercase=True
        )
        
        X_vectorized = self.vectorizer.fit_transform(X)
        
        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Train ensemble model
        self.model = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=5,
            random_state=42
        )
        
        # Split and train
        X_train, X_test, y_train, y_test = train_test_split(
            X_vectorized, y_encoded, test_size=0.2, random_state=42
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        logger.info(f"Classification model accuracy: {accuracy:.3f}")
        
        return True
    
    def extract_text_features(self, row) -> Optional[str]:
        """Extract text features for classification"""
        features = []
        
        # Title features
        if pd.notna(row['titulo']):
            features.append(str(row['titulo']))
            
        # Type features
        if pd.notna(row['tipo']):
            features.append(str(row['tipo']))
            
        # Ementa features
        if pd.notna(row['ementa']):
            features.append(str(row['ementa'])[:500])  # Limit length
            
        # Subject features
        if pd.notna(row['assuntos']):
            features.append(str(row['assuntos'])[:300])
            
        return ' '.join(features) if features else None
    
    def infer_classification(self, row) -> Tuple[Optional[str], float]:
        """Infer document classification with confidence score"""
        
        # Strategy 1: Pattern-based classification
        pattern_class = self.classify_by_patterns(row)
        if pattern_class:
            return pattern_class, 0.8
            
        # Strategy 2: ML-based classification
        if self.model and self.vectorizer:
            ml_class = self.classify_by_ml(row)
            if ml_class:
                return ml_class[0], ml_class[1]
                
        # Strategy 3: Heuristic classification
        heuristic_class = self.classify_by_heuristics(row)
        if heuristic_class:
            return heuristic_class, 0.6
            
        return None, 0.0
    
    def classify_by_patterns(self, row) -> Optional[str]:
        """Classify using regex patterns"""
        text = ''
        if pd.notna(row['titulo']):
            text += str(row['titulo']) + ' '
        if pd.notna(row['tipo']):
            text += str(row['tipo']) + ' '
        if pd.notna(row['ementa']):
            text += str(row['ementa'])[:200]
            
        if not text:
            return None
            
        text = text.upper()
        
        # Check each category
        for category, patterns in self.nlp.classification_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return category.title()
                    
        return None
    
    def classify_by_ml(self, row) -> Optional[Tuple[str, float]]:
        """Classify using trained ML model"""
        if not self.model:
            return None
            
        features = self.extract_text_features(row)
        if not features:
            return None
            
        try:
            features_vectorized = self.vectorizer.transform([features])
            prediction = self.model.predict(features_vectorized)[0]
            probability = self.model.predict_proba(features_vectorized)[0].max()
            
            predicted_class = self.label_encoder.inverse_transform([prediction])[0]
            return predicted_class, probability
            
        except Exception as e:
            logger.warning(f"ML classification error: {e}")
            return None
    
    def classify_by_heuristics(self, row) -> Optional[str]:
        """Classify using heuristic rules"""
        if pd.notna(row['tipo']):
            tipo = str(row['tipo']).lower()
            if any(word in tipo for word in ['lei', 'decreto', 'portaria', 'resolução']):
                return 'Legislação'
            elif any(word in tipo for word in ['acórdão', 'decisão', 'sentença']):
                return 'Jurisprudência'
            elif any(word in tipo for word in ['livro', 'artigo', 'tese']):
                return 'Doutrina'
            elif any(word in tipo for word in ['projeto', 'proposta']):
                return 'Proposições'
                
        return None


class GeographicEnhancer:
    """Enhance geographic data using text mining and NER"""
    
    def __init__(self, nlp_processor: BrazilianLegalNLP):
        self.nlp = nlp_processor
        self.load_municipal_data()
        
    def load_municipal_data(self):
        """Load Brazilian municipal data for validation"""
        # This would typically load from IBGE data
        # For now, using common patterns
        self.major_cities = {
            'SP': ['São Paulo', 'Campinas', 'Santos', 'Ribeirão Preto', 'Sorocaba'],
            'RJ': ['Rio de Janeiro', 'Niterói', 'Nova Iguaçu', 'Duque de Caxias'],
            'MG': ['Belo Horizonte', 'Uberlândia', 'Contagem', 'Juiz de Fora'],
            'PR': ['Curitiba', 'Londrina', 'Maringá', 'Ponta Grossa'],
            'RS': ['Porto Alegre', 'Caxias do Sul', 'Pelotas', 'Santa Maria'],
            'BA': ['Salvador', 'Feira de Santana', 'Vitória da Conquista'],
            'PE': ['Recife', 'Jaboatão dos Guararapes', 'Olinda', 'Caruaru'],
            'CE': ['Fortaleza', 'Caucaia', 'Juazeiro do Norte', 'Sobral'],
            'GO': ['Goiânia', 'Aparecida de Goiânia', 'Anápolis', 'Rio Verde']
        }
        
    def enhance_geographic_data(self, row) -> Dict[str, Optional[str]]:
        """Extract and enhance geographic information"""
        result = {
            'estado': row.get('estado'),
            'municipio': row.get('municipio'),
            'jurisdicao': row.get('jurisdicao'),
            'confidence': 0.0
        }
        
        # If we already have complete data, validate it
        if pd.notna(row.get('estado')) and pd.notna(row.get('municipio')):
            if self.validate_geographic_pair(row['estado'], row['municipio']):
                result['confidence'] = 0.9
                return result
        
        # Extract from text fields
        text_fields = ['titulo', 'ementa', 'assuntos']
        combined_text = ''
        
        for field in text_fields:
            if pd.notna(row.get(field)):
                combined_text += str(row[field]) + ' '
        
        if not combined_text:
            return result
            
        # Extract state information
        extracted_state = self.extract_state(combined_text)
        if extracted_state and not pd.notna(result['estado']):
            result['estado'] = extracted_state
            result['confidence'] = max(result['confidence'], 0.7)
            
        # Extract municipality information
        extracted_municipality = self.extract_municipality(combined_text, result['estado'])
        if extracted_municipality and not pd.notna(result['municipio']):
            result['municipio'] = extracted_municipality
            result['confidence'] = max(result['confidence'], 0.6)
            
        # Infer jurisdiction
        if not pd.notna(result['jurisdicao']):
            result['jurisdicao'] = self.infer_jurisdiction(row, result)
            
        return result
    
    def extract_state(self, text: str) -> Optional[str]:
        """Extract state information from text"""
        text_upper = text.upper()
        
        # Look for state abbreviations
        for abbr, full_name in self.nlp.states_mapping.items():
            # Check for abbreviation patterns
            if re.search(rf'\b{abbr}\b', text_upper):
                return abbr
            # Check for full state names
            if full_name.upper() in text_upper:
                return abbr
                
        # Look for federal jurisdiction indicators
        federal_indicators = ['FEDERAL', 'UNIÃO', 'CONGRESSO NACIONAL', 'PRESIDÊNCIA']
        for indicator in federal_indicators:
            if indicator in text_upper:
                return 'Federal'
                
        return None
    
    def extract_municipality(self, text: str, state: Optional[str] = None) -> Optional[str]:
        """Extract municipality information from text"""
        if not state or state == 'Federal':
            return None
            
        text_lower = text.lower()
        
        # Look for cities in the identified state
        if state in self.major_cities:
            for city in self.major_cities[state]:
                if city.lower() in text_lower:
                    return city
                    
        # Use NER to find locations
        doc = self.nlp.nlp(text[:1000])  # Limit text length for performance
        for ent in doc.ents:
            if ent.label_ in ['LOC', 'GPE']:  # Location or geopolitical entity
                city_name = ent.text.strip()
                if len(city_name) > 3 and self.is_likely_municipality(city_name):
                    return city_name
                    
        return None
    
    def is_likely_municipality(self, name: str) -> bool:
        """Check if name is likely a municipality"""
        # Basic heuristics
        if len(name) < 3 or len(name) > 50:
            return False
            
        # Common municipal suffixes in Brazil
        municipal_suffixes = ['cidade', 'município', 'prefeitura']
        if any(suffix in name.lower() for suffix in municipal_suffixes):
            return True
            
        # Should start with capital letter and contain only letters, spaces, hyphens
        if re.match(r'^[A-ZÀÁÂÃÄÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ][a-zA-ZÀ-ÿ\s\-\']+$', name):
            return True
            
        return False
    
    def infer_jurisdiction(self, row, geo_result: Dict) -> Optional[str]:
        """Infer jurisdiction level from document characteristics"""
        
        # Federal level indicators
        federal_indicators = ['ANTT', 'ANTAQ', 'ANAC', 'Ministério', 'Federal', 'República']
        text_to_check = str(row.get('titulo', '')) + ' ' + str(row.get('ementa', ''))
        
        for indicator in federal_indicators:
            if indicator in text_to_check:
                return 'Federal'
                
        # State level
        if geo_result.get('estado') and geo_result['estado'] != 'Federal':
            if not geo_result.get('municipio'):
                return 'Estadual'
                
        # Municipal level
        if geo_result.get('municipio'):
            return 'Municipal'
            
        return None
    
    def validate_geographic_pair(self, state: str, municipality: str) -> bool:
        """Validate that municipality belongs to the state"""
        if not state or not municipality:
            return False
            
        if state == 'Federal':
            return municipality is None or pd.isna(municipality)
            
        # This would typically check against IBGE database
        # For now, basic validation
        if state in self.major_cities:
            return municipality in self.major_cities[state]
            
        return True  # Assume valid if we can't verify


class URNValidator:
    """Validate and reconstruct URN identifiers for legal documents"""
    
    def __init__(self):
        self.setup_urn_patterns()
        
    def setup_urn_patterns(self):
        """Setup URN patterns for Brazilian legal documents"""
        
        # Standard URN pattern: urn:lex:br:federal:lei:2020-01-01;12345
        self.urn_pattern = re.compile(
            r'urn:lex:br:(federal|[a-z]{2}):([a-z\-]+):(\d{4}-\d{2}-\d{2});?(\d+)?'
        )
        
        # Document type mappings
        self.doc_type_mapping = {
            'lei': ['lei'],
            'decreto': ['decreto'],
            'portaria': ['portaria'],
            'resolucao': ['resolução', 'resolucao'],
            'instrucao.normativa': ['instrução normativa', 'instrucao normativa'],
            'medida.provisoria': ['medida provisória', 'medida provisoria'],
            'emenda.constitucional': ['emenda constitucional'],
            'projeto.de.lei': ['projeto de lei', 'pl']
        }
        
    def validate_urn(self, urn: str) -> Dict[str, any]:
        """Validate URN format and extract components"""
        if not urn or pd.isna(urn):
            return {'valid': False, 'error': 'Empty URN'}
            
        match = self.urn_pattern.match(urn.lower())
        if not match:
            return {'valid': False, 'error': 'Invalid URN format'}
            
        jurisdiction, doc_type, date, number = match.groups()
        
        # Validate date format
        try:
            datetime.strptime(date, '%Y-%m-%d')
        except ValueError:
            return {'valid': False, 'error': 'Invalid date format'}
            
        return {
            'valid': True,
            'jurisdiction': jurisdiction,
            'document_type': doc_type,
            'date': date,
            'number': number,
            'components': match.groups()
        }
    
    def reconstruct_urn(self, row) -> Optional[str]:
        """Reconstruct URN from document metadata"""
        
        # Extract components
        jurisdiction = self.extract_jurisdiction(row)
        doc_type = self.extract_document_type(row)
        date = self.extract_date(row)
        number = self.extract_number(row)
        
        if not all([jurisdiction, doc_type, date]):
            return None
            
        # Build URN
        urn_parts = ['urn', 'lex', 'br', jurisdiction, doc_type, date]
        
        if number:
            urn_base = ':'.join(urn_parts)
            return f"{urn_base};{number}"
        else:
            return ':'.join(urn_parts)
    
    def extract_jurisdiction(self, row) -> Optional[str]:
        """Extract jurisdiction for URN"""
        estado = row.get('estado')
        jurisdicao = row.get('jurisdicao')
        
        if estado == 'Federal' or jurisdicao == 'Federal':
            return 'federal'
        elif estado and len(estado) == 2:
            return estado.lower()
        elif jurisdicao == 'Estadual' and estado:
            return estado.lower()
            
        return 'federal'  # Default fallback
    
    def extract_document_type(self, row) -> Optional[str]:
        """Extract document type for URN"""
        tipo = str(row.get('tipo', '')).lower()
        titulo = str(row.get('titulo', '')).lower()
        
        combined_text = f"{tipo} {titulo}"
        
        for urn_type, variations in self.doc_type_mapping.items():
            for variation in variations:
                if variation in combined_text:
                    return urn_type
                    
        # Try to infer from title patterns
        if 'lei nº' in titulo or 'lei n°' in titulo:
            return 'lei'
        elif 'decreto nº' in titulo or 'decreto n°' in titulo:
            return 'decreto'
        elif 'portaria nº' in titulo:
            return 'portaria'
        elif 'resolução nº' in titulo:
            return 'resolucao'
            
        return None
    
    def extract_date(self, row) -> Optional[str]:
        """Extract and format date for URN"""
        data = row.get('data')
        
        if pd.isna(data):
            return None
            
        try:
            if isinstance(data, str):
                # Try to parse different date formats
                for fmt in ['%Y-%m-%d', '%d/%m/%Y', '%Y']:
                    try:
                        parsed_date = datetime.strptime(data, fmt)
                        return parsed_date.strftime('%Y-%m-%d')
                    except ValueError:
                        continue
            elif hasattr(data, 'strftime'):
                return data.strftime('%Y-%m-%d')
                
        except Exception:
            pass
            
        return None
    
    def extract_number(self, row) -> Optional[str]:
        """Extract document number for URN"""
        titulo = str(row.get('titulo', ''))
        numero = row.get('numero')
        
        if pd.notna(numero):
            return str(numero)
            
        # Extract from title
        number_patterns = [
            r'nº\s*(\d+)',
            r'n°\s*(\d+)',
            r'número\s*(\d+)',
            r'/(\d{4})',  # Year suffix
            r'(\d+)/\d{4}'  # Number/year format
        ]
        
        for pattern in number_patterns:
            match = re.search(pattern, titulo, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return None


class DataQualityEnhancer:
    """Main coordinator for data quality enhancement"""
    
    def __init__(self, data_path: str):
        """Initialize the enhancement framework"""
        self.data_path = data_path
        self.nlp = BrazilianLegalNLP()
        self.author_extractor = AuthorExtractor(self.nlp)
        self.classifier = ClassificationInferencer(self.nlp)
        self.geo_enhancer = GeographicEnhancer(self.nlp)
        self.urn_validator = URNValidator()
        
        # Load data
        logger.info(f"Loading data from {data_path}")
        self.df = pd.read_csv(data_path, low_memory=False)
        logger.info(f"Loaded {len(self.df):,} documents")
        
        # Initialize quality metrics
        self.quality_metrics = self.calculate_baseline_quality()
        
    def calculate_baseline_quality(self) -> Dict[str, float]:
        """Calculate baseline data quality metrics"""
        metrics = {}
        
        for column in self.df.columns:
            total = len(self.df)
            non_null = self.df[column].notna().sum()
            non_empty = (self.df[column] != '').sum() if self.df[column].dtype == 'object' else non_null
            completeness = (non_empty / total) * 100
            metrics[column] = completeness
            
        # Calculate overall completeness
        critical_fields = ['titulo', 'tipo', 'data', 'estado', 'autor', 'classificacao', 'municipio', 'urn']
        available_critical = [field for field in critical_fields if field in metrics]
        
        if available_critical:
            overall_completeness = sum(metrics[field] for field in available_critical) / len(available_critical)
            metrics['overall'] = overall_completeness
        
        logger.info(f"Baseline overall completeness: {metrics.get('overall', 0):.1f}%")
        return metrics
    
    def enhance_all_data(self, batch_size: int = 1000) -> pd.DataFrame:
        """Enhanced all data using ML and NLP techniques"""
        logger.info("Starting comprehensive data enhancement...")
        
        # Train classification model if possible
        self.classifier.train_classification_model(self.df)
        
        enhanced_df = self.df.copy()
        
        # Process in batches for memory efficiency
        for i in range(0, len(enhanced_df), batch_size):
            batch_end = min(i + batch_size, len(enhanced_df))
            batch = enhanced_df.iloc[i:batch_end].copy()
            
            logger.info(f"Processing batch {i//batch_size + 1}/{(len(enhanced_df)-1)//batch_size + 1}")
            
            # Enhance batch
            batch = self.enhance_batch(batch)
            
            # Update main dataframe
            enhanced_df.iloc[i:batch_end] = batch
            
        # Calculate final quality metrics
        final_metrics = self.calculate_final_quality(enhanced_df)
        
        # Log improvement summary
        self.log_improvement_summary(final_metrics)
        
        return enhanced_df
    
    def enhance_batch(self, batch: pd.DataFrame) -> pd.DataFrame:
        """Enhance a batch of documents"""
        
        for idx, row in batch.iterrows():
            
            # 1. Author Enhancement
            if pd.isna(row['autor']) or row['autor'] == '':
                # Try extracting from assuntos first
                author = self.author_extractor.extract_from_assuntos(row.get('assuntos'))
                if not author:
                    # Try extracting from text fields
                    combined_text = f"{row.get('titulo', '')} {row.get('ementa', '')}"
                    author = self.author_extractor.extract_from_text(combined_text)
                
                if author:
                    batch.at[idx, 'autor'] = author
            
            # 2. Classification Enhancement
            if pd.isna(row['classificacao']) or row['classificacao'] == '':
                classification, confidence = self.classifier.infer_classification(row)
                if classification and confidence > 0.5:
                    batch.at[idx, 'classificacao'] = classification
            
            # 3. Geographic Enhancement
            geo_enhancement = self.geo_enhancer.enhance_geographic_data(row)
            
            if geo_enhancement['confidence'] > 0.5:
                if geo_enhancement['estado'] and (pd.isna(row['estado']) or row['estado'] == ''):
                    batch.at[idx, 'estado'] = geo_enhancement['estado']
                    
                if geo_enhancement['municipio'] and (pd.isna(row['municipio']) or row['municipio'] == ''):
                    batch.at[idx, 'municipio'] = geo_enhancement['municipio']
                    
                if geo_enhancement['jurisdicao'] and (pd.isna(row['jurisdicao']) or row['jurisdicao'] == ''):
                    batch.at[idx, 'jurisdicao'] = geo_enhancement['jurisdicao']
            
            # 4. URN Enhancement
            if pd.isna(row['urn']) or row['urn'] == '':
                reconstructed_urn = self.urn_validator.reconstruct_urn(row)
                if reconstructed_urn:
                    batch.at[idx, 'urn'] = reconstructed_urn
            else:
                # Validate existing URN
                validation = self.urn_validator.validate_urn(row['urn'])
                if not validation['valid']:
                    reconstructed_urn = self.urn_validator.reconstruct_urn(row)
                    if reconstructed_urn:
                        batch.at[idx, 'urn'] = reconstructed_urn
        
        return batch
    
    def calculate_final_quality(self, enhanced_df: pd.DataFrame) -> Dict[str, float]:
        """Calculate final quality metrics after enhancement"""
        metrics = {}
        
        for column in enhanced_df.columns:
            total = len(enhanced_df)
            non_null = enhanced_df[column].notna().sum()
            non_empty = (enhanced_df[column] != '').sum() if enhanced_df[column].dtype == 'object' else non_null
            completeness = (non_empty / total) * 100
            metrics[column] = completeness
            
        # Calculate overall completeness
        critical_fields = ['titulo', 'tipo', 'data', 'estado', 'autor', 'classificacao', 'municipio', 'urn']
        available_critical = [field for field in critical_fields if field in metrics]
        
        if available_critical:
            overall_completeness = sum(metrics[field] for field in available_critical) / len(available_critical)
            metrics['overall'] = overall_completeness
        
        return metrics
    
    def log_improvement_summary(self, final_metrics: Dict[str, float]):
        """Log comprehensive improvement summary"""
        logger.info("=== DATA QUALITY ENHANCEMENT SUMMARY ===")
        
        critical_fields = ['autor', 'classificacao', 'municipio', 'estado', 'urn']
        
        for field in critical_fields:
            if field in self.quality_metrics and field in final_metrics:
                baseline = self.quality_metrics[field]
                final = final_metrics[field]
                improvement = final - baseline
                
                logger.info(f"{field.upper()}: {baseline:.1f}% → {final:.1f}% (+{improvement:.1f}%)")
        
        # Overall improvement
        if 'overall' in self.quality_metrics and 'overall' in final_metrics:
            baseline_overall = self.quality_metrics['overall']
            final_overall = final_metrics['overall']
            overall_improvement = final_overall - baseline_overall
            
            logger.info(f"OVERALL COMPLETENESS: {baseline_overall:.1f}% → {final_overall:.1f}% (+{overall_improvement:.1f}%)")
            
            if final_overall >= 90.0:
                logger.info("🎯 TARGET ACHIEVED: >90% completeness reached!")
            else:
                logger.info(f"📈 PROGRESS: {90.0 - final_overall:.1f}% remaining to reach 90% target")
    
    def save_enhanced_data(self, enhanced_df: pd.DataFrame, output_path: str):
        """Save enhanced data to file"""
        logger.info(f"Saving enhanced data to {output_path}")
        enhanced_df.to_csv(output_path, index=False, encoding='utf-8')
        
        # Save quality report
        report_path = output_path.replace('.csv', '_quality_report.json')
        quality_report = {
            'baseline_metrics': self.quality_metrics,
            'final_metrics': self.calculate_final_quality(enhanced_df),
            'enhancement_timestamp': datetime.now().isoformat(),
            'total_documents': len(enhanced_df),
            'enhancement_summary': {
                'author_enhanced': (enhanced_df['autor'].notna()).sum(),
                'classification_enhanced': (enhanced_df['classificacao'].notna()).sum(),
                'geographic_enhanced': (enhanced_df['municipio'].notna()).sum(),
                'urn_enhanced': (enhanced_df['urn'].notna()).sum()
            }
        }
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(quality_report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Quality report saved to {report_path}")


def main():
    """Main execution function"""
    
    # Configuration
    DATA_PATH = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao/lexml_dataset_limpo_classificado_20250722_102507_com_localizacao.csv"
    OUTPUT_PATH = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/enhanced/lexml_dataset_enhanced_v4.csv"
    
    try:
        # Initialize enhancer
        enhancer = DataQualityEnhancer(DATA_PATH)
        
        # Perform enhancement
        enhanced_data = enhancer.enhance_all_data(batch_size=500)
        
        # Save results
        enhancer.save_enhanced_data(enhanced_data, OUTPUT_PATH)
        
        logger.info("Data quality enhancement completed successfully!")
        
    except Exception as e:
        logger.error(f"Enhancement failed: {e}")
        raise

if __name__ == "__main__":
    main()