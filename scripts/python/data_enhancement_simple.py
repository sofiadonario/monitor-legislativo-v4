#!/usr/bin/env python3
"""
Simplified Data Enhancement for Monitor Legislativo v4
Rule-based enhancement for Brazilian legislative documents using only built-in libraries

Target: Improve data completeness from current state to >90%
Focus Areas:
- Author extraction using regex patterns
- Classification inference using keyword matching
- Geographic data enhancement using pattern matching
- URN validation and reconstruction
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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data_enhancement_simple.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SimpleBrazilianLegalProcessor:
    """Simplified processor for Brazilian legal documents using only built-in libraries"""
    
    def __init__(self):
        self.setup_patterns()
        
    def setup_patterns(self):
        """Setup regex patterns for Brazilian legal document processing"""
        
        # Brazilian states
        self.states_mapping = {
            'AC': 'Acre', 'AL': 'Alagoas', 'AP': 'Amapá', 'AM': 'Amazonas',
            'BA': 'Bahia', 'CE': 'Ceará', 'DF': 'Distrito Federal', 'ES': 'Espírito Santo',
            'GO': 'Goiás', 'MA': 'Maranhão', 'MT': 'Mato Grosso', 'MS': 'Mato Grosso do Sul',
            'MG': 'Minas Gerais', 'PA': 'Pará', 'PB': 'Paraíba', 'PR': 'Paraná',
            'PE': 'Pernambuco', 'PI': 'Piauí', 'RJ': 'Rio de Janeiro', 'RN': 'Rio Grande do Norte',
            'RS': 'Rio Grande do Sul', 'RO': 'Rondônia', 'RR': 'Roraima', 'SC': 'Santa Catarina',
            'SP': 'São Paulo', 'SE': 'Sergipe', 'TO': 'Tocantins'
        }
        
        # Major Brazilian cities by state
        self.major_cities = {
            'SP': ['São Paulo', 'Campinas', 'Santos', 'Ribeirão Preto', 'Sorocaba', 'São Bernardo do Campo', 'Santo André'],
            'RJ': ['Rio de Janeiro', 'Niterói', 'Nova Iguaçu', 'Duque de Caxias', 'São Gonçalo', 'Volta Redonda'],
            'MG': ['Belo Horizonte', 'Uberlândia', 'Contagem', 'Juiz de Fora', 'Betim', 'Montes Claros'],
            'PR': ['Curitiba', 'Londrina', 'Maringá', 'Ponta Grossa', 'Cascavel', 'São José dos Pinhais'],
            'RS': ['Porto Alegre', 'Caxias do Sul', 'Pelotas', 'Santa Maria', 'Gravataí', 'Viamão'],
            'BA': ['Salvador', 'Feira de Santana', 'Vitória da Conquista', 'Camaçari', 'Juazeiro', 'Ilhéus'],
            'PE': ['Recife', 'Jaboatão dos Guararapes', 'Olinda', 'Caruaru', 'Petrolina', 'Paulista'],
            'CE': ['Fortaleza', 'Caucaia', 'Juazeiro do Norte', 'Sobral', 'Crato', 'Itapipoca'],
            'GO': ['Goiânia', 'Aparecida de Goiânia', 'Anápolis', 'Rio Verde', 'Luziânia', 'Águas Lindas']
        }
        
        # Author extraction patterns
        self.author_patterns = [
            r'Autor[ia]?:\s*([^;,\n]+)',
            r'De autoria de:\s*([^;,\n]+)',
            r'Elaborado por:\s*([^;,\n]+)',
            r'Proposto por:\s*([^;,\n]+)',
            r'Relatoria:\s*([^;,\n]+)',
            r'Relator[a]?:\s*([^;,\n]+)',
            r'Deputad[oa]?\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+)',
            r'Senador[a]?\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+)'
        ]
        
        # Institutional patterns
        self.institutional_patterns = {
            'federal_agencies': [
                r'ANTT|Agência Nacional de Transportes Terrestres',
                r'ANTAQ|Agência Nacional de Transportes Aquaviários',
                r'ANAC|Agência Nacional de Aviação Civil',
                r'ANP|Agência Nacional do Petróleo',
                r'ANEEL|Agência Nacional de Energia Elétrica',
                r'ANVISA|Agência Nacional de Vigilância Sanitária'
            ],
            'ministries': [
                r'Ministério dos Transportes',
                r'Ministério da Infraestrutura',
                r'Ministério do Desenvolvimento Regional',
                r'Casa Civil',
                r'Presidência da República'
            ],
            'courts': [
                r'STF|Supremo Tribunal Federal',
                r'STJ|Superior Tribunal de Justiça',
                r'TST|Tribunal Superior do Trabalho',
                r'TCU|Tribunal de Contas da União',
                r'TRF.*|Tribunal Regional Federal',
                r'TJ[A-Z]{2}|Tribunal de Justiça'
            ],
            'congress': [
                r'Câmara dos Deputados',
                r'Senado Federal',
                r'Congresso Nacional'
            ]
        }
        
        # Classification patterns
        self.classification_keywords = {
            'Legislação': [
                'lei', 'decreto', 'portaria', 'resolução', 'instrução normativa',
                'medida provisória', 'constituição', 'emenda constitucional',
                'código', 'regulamento'
            ],
            'Jurisprudência': [
                'acórdão', 'decisão', 'sentença', 'despacho', 'recurso',
                'agravo', 'apelação', 'mandado de segurança', 'ação',
                'embargos', 'habeas corpus'
            ],
            'Doutrina': [
                'artigo', 'livro', 'tese', 'dissertação', 'monografia',
                'paper', 'estudo', 'análise', 'comentário', 'manual'
            ],
            'Proposições': [
                'projeto de lei', 'pl nº', 'pec nº', 'proposta de emenda',
                'indicação', 'requerimento', 'moção', 'projeto de decreto'
            ]
        }
        
        # URN pattern
        self.urn_pattern = re.compile(
            r'urn:lex:br:(federal|[a-z]{2}):([a-z\.\-]+):(\d{4}-\d{2}-\d{2})(;\d+)?',
            re.IGNORECASE
        )


class SimpleAuthorExtractor:
    """Extract author information using pattern matching"""
    
    def __init__(self, processor: SimpleBrazilianLegalProcessor):
        self.processor = processor
        
    def extract_author(self, row) -> Optional[str]:
        """Extract author from various text fields"""
        
        # Priority order: assuntos, titulo, ementa
        text_fields = [
            ('assuntos', row.get('assuntos', '')),
            ('titulo', row.get('titulo', '')),
            ('ementa', row.get('ementa', ''))
        ]
        
        for field_name, text in text_fields:
            if pd.notna(text) and str(text).strip():
                author = self.extract_from_text(str(text))
                if author:
                    return author
        
        # Try institutional author extraction
        combined_text = ' '.join([str(row.get(field, '')) for field in ['titulo', 'ementa', 'assuntos']])
        return self.extract_institutional_author(combined_text)
    
    def extract_from_text(self, text: str) -> Optional[str]:
        """Extract author from text using regex patterns"""
        
        for pattern in self.processor.author_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                author = matches[0].strip()
                if len(author) > 3 and self.is_valid_author_name(author):
                    return self.clean_author_name(author)
        
        return None
    
    def extract_institutional_author(self, text: str) -> Optional[str]:
        """Extract institutional author"""
        text_upper = text.upper()
        
        # Check all institutional pattern categories
        for category, patterns in self.processor.institutional_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, text_upper, re.IGNORECASE)
                if match:
                    return match.group(0)
        
        return None
    
    def is_valid_author_name(self, name: str) -> bool:
        """Check if the extracted name looks valid"""
        name = name.strip()
        
        # Too short or generic
        if len(name) < 3:
            return False
        
        # Generic terms to exclude
        exclude_terms = ['autor', 'autoria', 'elaborado', 'proposto', 'relator', 'relatoria']
        if name.lower() in exclude_terms:
            return False
        
        # Should not be just numbers or symbols
        if re.match(r'^[\d\s\-\.,;:]+$', name):
            return False
        
        return True
    
    def clean_author_name(self, author: str) -> str:
        """Clean and standardize author name"""
        # Remove common prefixes
        author = re.sub(r'^(Autor[ia]?:|De autoria de:|Elaborado por:|Proposto por:|Relator[a]?:)\s*', '', author, flags=re.IGNORECASE)
        
        # Remove trailing punctuation and extra info
        author = re.sub(r'[;,].*$', '', author)
        
        # Clean whitespace
        author = ' '.join(author.split())
        
        # Basic capitalization for person names
        if len(author.split()) >= 2 and not any(char.isupper() for char in author[1:]):
            words = author.split()
            capitalized = []
            for word in words:
                if word.lower() in ['de', 'da', 'do', 'dos', 'das', 'e']:
                    capitalized.append(word.lower())
                else:
                    capitalized.append(word.capitalize())
            author = ' '.join(capitalized)
        
        return author.strip()


class SimpleClassificationInferencer:
    """Infer document classification using keyword matching"""
    
    def __init__(self, processor: SimpleBrazilianLegalProcessor):
        self.processor = processor
        
    def infer_classification(self, row) -> Tuple[Optional[str], float]:
        """Infer document classification with confidence score"""
        
        # Combine text fields for analysis
        text_fields = [
            str(row.get('titulo', '')),
            str(row.get('tipo', '')),
            str(row.get('ementa', ''))[:200]  # Limit ementa length
        ]
        
        combined_text = ' '.join(text_fields).lower()
        
        if not combined_text.strip():
            return None, 0.0
        
        # Score each category
        category_scores = {}
        
        for category, keywords in self.processor.classification_keywords.items():
            score = 0
            matches = []
            
            for keyword in keywords:
                # Count occurrences of each keyword
                pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
                keyword_matches = len(re.findall(pattern, combined_text))
                if keyword_matches > 0:
                    score += keyword_matches
                    matches.append(keyword)
            
            if score > 0:
                category_scores[category] = {
                    'score': score,
                    'matches': matches,
                    'confidence': min(0.9, score * 0.1 + 0.5)  # Scale confidence
                }
        
        if not category_scores:
            return None, 0.0
        
        # Find best category
        best_category = max(category_scores.keys(), key=lambda k: category_scores[k]['score'])
        confidence = category_scores[best_category]['confidence']
        
        # Minimum confidence threshold
        if confidence < 0.6:
            return None, confidence
        
        return best_category, confidence


class SimpleGeographicEnhancer:
    """Enhance geographic information using pattern matching"""
    
    def __init__(self, processor: SimpleBrazilianLegalProcessor):
        self.processor = processor
        
    def enhance_geographic_data(self, row) -> Dict[str, Optional[str]]:
        """Extract and enhance geographic information"""
        
        result = {
            'estado': row.get('estado'),
            'municipio': row.get('municipio'),
            'jurisdicao': row.get('jurisdicao'),
            'confidence': 0.0
        }
        
        # Combine text for analysis
        text_fields = [
            str(row.get('titulo', '')),
            str(row.get('ementa', ''))[:300],  # Limit length
            str(row.get('assuntos', ''))[:200]
        ]
        
        combined_text = ' '.join(text_fields)
        
        # Extract state if missing
        if pd.isna(result['estado']) or result['estado'] == '':
            extracted_state = self.extract_state(combined_text)
            if extracted_state:
                result['estado'] = extracted_state
                result['confidence'] = max(result['confidence'], 0.7)
        
        # Extract municipality if missing
        if pd.isna(result['municipio']) or result['municipio'] == '':
            extracted_municipality = self.extract_municipality(combined_text, result['estado'])
            if extracted_municipality:
                result['municipio'] = extracted_municipality
                result['confidence'] = max(result['confidence'], 0.6)
        
        # Infer jurisdiction if missing
        if pd.isna(result['jurisdicao']) or result['jurisdicao'] == '':
            result['jurisdicao'] = self.infer_jurisdiction(result, combined_text)
        
        return result
    
    def extract_state(self, text: str) -> Optional[str]:
        """Extract state information from text"""
        text_upper = text.upper()
        
        # Look for state abbreviations
        for abbr in self.processor.states_mapping.keys():
            # Check for abbreviation with word boundaries
            if re.search(rf'\b{abbr}\b', text_upper):
                return abbr
        
        # Look for full state names
        for abbr, full_name in self.processor.states_mapping.items():
            if full_name.upper() in text_upper:
                return abbr
        
        # Look for federal indicators
        federal_patterns = [
            r'\bFEDERAL\b', r'\bUNIÃO\b', r'\bREPÚBLICA\b',
            r'CONGRESSO NACIONAL', r'PRESIDÊNCIA'
        ]
        
        for pattern in federal_patterns:
            if re.search(pattern, text_upper):
                return 'Federal'
        
        return None
    
    def extract_municipality(self, text: str, state: Optional[str] = None) -> Optional[str]:
        """Extract municipality information from text"""
        
        if not state or state == 'Federal':
            return None
        
        text_lower = text.lower()
        
        # Look for major cities in the identified state
        if state in self.processor.major_cities:
            for city in self.processor.major_cities[state]:
                city_lower = city.lower()
                
                # Exact match
                if city_lower in text_lower:
                    return city
                
                # Check for partial matches (city name + common suffixes)
                city_patterns = [
                    rf'\b{re.escape(city_lower)}\b',
                    rf'\b{re.escape(city_lower)}\s+\([^)]*\)',  # City (State)
                    rf'município\s+de\s+{re.escape(city_lower)}\b',
                    rf'prefeitura\s+(?:municipal\s+)?(?:de\s+)?{re.escape(city_lower)}\b'
                ]
                
                for pattern in city_patterns:
                    if re.search(pattern, text_lower):
                        return city
        
        # Look for municipality indicators + capitalized words
        municipality_patterns = [
            r'município\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+?)(?:\s|$|[,;.])',
            r'prefeitura\s+(?:municipal\s+)?(?:de\s+)?([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+?)(?:\s|$|[,;.])',
            r'cidade\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s]+?)(?:\s|$|[,;.])'
        ]
        
        for pattern in municipality_patterns:
            matches = re.findall(pattern, text)
            if matches:
                municipality = matches[0].strip()
                if self.is_valid_municipality_name(municipality):
                    return municipality
        
        return None
    
    def is_valid_municipality_name(self, name: str) -> bool:
        """Check if name looks like a valid municipality"""
        name = name.strip()
        
        # Basic checks
        if len(name) < 3 or len(name) > 50:
            return False
        
        # Should contain only letters, spaces, and hyphens
        if not re.match(r'^[A-Za-záàâãéêíóôõúçÁÀÂÃÉÊÍÓÔÕÚÇ\s\-\']+$', name):
            return False
        
        # Should not be common words that aren't city names
        common_words = ['brasil', 'estado', 'município', 'prefeitura', 'cidade', 'federal']
        if name.lower() in common_words:
            return False
        
        return True
    
    def infer_jurisdiction(self, geo_result: Dict, text: str) -> Optional[str]:
        """Infer jurisdiction level"""
        
        # Federal level indicators
        federal_indicators = [
            'ANTT', 'ANTAQ', 'ANAC', 'ANP', 'ANEEL', 'ANVISA',
            'Ministério', 'Federal', 'República', 'Congresso Nacional',
            'Câmara dos Deputados', 'Senado Federal', 'STF', 'STJ'
        ]
        
        text_upper = text.upper()
        for indicator in federal_indicators:
            if indicator.upper() in text_upper:
                return 'Federal'
        
        # Municipal level
        if geo_result.get('municipio'):
            municipal_indicators = ['município', 'prefeitura', 'câmara municipal', 'vereador']
            text_lower = text.lower()
            for indicator in municipal_indicators:
                if indicator in text_lower:
                    return 'Municipal'
            # Default to municipal if we have a municipality
            return 'Municipal'
        
        # State level
        if geo_result.get('estado') and geo_result['estado'] != 'Federal':
            state_indicators = ['estado', 'governo estadual', 'assembleia legislativa', 'tribunal de justiça']
            text_lower = text.lower()
            for indicator in state_indicators:
                if indicator in text_lower:
                    return 'Estadual'
            # If we have a non-federal state but no municipality, likely state level
            if not geo_result.get('municipio'):
                return 'Estadual'
        
        return None


class SimpleURNValidator:
    """Validate and reconstruct URN identifiers"""
    
    def __init__(self, processor: SimpleBrazilianLegalProcessor):
        self.processor = processor
        
        # Document type mapping for URN construction
        self.doc_type_mapping = {
            'lei': ['lei'],
            'decreto': ['decreto'],
            'portaria': ['portaria'],
            'resolucao': ['resolução', 'resolucao'],
            'instrucao.normativa': ['instrução normativa', 'instrucao normativa'],
            'medida.provisoria': ['medida provisória', 'medida provisoria', 'mp'],
            'emenda.constitucional': ['emenda constitucional'],
            'projeto.de.lei': ['projeto de lei', 'pl']
        }
    
    def validate_and_fix_urn(self, row) -> Optional[str]:
        """Validate existing URN or reconstruct if possible"""
        
        existing_urn = row.get('urn')
        
        # If we have a URN, validate it
        if pd.notna(existing_urn) and existing_urn.strip():
            if self.processor.urn_pattern.match(str(existing_urn).strip()):
                return str(existing_urn).strip()  # Valid URN
        
        # Try to reconstruct URN
        return self.reconstruct_urn(row)
    
    def reconstruct_urn(self, row) -> Optional[str]:
        """Reconstruct URN from document metadata"""
        
        # Extract components
        jurisdiction = self.extract_jurisdiction_for_urn(row)
        doc_type = self.extract_document_type_for_urn(row)
        date = self.extract_date_for_urn(row)
        number = self.extract_number_for_urn(row)
        
        if not all([jurisdiction, doc_type, date]):
            return None
        
        # Build URN
        urn_parts = ['urn', 'lex', 'br', jurisdiction, doc_type, date]
        urn_base = ':'.join(urn_parts)
        
        if number:
            return f"{urn_base};{number}"
        else:
            return urn_base
    
    def extract_jurisdiction_for_urn(self, row) -> Optional[str]:
        """Extract jurisdiction for URN"""
        estado = row.get('estado')
        jurisdicao = row.get('jurisdicao')
        
        if estado == 'Federal' or jurisdicao == 'Federal':
            return 'federal'
        elif estado and len(str(estado)) == 2 and str(estado) != 'nan':
            return str(estado).lower()
        elif jurisdicao in ['Estadual', 'Municipal'] and estado and len(str(estado)) == 2:
            return str(estado).lower()
        
        return 'federal'  # Default fallback
    
    def extract_document_type_for_urn(self, row) -> Optional[str]:
        """Extract document type for URN"""
        titulo = str(row.get('titulo', '')).lower()
        tipo = str(row.get('tipo', '')).lower()
        
        combined_text = f"{titulo} {tipo}"
        
        # Match against known types
        for urn_type, variations in self.doc_type_mapping.items():
            for variation in variations:
                if variation.lower() in combined_text:
                    return urn_type
        
        # Common pattern matching
        if re.search(r'\blei\s+n[°º]?\s*\d+', titulo):
            return 'lei'
        elif re.search(r'\bdecreto\s+n[°º]?\s*\d+', titulo):
            return 'decreto'
        elif re.search(r'\bportaria\s+n[°º]?\s*\d+', titulo):
            return 'portaria'
        elif re.search(r'\bresolução\s+n[°º]?\s*\d+', titulo):
            return 'resolucao'
        elif re.search(r'\bmedida\s+provisória\s+n[°º]?\s*\d+', titulo):
            return 'medida.provisoria'
        
        return None
    
    def extract_date_for_urn(self, row) -> Optional[str]:
        """Extract and format date for URN"""
        data = row.get('data')
        
        if pd.isna(data):
            return None
        
        try:
            # Handle different date formats
            if isinstance(data, str):
                data_str = data.strip()
                
                # Try YYYY-MM-DD format
                if re.match(r'^\d{4}-\d{2}-\d{2}$', data_str):
                    return data_str
                
                # Try DD/MM/YYYY format
                date_match = re.match(r'^(\d{1,2})/(\d{1,2})/(\d{4})$', data_str)
                if date_match:
                    day, month, year = date_match.groups()
                    return f"{year}-{month.zfill(2)}-{day.zfill(2)}"
                
                # Try YYYY format (year only)
                if re.match(r'^\d{4}$', data_str):
                    return f"{data_str}-01-01"
                    
                # Try to parse as pandas datetime
                parsed_date = pd.to_datetime(data_str, errors='coerce')
                if pd.notna(parsed_date):
                    return parsed_date.strftime('%Y-%m-%d')
            
            # If data is already datetime-like
            elif hasattr(data, 'strftime'):
                return data.strftime('%Y-%m-%d')
                
        except Exception:
            pass
        
        return None
    
    def extract_number_for_urn(self, row) -> Optional[str]:
        """Extract document number for URN"""
        numero = row.get('numero')
        titulo = str(row.get('titulo', ''))
        
        # Use existing number field if available
        if pd.notna(numero) and str(numero).strip() and str(numero) != 'nan':
            return str(numero).strip()
        
        # Extract from title
        number_patterns = [
            r'n[°º]\s*(\d+)',
            r'número\s*(\d+)',
            r'/(\d{4})',  # Year suffix like /2023
            r'(\d+)/\d{4}',  # Number/year format like 123/2023
            r'(\d+)\s*,?\s*de\s+\d{1,2}',  # Number followed by date
        ]
        
        for pattern in number_patterns:
            matches = re.findall(pattern, titulo, re.IGNORECASE)
            if matches:
                # Take the first number found
                number = matches[0].strip()
                if number.isdigit() and len(number) <= 6:  # Reasonable number length
                    return number
        
        return None


class SimpleDataQualityEnhancer:
    """Main coordinator for simplified data quality enhancement"""
    
    def __init__(self, data_path: str):
        """Initialize the enhancement framework"""
        self.data_path = data_path
        
        # Initialize processors
        self.processor = SimpleBrazilianLegalProcessor()
        self.author_extractor = SimpleAuthorExtractor(self.processor)
        self.classifier = SimpleClassificationInferencer(self.processor)
        self.geo_enhancer = SimpleGeographicEnhancer(self.processor)
        self.urn_validator = SimpleURNValidator(self.processor)
        
        # Load data
        logger.info(f"Loading data from {data_path}")
        self.df = pd.read_csv(data_path, low_memory=False)
        logger.info(f"Loaded {len(self.df):,} documents")
        
        # Calculate baseline metrics
        self.baseline_metrics = self.calculate_baseline_metrics()
        
    def calculate_baseline_metrics(self) -> Dict[str, float]:
        """Calculate baseline data quality metrics"""
        metrics = {}
        
        for column in ['autor', 'classificacao', 'municipio', 'estado', 'urn']:
            if column in self.df.columns:
                total = len(self.df)
                if self.df[column].dtype == 'object':
                    complete = ((self.df[column].notna()) & 
                              (self.df[column] != '') & 
                              (self.df[column].astype(str).str.len() > 2)).sum()
                else:
                    complete = self.df[column].notna().sum()
                
                completeness = (complete / total) * 100
                metrics[column] = completeness
        
        # Overall completeness
        if metrics:
            metrics['overall'] = sum(metrics.values()) / len(metrics)
        
        logger.info(f"Baseline overall completeness: {metrics.get('overall', 0):.1f}%")
        return metrics
    
    def enhance_data(self, batch_size: int = 1000) -> pd.DataFrame:
        """Enhance data using rule-based techniques"""
        logger.info("Starting data enhancement...")
        
        enhanced_df = self.df.copy()
        total_batches = (len(enhanced_df) - 1) // batch_size + 1
        
        enhancement_stats = {
            'author_enhanced': 0,
            'classification_enhanced': 0,
            'geographic_enhanced': 0,
            'urn_enhanced': 0
        }
        
        # Process in batches
        for i in range(0, len(enhanced_df), batch_size):
            batch_num = i // batch_size + 1
            batch_end = min(i + batch_size, len(enhanced_df))
            
            logger.info(f"Processing batch {batch_num}/{total_batches} ({i+1}-{batch_end})")
            
            for idx in range(i, batch_end):
                row = enhanced_df.iloc[idx]
                
                # 1. Author Enhancement
                if pd.isna(row['autor']) or str(row['autor']).strip() == '' or str(row['autor']) == 'nan':
                    author = self.author_extractor.extract_author(row)
                    if author:
                        enhanced_df.at[idx, 'autor'] = author
                        enhancement_stats['author_enhanced'] += 1
                
                # 2. Classification Enhancement
                if pd.isna(row['classificacao']) or str(row['classificacao']).strip() == '' or str(row['classificacao']) == 'nan':
                    classification, confidence = self.classifier.infer_classification(row)
                    if classification and confidence > 0.6:
                        enhanced_df.at[idx, 'classificacao'] = classification
                        enhancement_stats['classification_enhanced'] += 1
                
                # 3. Geographic Enhancement
                geo_enhancement = self.geo_enhancer.enhance_geographic_data(row)
                if geo_enhancement['confidence'] > 0.5:
                    
                    if geo_enhancement['estado'] and (pd.isna(row['estado']) or str(row['estado']).strip() == '' or str(row['estado']) == 'nan'):
                        enhanced_df.at[idx, 'estado'] = geo_enhancement['estado']
                        enhancement_stats['geographic_enhanced'] += 1
                    
                    if geo_enhancement['municipio'] and (pd.isna(row['municipio']) or str(row['municipio']).strip() == '' or str(row['municipio']) == 'nan'):
                        enhanced_df.at[idx, 'municipio'] = geo_enhancement['municipio']
                        enhancement_stats['geographic_enhanced'] += 1
                    
                    if geo_enhancement['jurisdicao'] and (pd.isna(row['jurisdicao']) or str(row['jurisdicao']).strip() == '' or str(row['jurisdicao']) == 'nan'):
                        enhanced_df.at[idx, 'jurisdicao'] = geo_enhancement['jurisdicao']
                
                # 4. URN Enhancement
                if pd.isna(row['urn']) or str(row['urn']).strip() == '' or str(row['urn']) == 'nan':
                    # Use updated row data for URN reconstruction
                    updated_row = enhanced_df.iloc[idx]
                    urn = self.urn_validator.validate_and_fix_urn(updated_row)
                    if urn:
                        enhanced_df.at[idx, 'urn'] = urn
                        enhancement_stats['urn_enhanced'] += 1
            
            # Log progress
            if batch_num % 10 == 0 or batch_num == total_batches:
                logger.info(f"Enhancement progress: Authors: {enhancement_stats['author_enhanced']}, "
                          f"Classifications: {enhancement_stats['classification_enhanced']}, "
                          f"Geographic: {enhancement_stats['geographic_enhanced']}, "
                          f"URNs: {enhancement_stats['urn_enhanced']}")
        
        # Calculate final metrics and log improvement
        final_metrics = self.calculate_final_metrics(enhanced_df)
        self.log_improvement_summary(final_metrics, enhancement_stats)
        
        return enhanced_df
    
    def calculate_final_metrics(self, enhanced_df: pd.DataFrame) -> Dict[str, float]:
        """Calculate final quality metrics"""
        metrics = {}
        
        for column in ['autor', 'classificacao', 'municipio', 'estado', 'urn']:
            if column in enhanced_df.columns:
                total = len(enhanced_df)
                if enhanced_df[column].dtype == 'object':
                    complete = ((enhanced_df[column].notna()) & 
                              (enhanced_df[column] != '') & 
                              (enhanced_df[column].astype(str).str.len() > 2) &
                              (enhanced_df[column].astype(str) != 'nan')).sum()
                else:
                    complete = enhanced_df[column].notna().sum()
                
                completeness = (complete / total) * 100
                metrics[column] = completeness
        
        if metrics:
            metrics['overall'] = sum(metrics.values()) / len(metrics)
        
        return metrics
    
    def log_improvement_summary(self, final_metrics: Dict[str, float], enhancement_stats: Dict[str, int]):
        """Log comprehensive improvement summary"""
        logger.info("=" * 80)
        logger.info("DATA QUALITY ENHANCEMENT SUMMARY")
        logger.info("=" * 80)
        
        # Enhancement counts
        logger.info(f"ENHANCEMENT STATISTICS:")
        logger.info(f"  Authors enhanced: {enhancement_stats['author_enhanced']:,}")
        logger.info(f"  Classifications enhanced: {enhancement_stats['classification_enhanced']:,}")
        logger.info(f"  Geographic data enhanced: {enhancement_stats['geographic_enhanced']:,}")
        logger.info(f"  URNs enhanced: {enhancement_stats['urn_enhanced']:,}")
        
        logger.info(f"\nCOMPLETENESS IMPROVEMENTS:")
        
        critical_fields = ['autor', 'classificacao', 'municipio', 'estado', 'urn']
        
        for field in critical_fields:
            if field in self.baseline_metrics and field in final_metrics:
                baseline = self.baseline_metrics[field]
                final = final_metrics[field]
                improvement = final - baseline
                
                logger.info(f"  {field.upper()}: {baseline:.1f}% → {final:.1f}% (+{improvement:.1f}%)")
        
        # Overall improvement
        if 'overall' in self.baseline_metrics and 'overall' in final_metrics:
            baseline_overall = self.baseline_metrics['overall']
            final_overall = final_metrics['overall']
            overall_improvement = final_overall - baseline_overall
            
            logger.info(f"\n  OVERALL COMPLETENESS: {baseline_overall:.1f}% → {final_overall:.1f}% (+{overall_improvement:.1f}%)")
            
            if final_overall >= 90.0:
                logger.info("🎯 TARGET ACHIEVED: 90% completeness reached!")
            else:
                remaining = 90.0 - final_overall
                logger.info(f"📈 PROGRESS: {remaining:.1f}% remaining to reach 90% target")
        
        logger.info("=" * 80)
    
    def save_enhanced_data(self, enhanced_df: pd.DataFrame, output_path: str):
        """Save enhanced data and generate quality report"""
        logger.info(f"Saving enhanced data to {output_path}")
        enhanced_df.to_csv(output_path, index=False, encoding='utf-8')
        
        # Generate quality report
        final_metrics = self.calculate_final_metrics(enhanced_df)
        
        quality_report = {
            'enhancement_summary': {
                'timestamp': datetime.now().isoformat(),
                'total_documents': len(enhanced_df),
                'baseline_metrics': self.baseline_metrics,
                'final_metrics': final_metrics,
                'improvements': {
                    field: final_metrics.get(field, 0) - self.baseline_metrics.get(field, 0)
                    for field in ['autor', 'classificacao', 'municipio', 'estado', 'urn']
                    if field in final_metrics and field in self.baseline_metrics
                }
            },
            'target_achievement': {
                'overall_90_percent': final_metrics.get('overall', 0) >= 90,
                'author_80_percent': final_metrics.get('autor', 0) >= 80,
                'classification_85_percent': final_metrics.get('classificacao', 0) >= 85,
                'geographic_80_percent': final_metrics.get('municipio', 0) >= 80,
                'urn_98_percent': final_metrics.get('urn', 0) >= 98
            },
            'field_completeness': {
                field: final_metrics.get(field, 0)
                for field in enhanced_df.columns
            }
        }
        
        # Save report
        report_path = output_path.replace('.csv', '_quality_report.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(quality_report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Quality report saved to {report_path}")
        
        return quality_report


def main():
    """Main execution function"""
    
    # Configuration
    DATA_PATH = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao/lexml_dataset_limpo_classificado_20250722_102507_com_localizacao.csv"
    OUTPUT_PATH = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/enhanced/lexml_dataset_enhanced_simple.csv"
    
    try:
        # Initialize enhancer
        enhancer = SimpleDataQualityEnhancer(DATA_PATH)
        
        # Perform enhancement
        enhanced_data = enhancer.enhance_data(batch_size=500)
        
        # Save results
        quality_report = enhancer.save_enhanced_data(enhanced_data, OUTPUT_PATH)
        
        # Print final summary
        print("\n" + "="*80)
        print("DATA QUALITY ENHANCEMENT COMPLETED")
        print("="*80)
        print(f"Total documents processed: {len(enhanced_data):,}")
        print(f"Final overall completeness: {quality_report['enhancement_summary']['final_metrics'].get('overall', 0):.1f}%")
        print(f"Target achievement (90%): {'✅ YES' if quality_report['target_achievement']['overall_90_percent'] else '❌ NO'}")
        print("="*80)
        
        logger.info("Data quality enhancement completed successfully!")
        
    except Exception as e:
        logger.error(f"Enhancement failed: {e}")
        raise

if __name__ == "__main__":
    main()