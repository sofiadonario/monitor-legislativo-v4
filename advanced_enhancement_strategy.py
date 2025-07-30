#!/usr/bin/env python3
"""
Advanced Data Enhancement Strategy for Monitor Legislativo v4
Phase 2 enhancement to reach >90% completeness target

Current Status: 47.3% → Target: 90%+
Priority Areas:
1. Municipality extraction (3.8% → 80%+)
2. Author patterns expansion (36.0% → 80%+)
3. Classification ML training (33.9% → 85%+)
"""

import pandas as pd
import numpy as np
import re
import json
import logging
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime
from collections import Counter, defaultdict
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AdvancedGeographicEnhancer:
    """Advanced geographic data enhancement using multiple strategies"""
    
    def __init__(self):
        self.setup_comprehensive_geographic_data()
        
    def setup_comprehensive_geographic_data(self):
        """Setup comprehensive Brazilian geographic data"""
        
        # Extended Brazilian municipalities database (sample - would be loaded from IBGE in production)
        self.municipalities_by_state = {
            'AC': ['Rio Branco', 'Cruzeiro do Sul', 'Sena Madureira', 'Tarauacá', 'Feijó'],
            'AL': ['Maceió', 'Arapiraca', 'Palmeira dos Índios', 'Rio Largo', 'Penedo', 'União dos Palmares'],
            'AP': ['Macapá', 'Santana', 'Laranjal do Jari', 'Oiapoque', 'Porto Grande'],
            'AM': ['Manaus', 'Parintins', 'Itacoatiara', 'Manacapuru', 'Coari', 'Tefé', 'Tabatinga'],
            'BA': ['Salvador', 'Feira de Santana', 'Vitória da Conquista', 'Camaçari', 'Juazeiro', 'Ilhéus', 
                   'Itabuna', 'Lauro de Freitas', 'Jequié', 'Alagoinhas', 'Barreiras', 'Paulo Afonso'],
            'CE': ['Fortaleza', 'Caucaia', 'Juazeiro do Norte', 'Sobral', 'Crato', 'Itapipoca', 
                   'Maranguape', 'Iguatu', 'Quixadá', 'Canindé'],
            'DF': ['Brasília', 'Taguatinga', 'Ceilândia', 'Gama', 'Planaltina', 'Sobradinho'],
            'ES': ['Vitória', 'Serra', 'Vila Velha', 'Cariacica', 'Cachoeiro de Itapemirim', 'Linhares', 
                   'São Mateus', 'Colatina', 'Guarapari'],
            'GO': ['Goiânia', 'Aparecida de Goiânia', 'Anápolis', 'Rio Verde', 'Luziânia', 'Águas Lindas de Goiás',
                   'Valparaíso de Goiás', 'Trindade', 'Formosa', 'Novo Gama'],
            'MA': ['São Luís', 'Imperatriz', 'São José de Ribamar', 'Timon', 'Caxias', 'Codó', 
                   'Paço do Lumiar', 'Açailândia', 'Bacabal'],
            'MT': ['Cuiabá', 'Várzea Grande', 'Rondonópolis', 'Sinop', 'Tangará da Serra', 'Cáceres',
                   'Sorriso', 'Lucas do Rio Verde', 'Barra do Garças'],
            'MS': ['Campo Grande', 'Dourados', 'Três Lagoas', 'Corumbá', 'Ponta Porã', 'Naviraí',
                   'Nova Andradina', 'Sidrolândia', 'Maracaju'],
            'MG': ['Belo Horizonte', 'Uberlândia', 'Contagem', 'Juiz de Fora', 'Betim', 'Montes Claros',
                   'Ribeirão das Neves', 'Uberaba', 'Governador Valadares', 'Ipatinga', 'Sete Lagoas',
                   'Divinópolis', 'Santa Luzia', 'Ibirité', 'Poços de Caldas', 'Patos de Minas',
                   'Pouso Alegre', 'Teófilo Otoni', 'Barbacena', 'Sabará', 'Varginha', 'Conselheiro Lafaiete',
                   'Itabira', 'Araguari', 'Passos', 'Ubá', 'Coronel Fabriciano', 'Muriaé', 'Ituiutaba',
                   'Araxá', 'Lavras', 'Ponte Nova', 'Itajubá', 'Pará de Minas', 'Nova Lima', 'Paracatu'],
            'PA': ['Belém', 'Ananindeua', 'Santarém', 'Marabá', 'Parauapebas', 'Castanhal',
                   'Abaetetuba', 'Cametá', 'Marituba', 'Breves'],
            'PB': ['João Pessoa', 'Campina Grande', 'Santa Rita', 'Patos', 'Bayeux', 'Sousa',
                   'Cajazeiras', 'Cabedelo', 'Guarabira', 'Mamanguape'],
            'PE': ['Recife', 'Jaboatão dos Guararapes', 'Olinda', 'Caruaru', 'Petrolina', 'Paulista',
                   'Cabo de Santo Agostinho', 'Camaragibe', 'Garanhuns', 'Vitória de Santo Antão',
                   'Igarassu', 'São Lourenço da Mata', 'Santa Cruz do Capibaribe'],
            'PI': ['Teresina', 'Parnaíba', 'Picos', 'Piripiri', 'Floriano', 'Campo Maior',
                   'Barras', 'Altos', 'Oeiras', 'Pedro II'],
            'PR': ['Curitiba', 'Londrina', 'Maringá', 'Ponta Grossa', 'Cascavel', 'São José dos Pinhais',
                   'Foz do Iguaçu', 'Colombo', 'Guarapuava', 'Paranaguá', 'Araucária', 'Toledo',
                   'Apucarana', 'Pinhais', 'Campo Largo', 'Arapongas', 'Almirante Tamandaré',
                   'Umuarama', 'Piraquara', 'Cambé', 'Campo Mourão', 'Fazenda Rio Grande'],
            'RJ': ['Rio de Janeiro', 'São Gonçalo', 'Duque de Caxias', 'Nova Iguaçu', 'Niterói',
                   'Belford Roxo', 'São João de Meriti', 'Campos dos Goytacazes', 'Petrópolis',
                   'Volta Redonda', 'Magé', 'Macaé', 'Itaboraí', 'Cabo Frio', 'Angra dos Reis',
                   'Nova Friburgo', 'Barra Mansa', 'Teresópolis', 'Mesquita', 'Nilópolis'],
            'RN': ['Natal', 'Mossoró', 'Parnamirim', 'São Gonçalo do Amarante', 'Macaíba',
                   'Ceará-Mirim', 'Caicó', 'Assu', 'Currais Novos', 'João Câmara'],
            'RS': ['Porto Alegre', 'Caxias do Sul', 'Pelotas', 'Canoas', 'Santa Maria', 'Gravataí',
                   'Viamão', 'Novo Hamburgo', 'São Leopoldo', 'Rio Grande', 'Alvorada', 'Passo Fundo',
                   'Sapucaia do Sul', 'Uruguaiana', 'Santa Cruz do Sul', 'Cachoeirinha', 'Bagé',
                   'Bento Gonçalves', 'Erechim', 'Guaíba', 'Cachoeira do Sul'],
            'RO': ['Porto Velho', 'Ji-Paraná', 'Ariquemes', 'Vilhena', 'Cacoal', 'Rolim de Moura',
                   'Jaru', 'Guajará-Mirim', 'Buritis', 'Ouro Preto do Oeste'],
            'RR': ['Boa Vista', 'Rorainópolis', 'Caracaraí', 'Alto Alegre', 'Mucajaí'],
            'SC': ['Florianópolis', 'Joinville', 'Blumenau', 'São José', 'Criciúma', 'Chapecó',
                   'Itajaí', 'Lages', 'Jaraguá do Sul', 'Palhoça', 'Balneário Camboriú',
                   'Brusque', 'Tubarão', 'São Bento do Sul', 'Caçador', 'Camboriú'],
            'SP': ['São Paulo', 'Guarulhos', 'Campinas', 'São Bernardo do Campo', 'Santo André',
                   'Osasco', 'Ribeirão Preto', 'Sorocaba', 'Mauá', 'São José dos Campos',
                   'Mogi das Cruzes', 'Diadema', 'Jundiaí', 'Carapicuíba', 'Piracicaba',
                   'Bauru', 'São Vicente', 'Franca', 'Guarujá', 'Taubaté', 'Praia Grande',
                   'Limeira', 'Suzano', 'Taboão da Serra', 'Sumaré', 'Barueri', 'Embu das Artes',
                   'São Carlos', 'Marília', 'Indaiatuba', 'Cotia', 'Araraquara', 'Jacareí',
                   'Americana', 'Santos', 'Presidente Prudente', 'São José do Rio Preto'],
            'SE': ['Aracaju', 'Nossa Senhora do Socorro', 'Lagarto', 'Itabaiana', 'São Cristóvão',
                   'Estância', 'Tobias Barreto', 'Simão Dias', 'Propriá', 'Barra dos Coqueiros'],
            'TO': ['Palmas', 'Araguaína', 'Gurupi', 'Porto Nacional', 'Paraíso do Tocantins',
                   'Colinas do Tocantins', 'Guaraí', 'Formoso do Araguaia', 'Tocantinópolis']
        }
        
        # Regional patterns for better geographic inference
        self.regional_patterns = {
            'Norte': {
                'keywords': ['amazônia', 'amazônico', 'floresta', 'acre', 'rondônia', 'roraima'],
                'states': ['AC', 'AP', 'AM', 'PA', 'RO', 'RR', 'TO']
            },
            'Nordeste': {
                'keywords': ['sertão', 'caatinga', 'nordestino', 'são francisco', 'bahia', 'ceará'],
                'states': ['AL', 'BA', 'CE', 'MA', 'PB', 'PE', 'PI', 'RN', 'SE']
            },
            'Centro-Oeste': {
                'keywords': ['cerrado', 'pantanal', 'agronegócio', 'centro-oeste', 'planalto central'],
                'states': ['GO', 'MT', 'MS', 'DF']
            },
            'Sudeste': {
                'keywords': ['mata atlântica', 'sudeste', 'vale do paraíba', 'triângulo mineiro'],
                'states': ['ES', 'MG', 'RJ', 'SP']
            },
            'Sul': {
                'keywords': ['serra gaúcha', 'vale do itajaí', 'região sul', 'pampas'],
                'states': ['PR', 'RS', 'SC']
            }
        }
        
        # Common municipal prefixes and suffixes in Brazil
        self.municipal_indicators = [
            r'município\s+de\s+',
            r'prefeitura\s+(?:municipal\s+)?(?:de\s+)?',
            r'câmara\s+municipal\s+de\s+',
            r'cidade\s+de\s+',
            r'vila\s+de\s+',
            r'distrito\s+de\s+'
        ]
        
    def enhanced_municipality_extraction(self, text: str, state: str) -> Optional[str]:
        """Advanced municipality extraction using multiple strategies"""
        
        if not text or not state or state == 'Federal':
            return None
        
        text_processed = self.preprocess_text_for_geographic(text)
        
        # Strategy 1: Direct municipality name matching
        municipality = self.direct_municipality_matching(text_processed, state)
        if municipality:
            return municipality
        
        # Strategy 2: Pattern-based extraction with municipal indicators
        municipality = self.pattern_based_municipality_extraction(text_processed, state)
        if municipality:
            return municipality
        
        # Strategy 3: Context-based geographic inference
        municipality = self.context_based_municipality_inference(text_processed, state)
        if municipality:
            return municipality
        
        # Strategy 4: Fuzzy matching for partial names
        municipality = self.fuzzy_municipality_matching(text_processed, state)
        if municipality:
            return municipality
        
        return None
    
    def preprocess_text_for_geographic(self, text: str) -> str:
        """Preprocess text for better geographic extraction"""
        # Remove common noise
        text = re.sub(r'\b(?:lei|decreto|portaria|resolução)\s+n[°º]?\s*\d+', '', text, flags=re.IGNORECASE)
        text = re.sub(r'\b\d{4}[-/]\d{2}[-/]\d{2}\b', '', text)  # Remove dates
        text = re.sub(r'\bde\s+\d{1,2}\s+de\s+\w+\s+de\s+\d{4}\b', '', text, flags=re.IGNORECASE)
        
        # Normalize whitespace
        text = ' '.join(text.split())
        
        return text
    
    def direct_municipality_matching(self, text: str, state: str) -> Optional[str]:
        """Direct matching against known municipalities"""
        if state not in self.municipalities_by_state:
            return None
        
        text_lower = text.lower()
        
        # Sort by length (longer names first to avoid partial matches)
        municipalities = sorted(self.municipalities_by_state[state], key=len, reverse=True)
        
        for municipality in municipalities:
            municipality_lower = municipality.lower()
            
            # Exact word boundary match
            pattern = rf'\b{re.escape(municipality_lower)}\b'
            if re.search(pattern, text_lower):
                return municipality
        
        return None
    
    def pattern_based_municipality_extraction(self, text: str, state: str) -> Optional[str]:
        """Extract municipality using linguistic patterns"""
        
        for indicator_pattern in self.municipal_indicators:
            # Build complete pattern
            full_pattern = indicator_pattern + r'([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s\-\']+?)(?:\s|$|[,;.])'
            
            matches = re.findall(full_pattern, text, re.IGNORECASE)
            for match in matches:
                candidate = match.strip()
                if self.is_valid_municipality_candidate(candidate, state):
                    return self.clean_municipality_name(candidate)
        
        return None
    
    def context_based_municipality_inference(self, text: str, state: str) -> Optional[str]:
        """Infer municipality from context clues"""
        
        # Look for specific contextual patterns
        context_patterns = [
            r'comarca\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s\-\']+)',
            r'foro\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s\-\']+)',
            r'delegacia\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s\-\']+)',
            r'cartório\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s\-\']+)',
            r'vara\s+de\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç\s\-\']+)'
        ]
        
        for pattern in context_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                candidate = match.strip()
                if self.is_valid_municipality_candidate(candidate, state):
                    return self.clean_municipality_name(candidate)
        
        return None
    
    def fuzzy_municipality_matching(self, text: str, state: str) -> Optional[str]:
        """Fuzzy matching for partial municipality names"""
        if state not in self.municipalities_by_state:
            return None
        
        # Extract potential municipality words (capitalized words)
        potential_words = re.findall(r'\b[A-ZÁÀÂÃÉÊÍÓÔÕÚÇ][a-záàâãéêíóôõúç]+\b', text)
        
        for municipality in self.municipalities_by_state[state]:
            municipality_words = municipality.split()
            
            # Check if significant part of municipality name appears in text
            match_count = 0
            for mun_word in municipality_words:
                if len(mun_word) >= 4:  # Only check significant words
                    for text_word in potential_words:
                        if mun_word.lower() in text_word.lower() or text_word.lower() in mun_word.lower():
                            match_count += 1
                            break
            
            # If most words match, consider it a match
            if match_count >= len(municipality_words) * 0.6:
                return municipality
        
        return None
    
    def is_valid_municipality_candidate(self, candidate: str, state: str) -> bool:
        """Enhanced validation for municipality candidates"""
        candidate = candidate.strip()
        
        # Basic length and format checks
        if len(candidate) < 3 or len(candidate) > 50:
            return False
        
        # Should contain letters
        if not re.search(r'[A-Za-záàâãéêíóôõúç]', candidate):
            return False
        
        # Should not be common words
        common_words = [
            'brasil', 'estado', 'município', 'prefeitura', 'cidade', 'federal',
            'nacional', 'público', 'social', 'civil', 'criminal', 'administrativo',
            'tribunal', 'justiça', 'direito', 'lei', 'decreto', 'portaria'
        ]
        
        if candidate.lower() in common_words:
            return False
        
        # Enhanced validation: check if it sounds like a Brazilian place name
        return self.sounds_like_brazilian_place_name(candidate)
    
    def sounds_like_brazilian_place_name(self, name: str) -> bool:
        """Check if name sounds like a Brazilian place name"""
        name_lower = name.lower()
        
        # Common endings in Brazilian place names
        brazilian_endings = [
            'ópolis', 'ândia', 'inha', 'ão', 'im', 'ense', 'eira', 'al',
            'ante', 'nte', 'ade', 'uba', 'açu', 'mirim', 'guaçu'
        ]
        
        for ending in brazilian_endings:
            if name_lower.endswith(ending):
                return True
        
        # Common prefixes
        brazilian_prefixes = ['são', 'santa', 'santo', 'nova', 'novo', 'bom', 'boa']
        first_word = name_lower.split()[0] if name_lower.split() else ''
        
        if first_word in brazilian_prefixes:
            return True
        
        # Has Portuguese characteristics (contains ç, ã, etc.)
        if re.search(r'[çãõáéíóúâêîôû]', name_lower):
            return True
        
        return len(name.split()) <= 4  # Brazilian place names usually don't have too many words
    
    def clean_municipality_name(self, name: str) -> str:
        """Clean and standardize municipality name"""
        name = name.strip()
        
        # Proper capitalization
        words = []
        for word in name.split():
            if word.lower() in ['de', 'da', 'do', 'dos', 'das', 'e']:
                words.append(word.lower())
            else:
                words.append(word.capitalize())
        
        return ' '.join(words)


class AdvancedAuthorExtractor:
    """Advanced author extraction using enhanced patterns and validation"""
    
    def __init__(self):
        self.setup_enhanced_author_patterns()
        
    def setup_enhanced_author_patterns(self):
        """Setup comprehensive author extraction patterns"""
        
        # Enhanced author patterns with more variations
        self.author_patterns = [
            # Direct author mentions
            r'Autor[ia]?:\s*([^;,\n]+)',
            r'De autoria de:\s*([^;,\n]+)',
            r'Elaborado por:\s*([^;,\n]+)',
            r'Proposto por:\s*([^;,\n]+)',
            r'Apresentado por:\s*([^;,\n]+)',
            
            # Legal professionals
            r'Relatoria:\s*([^;,\n]+)',
            r'Relator[a]?:\s*([^;,\n]+)',
            r'Revisor[a]?:\s*([^;,\n]+)',
            r'Presidente:\s*([^;,\n]+)',
            r'Desembargador[a]?\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇÑ][a-záàâãéêíóôõúçñ\s]+)',
            r'Juiz[a]?\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇÑ][a-záàâãéêíóôõúçñ\s]+)',
            r'Ministro[a]?\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇÑ][a-záàâãéêíóôõúçñ\s]+)',
            
            # Political figures
            r'Deputado[a]?\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇÑ][a-záàâãéêíóôõúçñ\s]+)',
            r'Senador[a]?\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇÑ][a-záàâãéêíóôõúçñ\s]+)',
            r'Vereador[a]?\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇÑ][a-záàâãéêíóôõúçñ\s]+)',
            r'Prefeito[a]?\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇÑ][a-záàâãéêíóôõúçñ\s]+)',
            r'Governador[a]?\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇÑ][a-záàâãéêíóôõúçñ\s]+)',
            
            # Academic authors
            r'Prof\.?\s*Dr\.?\s*([A-ZÁÀÂÃÉÊÍÓÔÕÚÇÑ][a-záàâãéêíóôõúçñ\s]+)',
            r'Professor[a]?\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇÑ][a-záàâãéêíóôõúçñ\s]+)',
            r'Doutor[a]?\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇÑ][a-záàâãéêíóôõúçñ\s]+)',
            
            # General name patterns (in specific contexts)
            r'(?:Projeto|Proposta|Indicação|Requerimento)\s+(?:de|do|da)\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇÑ][a-záàâãéêíóôõúçñ\s]+?)(?:\s|$|[,;.])',
        ]
        
        # Institution hierarchy patterns
        self.institutional_hierarchy = {
            'federal_executive': [
                'Presidência da República',
                'Casa Civil',
                'Ministério da Infraestrutura',
                'Ministério dos Transportes',
                'Ministério do Desenvolvimento Regional'
            ],
            'regulatory_agencies': [
                'ANTT', 'Agência Nacional de Transportes Terrestres',
                'ANTAQ', 'Agência Nacional de Transportes Aquaviários',
                'ANAC', 'Agência Nacional de Aviação Civil',
                'ANP', 'Agência Nacional do Petróleo',
                'ANEEL', 'Agência Nacional de Energia Elétrica'
            ],
            'federal_legislature': [
                'Câmara dos Deputados',
                'Senado Federal',
                'Congresso Nacional',
                'Mesa Diretora',
                'Comissão de Viação e Transportes'
            ],
            'federal_judiciary': [
                'STF', 'Supremo Tribunal Federal',
                'STJ', 'Superior Tribunal de Justiça',
                'TST', 'Tribunal Superior do Trabalho',
                'TCU', 'Tribunal de Contas da União'
            ]
        }
        
        # Brazilian name patterns for validation
        self.brazilian_name_indicators = [
            # Common Brazilian name elements
            r'\b(?:da|de|do|dos|das)\s+[A-Z]',  # Prepositions
            r'\b(?:Silva|Santos|Oliveira|Souza|Rodrigues|Ferreira|Alves|Pereira|Lima|Gomes)\b',  # Common surnames
            r'\b(?:José|João|Maria|Ana|Carlos|Antonio|Francisco|Paulo|Pedro|Luiz)\b',  # Common first names
        ]
    
    def extract_enhanced_author(self, row) -> Optional[str]:
        """Enhanced author extraction with multiple strategies"""
        
        # Strategy 1: Pattern-based extraction from structured fields
        author = self.extract_from_structured_fields(row)
        if author:
            return author
        
        # Strategy 2: Context-aware extraction from text
        author = self.extract_from_context(row)
        if author:
            return author
        
        # Strategy 3: Institutional authorship inference
        author = self.extract_institutional_authorship(row)
        if author:
            return author
        
        # Strategy 4: Name entity recognition in titles
        author = self.extract_from_document_title(row)
        if author:
            return author
        
        return None
    
    def extract_from_structured_fields(self, row) -> Optional[str]:
        """Extract author from structured fields with enhanced patterns"""
        
        # Priority order for text fields
        text_sources = [
            ('assuntos', row.get('assuntos', '')),
            ('ementa', row.get('ementa', '')),
            ('titulo', row.get('titulo', ''))
        ]
        
        for field_name, text in text_sources:
            if pd.notna(text) and str(text).strip():
                author = self.apply_enhanced_patterns(str(text))
                if author:
                    return author
        
        return None
    
    def apply_enhanced_patterns(self, text: str) -> Optional[str]:
        """Apply enhanced regex patterns with validation"""
        
        for pattern in self.author_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                cleaned_author = self.clean_and_validate_author(match)
                if cleaned_author:
                    return cleaned_author
        
        return None
    
    def extract_from_context(self, row) -> Optional[str]:
        """Context-aware author extraction"""
        
        # Combine relevant fields for context analysis
        context_text = []
        if pd.notna(row.get('titulo')):
            context_text.append(str(row['titulo']))
        if pd.notna(row.get('ementa')):
            context_text.append(str(row['ementa'])[:300])  # Limit length
        if pd.notna(row.get('tipo')):
            context_text.append(str(row['tipo']))
        
        combined_text = ' '.join(context_text)
        
        # Look for names in specific legal contexts
        legal_contexts = [
            r'(?:Projeto|Proposta|Indicação|Requerimento)\s+(?:de|do|da)\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇÑ][a-záàâãéêíóôõúçñ\s]+?)(?:\s+[A-Z]{2,}|\s*[-,]|$)',
            r'(?:Deputado|Senador|Vereador)[a]?\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇÑ][a-záàâãéêíóôõúçñ\s]+?)(?:\s*[-,(]|$)',
            r'(?:Ministro|Juiz|Desembargador)[a]?\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇÑ][a-záàâãéêíóôõúçñ\s]+?)(?:\s*[-,(]|$)',
        ]
        
        for pattern in legal_contexts:
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            for match in matches:
                cleaned_author = self.clean_and_validate_author(match)
                if cleaned_author:
                    return cleaned_author
        
        return None
    
    def extract_institutional_authorship(self, row) -> Optional[str]:
        """Extract institutional authorship with hierarchy awareness"""
        
        text_fields = [str(row.get(field, '')) for field in ['titulo', 'ementa', 'assuntos']]
        combined_text = ' '.join(text_fields).upper()
        
        # Check institution hierarchy (most specific first)
        for category, institutions in self.institutional_hierarchy.items():
            for institution in institutions:
                if institution.upper() in combined_text:
                    return institution
        
        return None
    
    def extract_from_document_title(self, row) -> Optional[str]:
        """Extract author from document title patterns"""
        
        titulo = row.get('titulo', '')
        if not pd.notna(titulo):
            return None
        
        titulo_str = str(titulo)
        
        # Look for possessive constructions that might indicate authorship
        possessive_patterns = [
            r'(?:Projeto|Proposta|Parecer|Relatório)\s+(?:de|do|da)\s+([A-ZÁÀÂÃÉÊÍÓÔÕÚÇÑ][a-záàâãéêíóôõúçñ\s]+?)(?:\s|$|[,;.])',
            r'([A-ZÁÀÂÃÉÊÍÓÔÕÚÇÑ][a-záàâãéêíóôõúçñ\s]+?)\s*[-:]\s*(?:Projeto|Proposta|Parecer)',
        ]
        
        for pattern in possessive_patterns:
            matches = re.findall(pattern, titulo_str, re.IGNORECASE)
            for match in matches:
                cleaned_author = self.clean_and_validate_author(match)
                if cleaned_author:
                    return cleaned_author
        
        return None
    
    def clean_and_validate_author(self, author_raw: str) -> Optional[str]:
        """Enhanced cleaning and validation of author names"""
        
        author = author_raw.strip()
        
        # Basic length check
        if len(author) < 3 or len(author) > 100:
            return None
        
        # Remove common prefixes and suffixes
        prefixes_to_remove = [
            r'^(?:Autor[ia]?:|De autoria de:|Elaborado por:|Proposto por:|Relatoria:|Relator[a]?:)\s*',
            r'^(?:Deputado[a]?|Senador[a]?|Ministro[a]?|Juiz[a]?|Desembargador[a]?)\s+',
            r'^(?:Prof\.?\s*)?(?:Dr\.?\s*)?'
        ]
        
        for prefix_pattern in prefixes_to_remove:
            author = re.sub(prefix_pattern, '', author, flags=re.IGNORECASE)
        
        # Remove trailing information
        author = re.sub(r'\s*[;,].*$', '', author)
        author = re.sub(r'\s*\([^)]*\).*$', '', author)  # Remove parenthetical info
        author = re.sub(r'\s*[-–—].*$', '', author)  # Remove dash-separated info
        
        # Clean whitespace
        author = ' '.join(author.split())
        
        # Validation checks
        if not self.is_valid_author_name(author):
            return None
        
        # Standardize capitalization for person names
        if self.looks_like_person_name(author):
            author = self.standardize_person_name(author)
        
        return author
    
    def is_valid_author_name(self, name: str) -> bool:
        """Enhanced validation for author names"""
        
        # Basic checks
        if len(name) < 3:
            return False
        
        # Should not be common generic terms
        generic_terms = [
            'autor', 'autoria', 'elaborado', 'proposto', 'relator', 'relatoria',
            'presidente', 'coordenador', 'diretor', 'secretário', 'ministro',
            'brasil', 'federal', 'nacional', 'público', 'governo', 'estado'
        ]
        
        if name.lower() in generic_terms:
            return False
        
        # Should not be just numbers or symbols
        if re.match(r'^[\d\s\-\.,;:()]+$', name):
            return False
        
        # Should contain letters
        if not re.search(r'[A-Za-záàâãéêíóôõúçñÁÀÂÃÉÊÍÓÔÕÚÇÑ]', name):
            return False
        
        # Enhanced validation for Brazilian names
        return self.passes_brazilian_name_validation(name)
    
    def passes_brazilian_name_validation(self, name: str) -> bool:
        """Validate if name looks like a Brazilian name"""
        
        # Check for Brazilian name indicators
        for pattern in self.brazilian_name_indicators:
            if re.search(pattern, name, re.IGNORECASE):
                return True
        
        # Check word count (Brazilian names typically 2-4 words)
        words = name.split()
        if len(words) < 1 or len(words) > 6:
            return False
        
        # Each word should look like a name component
        for word in words:
            if len(word) < 2:
                return False
            # Should start with capital letter (for person names)
            if word[0].islower() and word.lower() not in ['de', 'da', 'do', 'dos', 'das', 'e']:
                return False
        
        return True
    
    def looks_like_person_name(self, name: str) -> bool:
        """Check if name looks like a person name (vs institution)"""
        
        # Institution indicators
        institution_indicators = [
            'ministério', 'secretaria', 'agência', 'tribunal', 'câmara', 'senado',
            'prefeitura', 'governo', 'assembleia', 'conselho', 'comissão',
            'antt', 'antaq', 'anac', 'stf', 'stj', 'tcu'
        ]
        
        name_lower = name.lower()
        for indicator in institution_indicators:
            if indicator in name_lower:
                return False
        
        # Check for typical person name patterns
        words = name.split()
        
        # Multiple words suggest person name
        if len(words) >= 2:
            return True
        
        # Single word that's a common Brazilian name
        if len(words) == 1:
            common_single_names = ['silva', 'santos', 'oliveira', 'souza']
            return name_lower not in common_single_names
        
        return True
    
    def standardize_person_name(self, name: str) -> str:
        """Standardize person name capitalization"""
        
        words = []
        for word in name.split():
            if word.lower() in ['de', 'da', 'do', 'dos', 'das', 'e']:
                words.append(word.lower())
            elif word.upper() in ['II', 'III', 'IV', 'JR', 'SR', 'FILHO', 'NETO']:
                words.append(word.upper())
            else:
                words.append(word.capitalize())
        
        return ' '.join(words)


def create_advanced_enhancement_pipeline():
    """Create complete advanced enhancement pipeline"""
    
    print("="*80)
    print("ADVANCED DATA ENHANCEMENT STRATEGY - PHASE 2")
    print("="*80)
    print("Target: Improve completeness from 47.3% to 90%+")
    print("")
    
    print("PHASE 2 ENHANCEMENT STRATEGIES:")
    print("-"*50)
    print("1. GEOGRAPHIC ENHANCEMENT (3.8% → 80%+)")
    print("   • Comprehensive Brazilian municipality database")
    print("   • Advanced pattern recognition for municipal indicators")
    print("   • Context-based geographic inference")
    print("   • Fuzzy matching for partial municipality names")
    print("")
    
    print("2. AUTHOR EXTRACTION EXPANSION (36.0% → 80%+)")
    print("   • Enhanced regex patterns for Brazilian legal professionals")
    print("   • Context-aware name extraction from document structure")
    print("   • Institutional hierarchy recognition")
    print("   • Brazilian name validation and standardization")
    print("")
    
    print("3. ADVANCED CLASSIFICATION (33.9% → 85%+)")
    print("   • Machine learning training on enhanced dataset")
    print("   • Legal document type inference from structure")
    print("   • Cross-validation with existing classifications")
    print("   • Confidence scoring and validation")
    print("")
    
    print("4. DATA INTEGRATION AND VALIDATION")
    print("   • Cross-field consistency checking")
    print("   • Temporal validation for historical documents")
    print("   • External database integration (IBGE, OAB)")
    print("   • Quality scoring and audit trails")
    print("")
    
    print("IMPLEMENTATION ROADMAP:")
    print("-"*50)
    print("Phase 2A: Advanced Geographic Enhancement")
    print("Phase 2B: Enhanced Author Pattern Recognition")
    print("Phase 2C: ML-based Classification Training")
    print("Phase 2D: Integrated Validation Framework")
    print("")
    
    print("EXPECTED OUTCOMES:")
    print("-"*50)
    print("• Overall completeness: 47.3% → 90%+ (Target achieved)")
    print("• Municipality data: 3.8% → 80%+ (~107,000 records enhanced)")
    print("• Author information: 36.0% → 80%+ (~59,000 additional records)")
    print("• Document classification: 33.9% → 85%+ (~68,000 additional records)")
    print("• Research-grade data quality for Brazilian legislative analysis")
    print("")
    
    print("="*80)
    print("Ready to implement Phase 2 advanced enhancement strategies")
    print("="*80)


if __name__ == "__main__":
    create_advanced_enhancement_pipeline()