#!/usr/bin/env python3
"""
Legal Text Preprocessor for Brazilian Portuguese
===============================================

Specialized text preprocessing for Brazilian legal and legislative documents.
Handles legal text normalization, cleaning, and standardization while preserving
important legal terminology and structure.

Features:
---------
- Legal text normalization (laws, decrees, articles, etc.)
- Portuguese accent and character handling
- Legal entity preservation during cleaning
- Date and number standardization
- Legal citation formatting
- Noise removal while preserving legal structure

Author: MackIntegridade Research Team
Date: 2025-08-08
Version: 2.0.0
"""

import re
import logging
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from datetime import datetime

import pandas as pd
from unidecode import unidecode

logger = logging.getLogger(__name__)

@dataclass
class PreprocessingConfig:
    """Configuration for text preprocessing options."""
    
    # Text cleaning options
    remove_extra_whitespace: bool = True
    remove_special_chars: bool = True
    preserve_legal_chars: bool = True
    normalize_case: bool = True
    
    # Legal-specific options
    standardize_legal_refs: bool = True
    preserve_legal_structure: bool = True
    normalize_dates: bool = True
    normalize_numbers: bool = True
    
    # Language options
    remove_accents: bool = False
    preserve_portuguese_chars: bool = True
    
    # Content filtering
    min_word_length: int = 2
    remove_stopwords: bool = False
    remove_legal_stopwords: bool = False


class LegalTextPreprocessor:
    """
    Advanced text preprocessor specialized for Brazilian legal documents.
    """
    
    def __init__(self, config: Optional[PreprocessingConfig] = None):
        """
        Initialize the legal text preprocessor.
        
        Args:
            config: Preprocessing configuration options
        """
        self.config = config or PreprocessingConfig()
        
        # Load legal patterns and vocabularies
        self._load_legal_patterns()
        self._load_stopwords()
        
        logger.info("LegalTextPreprocessor initialized")
    
    def _load_legal_patterns(self) -> None:
        """Load legal patterns for text processing."""
        
        # Legal document patterns
        self.legal_document_patterns = {
            'lei': r'\b(lei|l\.)\s*n[ºª°]?\s*(\d+(?:[.,/]\d+)*)\s*(?:de\s+(\d{1,2}\s+de\s+\w+\s+de\s+\d{4}|\d{1,2}/\d{1,2}/\d{4}))?\b',
            'decreto': r'\b(decreto|dec\.)\s*n[ºª°]?\s*(\d+(?:[.,/]\d+)*)\s*(?:de\s+(\d{1,2}\s+de\s+\w+\s+de\s+\d{4}|\d{1,2}/\d{1,2}/\d{4}))?\b',
            'portaria': r'\b(portaria|port\.)\s*n[ºª°]?\s*(\d+(?:[.,/]\d+)*)\s*(?:de\s+(\d{1,2}\s+de\s+\w+\s+de\s+\d{4}|\d{1,2}/\d{1,2}/\d{4}))?\b',
            'resolucao': r'\b(resolução|resol\.)\s*n[ºª°]?\s*(\d+(?:[.,/]\d+)*)\s*(?:de\s+(\d{1,2}\s+de\s+\w+\s+de\s+\d{4}|\d{1,2}/\d{1,2}/\d{4}))?\b',
            'instrucao_normativa': r'\b(instrução\s+normativa|in)\s*n[ºª°]?\s*(\d+(?:[.,/]\d+)*)\s*(?:de\s+(\d{1,2}\s+de\s+\w+\s+de\s+\d{4}|\d{1,2}/\d{1,2}/\d{4}))?\b',
            'medida_provisoria': r'\b(medida\s+provisória|mp)\s*n[ºª°]?\s*(\d+(?:[.,/]\d+)*)\s*(?:de\s+(\d{1,2}\s+de\s+\w+\s+de\s+\d{4}|\d{1,2}/\d{1,2}/\d{4}))?\b'
        }
        
        # Article and section patterns
        self.structural_patterns = {
            'artigo': r'\b(art(?:igo)?\.?)\s*(\d+(?:[º°ª])?(?:\s*[-,]\s*\d+(?:[º°ª])?)*)\b',
            'inciso': r'\b(inc(?:iso)?\.?)\s*([IVXLCDMivxlcdm]+|\d+)\b',
            'paragrafo': r'\b(§|par(?:ágrafo)?\.?)\s*(\d+[º°ª]?)\b',
            'alinea': r'\b(alínea|al\.)\s*([a-z])\b',
            'item': r'\b(item)\s*(\d+)\b'
        }
        
        # Date patterns
        self.date_patterns = {
            'full_date': r'\b(\d{1,2})\s+de\s+(\w+)\s+de\s+(\d{4})\b',
            'numeric_date': r'\b(\d{1,2})/(\d{1,2})/(\d{4})\b',
            'iso_date': r'\b(\d{4})-(\d{2})-(\d{2})\b',
            'partial_date': r'\b(\w+)\s+de\s+(\d{4})\b'
        }
        
        # Month names in Portuguese
        self.month_names = {
            'janeiro': '01', 'fevereiro': '02', 'março': '03', 'abril': '04',
            'maio': '05', 'junho': '06', 'julho': '07', 'agosto': '08',
            'setembro': '09', 'outubro': '10', 'novembro': '11', 'dezembro': '12'
        }
        
        # Number patterns
        self.number_patterns = {
            'currency': r'R\$\s*[\d.,]+',
            'percentage': r'\d+(?:[.,]\d+)?%',
            'ordinal': r'\d+[ºª°]',
            'decimal': r'\d+[.,]\d+',
            'large_number': r'\d{1,3}(?:[.,]\d{3})*'
        }
    
    def _load_stopwords(self) -> None:
        """Load stopwords for legal text processing."""
        
        # Standard Portuguese stopwords
        self.standard_stopwords = {
            'a', 'ao', 'aos', 'aquela', 'aquelas', 'aquele', 'aqueles', 'aquilo',
            'as', 'até', 'com', 'como', 'da', 'das', 'de', 'dela', 'delas',
            'dele', 'deles', 'depois', 'do', 'dos', 'e', 'ela', 'elas', 'ele',
            'eles', 'em', 'entre', 'essa', 'essas', 'esse', 'esses', 'esta',
            'estas', 'este', 'estes', 'eu', 'foi', 'for', 'isso', 'isto',
            'já', 'la', 'lhe', 'lhes', 'lo', 'mas', 'me', 'mesmo', 'meu',
            'meus', 'minha', 'minhas', 'muito', 'na', 'nas', 'nem', 'no',
            'nos', 'nós', 'nossa', 'nossas', 'nosso', 'nossos', 'o', 'os',
            'ou', 'para', 'pela', 'pelas', 'pelo', 'pelos', 'por', 'qual',
            'quando', 'que', 'quem', 'se', 'sem', 'seu', 'seus', 'só', 'sua',
            'suas', 'também', 'te', 'tem', 'tu', 'tua', 'tuas', 'teu', 'teus',
            'um', 'uma', 'umas', 'uns', 'você', 'vocês', 'vos'
        }
        
        # Legal-specific stopwords
        self.legal_stopwords = {
            'art', 'artigo', 'inc', 'inciso', 'par', 'parágrafo', 'alínea',
            'caput', 'considerando', 'resolve', 'fica', 'revogado', 'alterado',
            'incluído', 'vetado', 'estabelece', 'dispõe', 'sobre', 'dá',
            'outras', 'providências', 'institui', 'cria', 'disciplina',
            'regulamenta', 'aprova', 'autoriza', 'define', 'determina'
        }
        
        # Combined stopwords
        self.all_stopwords = self.standard_stopwords.union(self.legal_stopwords)
    
    def preprocess(
        self, 
        text: str, 
        custom_config: Optional[PreprocessingConfig] = None
    ) -> str:
        """
        Preprocess legal text with comprehensive cleaning and normalization.
        
        Args:
            text: Input text to preprocess
            custom_config: Optional custom configuration for this operation
            
        Returns:
            Preprocessed text
        """
        if not text or not isinstance(text, str):
            return ""
        
        config = custom_config or self.config
        processed_text = text
        
        # Step 1: Initial cleaning
        processed_text = self._initial_cleaning(processed_text, config)
        
        # Step 2: Legal entity preservation and standardization
        if config.standardize_legal_refs:
            processed_text = self._standardize_legal_references(processed_text)
        
        # Step 3: Date and number normalization
        if config.normalize_dates:
            processed_text = self._normalize_dates(processed_text)
        
        if config.normalize_numbers:
            processed_text = self._normalize_numbers(processed_text)
        
        # Step 4: Text normalization
        processed_text = self._normalize_text(processed_text, config)
        
        # Step 5: Final cleaning
        processed_text = self._final_cleaning(processed_text, config)
        
        return processed_text.strip()
    
    def preprocess_batch(
        self, 
        texts: List[str], 
        custom_config: Optional[PreprocessingConfig] = None
    ) -> List[str]:
        """
        Preprocess a batch of texts efficiently.
        
        Args:
            texts: List of texts to preprocess
            custom_config: Optional custom configuration
            
        Returns:
            List of preprocessed texts
        """
        return [self.preprocess(text, custom_config) for text in texts]
    
    def _initial_cleaning(self, text: str, config: PreprocessingConfig) -> str:
        """Perform initial text cleaning."""
        
        # Remove HTML/XML tags
        text = re.sub(r'<[^>]+>', ' ', text)
        
        # Remove URLs
        text = re.sub(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', ' ', text)
        
        # Remove email addresses
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', ' ', text)
        
        # Remove excessive punctuation
        if config.remove_special_chars and not config.preserve_legal_chars:
            text = re.sub(r'[^\w\s]', ' ', text)
        elif config.preserve_legal_chars:
            # Keep legal punctuation: §, º, ª, °, /, -, ., ,, ;, :, (, ), [, ]
            text = re.sub(r'[^\w\s§ºª°/\-.,;:()\[\]]', ' ', text)
        
        # Remove extra whitespace
        if config.remove_extra_whitespace:
            text = re.sub(r'\s+', ' ', text)
        
        return text
    
    def _standardize_legal_references(self, text: str) -> str:
        """Standardize legal document references."""
        
        # Standardize legal documents
        for doc_type, pattern in self.legal_document_patterns.items():
            def replace_match(match):
                doc_name = match.group(1).lower()
                doc_number = match.group(2)
                doc_date = match.group(3) if len(match.groups()) > 2 and match.group(3) else ""
                
                # Standardize document name
                if 'lei' in doc_name or 'l.' in doc_name:
                    standard_name = 'Lei'
                elif 'decreto' in doc_name or 'dec.' in doc_name:
                    standard_name = 'Decreto'
                elif 'portaria' in doc_name or 'port.' in doc_name:
                    standard_name = 'Portaria'
                elif 'resolução' in doc_name or 'resol.' in doc_name:
                    standard_name = 'Resolução'
                elif 'instrução' in doc_name or 'in' in doc_name:
                    standard_name = 'Instrução Normativa'
                elif 'medida' in doc_name or 'mp' in doc_name:
                    standard_name = 'Medida Provisória'
                else:
                    standard_name = doc_name.title()
                
                # Build standardized reference
                if doc_date:
                    return f"{standard_name} nº {doc_number}, de {doc_date}"
                else:
                    return f"{standard_name} nº {doc_number}"
            
            text = re.sub(pattern, replace_match, text, flags=re.IGNORECASE)
        
        # Standardize structural elements
        for element, pattern in self.structural_patterns.items():
            def replace_structural(match):
                element_name = match.group(1).lower()
                element_number = match.group(2)
                
                if 'art' in element_name:
                    return f"art. {element_number}"
                elif 'inc' in element_name:
                    return f"inciso {element_number}"
                elif '§' in element_name or 'par' in element_name:
                    return f"§ {element_number}"
                elif 'al' in element_name:
                    return f"alínea {element_number}"
                else:
                    return match.group(0)
            
            text = re.sub(pattern, replace_structural, text, flags=re.IGNORECASE)
        
        return text
    
    def _normalize_dates(self, text: str) -> str:
        """Normalize date formats."""
        
        # Convert full dates (e.g., "14 de junho de 2023" -> "14/06/2023")
        def replace_full_date(match):
            day, month_name, year = match.groups()
            month_num = self.month_names.get(month_name.lower(), '01')
            return f"{day.zfill(2)}/{month_num}/{year}"
        
        text = re.sub(self.date_patterns['full_date'], replace_full_date, text, flags=re.IGNORECASE)
        
        # Standardize ISO dates to DD/MM/YYYY
        def replace_iso_date(match):
            year, month, day = match.groups()
            return f"{day}/{month}/{year}"
        
        text = re.sub(self.date_patterns['iso_date'], replace_iso_date, text)
        
        return text
    
    def _normalize_numbers(self, text: str) -> str:
        """Normalize number formats."""
        
        # Standardize decimal separators (use comma for Portuguese)
        text = re.sub(r'(\d+)\.(\d{2})(?!\d)', r'\1,\2', text)  # Decimals
        
        # Standardize thousand separators (use dot for Portuguese)
        text = re.sub(r'(\d{1,3})(?:,(\d{3}))+(?!\d)', 
                     lambda m: m.group(0).replace(',', '.'), text)
        
        # Normalize currency
        text = re.sub(r'R\$\s*', 'R$ ', text)
        
        return text
    
    def _normalize_text(self, text: str, config: PreprocessingConfig) -> str:
        """Perform text normalization."""
        
        # Case normalization
        if config.normalize_case:
            # Convert to lowercase but preserve legal document names
            words = text.split()
            normalized_words = []
            
            for word in words:
                # Keep legal document references in title case
                if any(pattern in word.lower() for pattern in ['lei', 'decreto', 'portaria', 'resolução']):
                    normalized_words.append(word.title())
                else:
                    normalized_words.append(word.lower())
            
            text = ' '.join(normalized_words)
        
        # Remove accents if requested
        if config.remove_accents and not config.preserve_portuguese_chars:
            text = unidecode(text)
        
        return text
    
    def _final_cleaning(self, text: str, config: PreprocessingConfig) -> str:
        """Perform final text cleaning."""
        
        # Remove short words
        if config.min_word_length > 1:
            words = text.split()
            words = [word for word in words 
                    if len(word) >= config.min_word_length or 
                    word in ['§', 'º', 'ª', '°']]  # Keep legal symbols
            text = ' '.join(words)
        
        # Remove stopwords
        if config.remove_stopwords or config.remove_legal_stopwords:
            words = text.split()
            
            if config.remove_stopwords and config.remove_legal_stopwords:
                words = [word for word in words if word.lower() not in self.all_stopwords]
            elif config.remove_stopwords:
                words = [word for word in words if word.lower() not in self.standard_stopwords]
            elif config.remove_legal_stopwords:
                words = [word for word in words if word.lower() not in self.legal_stopwords]
            
            text = ' '.join(words)
        
        # Final whitespace cleanup
        text = re.sub(r'\s+', ' ', text)
        
        return text
    
    def extract_legal_elements(self, text: str) -> Dict[str, List[str]]:
        """
        Extract and structure legal elements from text.
        
        Args:
            text: Input legal text
            
        Returns:
            Dictionary with extracted legal elements
        """
        elements = {
            'legal_documents': [],
            'articles': [],
            'paragraphs': [],
            'incisos': [],
            'alineas': [],
            'dates': [],
            'numbers': []
        }
        
        # Extract legal documents
        for doc_type, pattern in self.legal_document_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    elements['legal_documents'].append(' '.join(filter(None, match)))
                else:
                    elements['legal_documents'].append(match)
        
        # Extract structural elements
        for element, pattern in self.structural_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    element_text = ' '.join(filter(None, match))
                else:
                    element_text = match
                
                if 'artigo' in element or 'art' in element:
                    elements['articles'].append(element_text)
                elif 'inciso' in element:
                    elements['incisos'].append(element_text)
                elif 'paragrafo' in element or '§' in element:
                    elements['paragraphs'].append(element_text)
                elif 'alinea' in element:
                    elements['alineas'].append(element_text)
        
        # Extract dates
        for date_type, pattern in self.date_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    elements['dates'].append(' '.join(filter(None, match)))
                else:
                    elements['dates'].append(match)
        
        # Extract numbers
        for number_type, pattern in self.number_patterns.items():
            matches = re.findall(pattern, text)
            elements['numbers'].extend(matches)
        
        return elements
    
    def get_preprocessing_stats(self, original_text: str, processed_text: str) -> Dict[str, Any]:
        """
        Get statistics about the preprocessing operation.
        
        Args:
            original_text: Original text before preprocessing
            processed_text: Text after preprocessing
            
        Returns:
            Dictionary with preprocessing statistics
        """
        original_words = original_text.split()
        processed_words = processed_text.split()
        
        return {
            'original_length': len(original_text),
            'processed_length': len(processed_text),
            'length_reduction': len(original_text) - len(processed_text),
            'length_reduction_percent': (len(original_text) - len(processed_text)) / len(original_text) * 100 if original_text else 0,
            'original_word_count': len(original_words),
            'processed_word_count': len(processed_words),
            'word_reduction': len(original_words) - len(processed_words),
            'word_reduction_percent': (len(original_words) - len(processed_words)) / len(original_words) * 100 if original_words else 0,
            'legal_elements_preserved': len(self.extract_legal_elements(processed_text)['legal_documents']),
            'processing_timestamp': datetime.now().isoformat()
        }